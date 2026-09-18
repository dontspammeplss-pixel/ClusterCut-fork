//! Inbound QUIC message and stream handlers.

use crate::protocol::Message;
use crate::state::AppState;
use crate::transport::Transport;
use crate::{net_util, storage};
use crate::{NotificationPayload, send_notification, check_and_notify_leave};
use tauri::{Emitter, Manager};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, AsyncBufReadExt, BufReader};
use std::path::PathBuf;
use tokio::fs::File;

fn safe_store_path(cache_dir: &std::path::Path, id: &str, ext: &str) -> Result<std::path::PathBuf, String> {
    // Reject — don't mint a fresh UUID (that hides the attack in logs).
    let parsed = uuid::Uuid::parse_str(id).map_err(|e| format!("bad id: {e}"))?;
    let ext: String = ext.chars().filter(|c| c.is_ascii_alphanumeric()).take(10).collect();
    if ext.is_empty() {
        return Err("bad ext".to_string());
    }
    let p = cache_dir.join(format!("{parsed}.{ext}"));
    // No canonicalize() here: target does not exist yet so the check is vacuous.
    // TOCTOU safety comes from create_new + symlink_metadata below.
    if p.symlink_metadata().is_ok() {
        return Err("exists or symlink".to_string());
    }
    Ok(p)
}

/// SHA-256 of a file's plaintext bytes, streamed in 1MB chunks. Rewinds to
/// offset 0 afterwards so the caller can immediately stream the file to the
/// peer. Two-pass disk read (hash, then send) — header must precede payload
/// on the wire, so single-pass is impossible without buffering whole files.
async fn plaintext_sha256(file: &mut File) -> Result<[u8; 32], String> {
    use std::io::SeekFrom;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        match file.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[0..n]),
            Err(e) => return Err(format!("hash read error: {}", e)),
        }
    }
    file.seek(SeekFrom::Start(0))
        .await
        .map_err(|e| format!("hash rewind error: {}", e))?;
    Ok(hasher.finalize().into())
}

/// Pure verdict for a received stream's SHA-256 digest against the header's.
/// `Verified` = digest present and equal; `Legacy` = pre-A2 sender, no digest
/// (size-only check applies); `Mismatch` = corrupt/tampered, drop it.
#[derive(Debug, PartialEq, Eq)]
enum Integrity {
    Verified,
    Legacy,
    Mismatch,
}

fn check_digest(expected: Option<[u8; 32]>, actual: [u8; 32]) -> Integrity {
    match expected {
        Some(e) if e == actual => Integrity::Verified,
        Some(_) => Integrity::Mismatch,
        None => Integrity::Legacy,
    }
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// H-4 bounds for inbound file streams. A malicious sender controls the
/// header line, `file_size`, and every stream byte, so all three are capped:
/// the header line (8KB — real headers are <1KB), the total bytes written
/// (2GiB), the zstd decompressed output (2GiB — zip-bomb guard), and each
/// individual read (30s — stalled-sender guard).
pub(crate) const MAX_FILE_STREAM_HEADER: usize = 8 * 1024;
pub(crate) const MAX_FILE_STREAM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const MAX_DECOMP_BUDGET: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const STREAM_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Pure verdicts for the H-4 bounds (unit-testable without QUIC/AppHandle).
pub(crate) fn file_stream_header_allowed(len: usize) -> bool {
    len <= MAX_FILE_STREAM_HEADER
}
pub(crate) fn file_stream_size_allowed(file_size: u64) -> bool {
    file_size <= MAX_FILE_STREAM_BYTES
}
/// True once `total` passes the enforceable limit: the declared size clamped
/// to the hard cap, so a lying `u64::MAX` header still aborts at 2GiB.
pub(crate) fn stream_over_budget(total: u64, declared: u64) -> bool {
    total > declared.min(MAX_FILE_STREAM_BYTES)
}

/// Stage received clipboard-blob bytes under `temp_downloads/<id>.<ext>` and
/// register them in `local_clipboard_blobs`, so this receiver can re-copy /
/// re-send the item from History. Mirrors the sender's
/// `stage_clipboard_blob_temp_file` but works from in-memory bytes we already
/// drained. Returns the staged path on success.
fn stage_received_clipboard_blob(
    app: &tauri::AppHandle,
    state: &AppState,
    id: &str,
    mime_type: &str,
    width: Option<u32>,
    height: Option<u32>,
    bytes: &[u8],
) -> Option<std::path::PathBuf> {
    let cache_dir = app
        .path()
        .app_cache_dir()
        .ok()?
        .join("temp_downloads");
    std::fs::create_dir_all(&cache_dir).ok()?;
    storage::set_dir_owner_only(&cache_dir);
    let ext = crate::clipboard::common::extension_for_clipboard_mime(mime_type);
    let path = match safe_store_path(&cache_dir, id, ext) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Rejected blob id {:?}: {}", id, e);
            return None;
        }
    };
    // create_new: fail closed if attacker pre-created file/symlink between check and write.
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(mut f) => {
            use std::io::Write;
            if f.write_all(bytes).is_err() {
                drop(f);
                let _ = std::fs::remove_file(&path);
                return None;
            }
            storage::set_owner_only(&path);
        }
        Err(e) => {
            tracing::warn!("Blob stage create_new failed {:?}: {}", path, e);
            return None;
        }
    }
    state.local_clipboard_blobs.lock().unwrap().insert(
        id.to_string(),
        crate::state::ClipboardBlobMetadata {
            path: path.clone(),
            mime_type: mime_type.to_string(),
            width,
            height,
            total_size: bytes.len() as u64,
        },
    );
    Some(path)
}

/// RAII refcount guard: marks a clipboard-blob id as actively being served to
/// a peer for the lifetime of the serve task, so History-store eviction won't
/// delete the staged file mid-transfer. Decrements (and removes at zero) on drop.
struct ServeGuard {
    map: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u32>>>,
    id: String,
}
impl ServeGuard {
    fn new(
        map: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u32>>>,
        id: String,
    ) -> Self {
        *map.lock().unwrap().entry(id.clone()).or_insert(0) += 1;
        ServeGuard { map, id }
    }
}
impl Drop for ServeGuard {
    fn drop(&mut self) {
        let mut m = self.map.lock().unwrap();
        if let Some(c) = m.get_mut(&self.id) {
            *c -= 1;
            if *c == 0 {
                m.remove(&self.id);
            }
        }
    }
}

/// Read a §3.3 clipboard-blob stream into memory and land it on the OS
/// clipboard. The header has already been parsed and confirmed to carry
/// `DeliveryTarget::Clipboard{…}`. Auth-token verification mirrors the file
/// path. Race protection: if `state.in_flight_clipboard_fetch` no longer
/// holds this id by the time bytes finish arriving, a newer clipboard event
/// has superseded this one — we still drain the stream to keep QUIC happy
/// but skip writing to the OS clipboard.
async fn handle_incoming_clipboard_blob_stream(
    reader: BufReader<quinn::RecvStream>,
    header: crate::protocol::FileStreamHeader,
    mime_type: String,
    width: Option<u32>,
    height: Option<u32>,
    addr: std::net::SocketAddr,
    state: AppState,
    app: tauri::AppHandle,
) {
    tracing::info!(
        "Receiving Clipboard Blob: mime={}, {} bytes, id={}, from={}",
        mime_type, header.file_size, header.id, addr
    );

    // No app-layer auth token to verify — the QUIC connection itself is
    // mTLS-pinned to the sending peer (see issue #9 follow-up).
    //
    // Drain the stream into memory. Cap is MIME-dependent:
    // text/* → MAX_CLIPBOARD_TEXT_BYTES, everything else → MAX_CLIPBOARD_IMAGE_BYTES.
    // Enforced defensively so a malformed sender can't OOM the receiver.
    let cap = if mime_type.starts_with("text/") {
        crate::clipboard::common::MAX_CLIPBOARD_TEXT_BYTES
    } else {
        crate::clipboard::common::MAX_CLIPBOARD_IMAGE_BYTES
    };
    let mut accum: Vec<u8> = Vec::with_capacity(header.file_size.min(cap as u64) as usize);
    let mut buf = vec![0u8; 1024 * 1024];
    let mut last_emit = std::time::Instant::now();
    let start_time = std::time::Instant::now();

    // Macro so the cap/progress/error logic is shared between the compressed
    // and raw paths without duplication.
    macro_rules! drain {
        ($src:expr) => {{
            let mut src = $src;
            loop {
                match tokio::time::timeout(STREAM_READ_TIMEOUT, src.read(&mut buf)).await {
                    Err(_) => {
                        tracing::error!("Clipboard-blob stream read timed out; dropping.");
                        return;
                    }
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        if accum.len() + n > cap {
                            tracing::error!(
                                "Clipboard-blob stream exceeds {} byte cap (got {}); dropping.",
                                cap,
                                accum.len() + n
                            );
                            // Drain remainder of stream to keep QUIC happy, but stop accumulating.
                            // Bounded + timed: a malicious sender must not be able to
                            // stream forever here either — drain at most the hard cap,
                            // then give up on the rest.
                            let mut sink = vec![0u8; 1024 * 1024];
                            let mut drained: u64 = 0;
                            loop {
                                match tokio::time::timeout(STREAM_READ_TIMEOUT, src.read(&mut sink)).await {
                                    Err(_) | Ok(Err(_)) | Ok(Ok(0)) => break,
                                    Ok(Ok(n2)) => {
                                        drained += n2 as u64;
                                        if drained > MAX_FILE_STREAM_BYTES {
                                            break;
                                        }
                                    }
                                }
                            }
                            return;
                        }
                        accum.extend_from_slice(&buf[..n]);
                        if last_emit.elapsed().as_millis() > 200 {
                            let _ = app.emit("file-progress", serde_json::json!({
                                "id": header.id,
                                "fileName": if mime_type.starts_with("text/") {
                                    format!("Clipboard text ({})", mime_type)
                                } else {
                                    format!("Clipboard image ({})", mime_type)
                                },
                                "total": header.file_size,
                                "transferred": accum.len() as u64,
                            }));
                            last_emit = std::time::Instant::now();
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::error!("Clipboard-blob stream read error: {}", e);
                        return;
                    }
                }
            }
        }};
    }

    if header.compressed {
        tracing::info!("[Receiver] Clipboard-blob ZSTD stream; expecting {} bytes (decompressed).", header.file_size);
        drain!(async_compression::tokio::bufread::ZstdDecoder::new(reader));
    } else {
        drain!(reader);
    }
    let total_time = start_time.elapsed();
    tracing::info!(
        "Clipboard-blob stream complete: {} bytes in {:?} (mime={})",
        accum.len(),
        total_time,
        mime_type
    );

    if accum.len() as u64 != header.file_size {
        tracing::warn!(
            "Clipboard-blob size mismatch: header says {} bytes, got {} bytes — dropping.",
            header.file_size,
            accum.len()
        );
        return;
    }

    // A2 integrity: digest covers the blob path via the same header. Mismatch
    // → drop bytes, emit file-corrupt, never stage or touch the clipboard.
    let blob_actual: [u8; 32] = Sha256::digest(&accum).into();
    match check_digest(header.sha256, blob_actual) {
        Integrity::Verified | Integrity::Legacy => {}
        Integrity::Mismatch => {
            tracing::warn!("Clipboard-blob digest mismatch id={}", header.id);
            let _ = app.emit("file-corrupt", serde_json::json!({
                "id": header.id,
                "file_index": header.file_index,
                "integrity": "mismatch",
                "expected": hex32(&header.sha256.unwrap()),
                "actual": hex32(&blob_actual),
            }));
            return;
        }
    }

    // Race protection: only land on clipboard if this id is still the in-flight one.
    let still_current = {
        let mut slot = state.in_flight_clipboard_fetch.lock().unwrap();
        match slot.as_ref() {
            Some(s) if *s == header.id => {
                *slot = None;
                true
            }
            _ => false,
        }
    };
    if !still_current {
        tracing::info!(
            "[ClipboardBlob] Discarding fetched bytes for id={} — superseded by a newer clipboard event",
            header.id
        );
        return;
    }

    let (auto_recv, notifications) = {
        let s = state.settings.lock().unwrap();
        (s.auto_receive, s.notifications.clone())
    };
    let byte_len = accum.len();
    let mb = byte_len as f64 / (1024.0 * 1024.0);

    if mime_type.starts_with("text/") {
        // Decode strictly; mTLS + the size-match check above make corruption
        // near-impossible, so on a decode failure we drop rather than paste
        // mojibake.
        let text = match String::from_utf8(accum) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("Large clipboard text did not decode as UTF-8: {}; dropping.", e);
                return;
            }
        };
        // Stage for re-call, then emit a light preview (record_and_emit reads
        // the staged file via local_clipboard_blobs to build the Disk entry).
        let staged = stage_received_clipboard_blob(
            &app, &state, &header.id, &mime_type, None, None, text.as_bytes(),
        );
        let payload_event = if staged.is_some() {
            // Descriptor → record_and_emit reads the staged file for the snippet.
            crate::protocol::ClipboardPayload {
                id: header.id.clone(),
                text: String::new(),
                files: None,
                blob: Some(crate::protocol::ClipboardBlob::descriptor(
                    mime_type.clone(),
                    header.id.clone(),
                    text.len() as u64,
                    None,
                    None,
                )),
                formats: None,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                sender: format!("{}", addr),
                sender_id: String::new(),
            }
        } else {
            // Staging failed — inline the full text so the item stays
            // re-callable (record_and_emit records it as StoredContent::Text).
            crate::protocol::ClipboardPayload {
                id: header.id.clone(),
                text: text.clone(),
                files: None,
                blob: None,
                formats: None,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                sender: format!("{}", addr),
                sender_id: String::new(),
            }
        };
        if auto_recv {
            crate::clipboard::set_clipboard(&app, text);
        } else {
            let mut pending = state.pending_clipboard.lock().unwrap();
            *pending = Some(payload_event.clone());
        }
        crate::clipboard::common::record_and_emit(&app, &state, "clipboard-change", &payload_event);
        if notifications.data_received {
            send_notification(
                &app,
                "Text Available to Paste",
                &format!("{:.1} MB of text is now on the clipboard.", mb),
                false, Some(3), "history", NotificationPayload::None,
            );
        }
    } else {
        let staged = stage_received_clipboard_blob(
            &app, &state, &header.id, &mime_type, width, height, &accum,
        );
        // Land the image on the OS clipboard (or stash as pending).
        let blob = crate::protocol::ClipboardBlob::from_bytes(mime_type.clone(), &accum, width, height);
        let payload_event = if staged.is_some() {
            // Descriptor payload → record_and_emit builds a Disk entry +
            // thumbnail from the staged file.
            crate::protocol::ClipboardPayload {
                id: header.id.clone(),
                text: String::new(),
                files: None,
                blob: Some(crate::protocol::ClipboardBlob::descriptor(
                    mime_type.clone(),
                    header.id.clone(),
                    accum.len() as u64,
                    width,
                    height,
                )),
                formats: None,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                sender: format!("{}", addr),
                sender_id: String::new(),
            }
        } else {
            // Staging failed — fall back to inline so History still shows it.
            crate::protocol::ClipboardPayload {
                id: header.id.clone(),
                text: String::new(),
                files: None,
                blob: Some(blob.clone()),
                formats: None,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                sender: format!("{}", addr),
                sender_id: String::new(),
            }
        };
        if auto_recv {
            crate::clipboard::set_clipboard_image(&app, blob);
        } else {
            let mut pending = state.pending_clipboard.lock().unwrap();
            *pending = Some(payload_event.clone());
        }
        crate::clipboard::common::record_and_emit(&app, &state, "clipboard-change", &payload_event);
        if notifications.data_received {
            send_notification(
                &app,
                "Image Available to Paste",
                &format!("{:.1} MB image is now on the clipboard.", mb),
                false, Some(3), "history", NotificationPayload::None,
            );
        }
    }
}

pub(crate) async fn handle_incoming_file_stream(recv: quinn::RecvStream, addr: std::net::SocketAddr, state: AppState, app: tauri::AppHandle) {
    tracing::info!("Starting File Stream Handler for {}", addr);

    let mut reader = BufReader::new(recv);
    let mut header_line = String::new();

    // 1. Read Header (JSON + Newline), bounded: take() caps memory at
    // MAX_FILE_STREAM_HEADER + 1 so a header without newline can't OOM us;
    // anything over the cap is rejected before File::create.
    let header_read = tokio::time::timeout(
        STREAM_READ_TIMEOUT,
        (&mut reader)
            .take((MAX_FILE_STREAM_HEADER + 1) as u64)
            .read_line(&mut header_line),
    )
    .await;
    match header_read {
        Err(_) => {
            tracing::error!("File stream header read timed out from {}", addr);
            return;
        }
        Ok(Err(e)) => {
            tracing::error!("Failed to read file stream header from {}: {}", addr, e);
            return;
        }
        Ok(Ok(_)) => {}
    }
    if !file_stream_header_allowed(header_line.len()) {
        tracing::warn!(
            "Rejecting file stream from {}: header exceeds {} bytes",
            addr,
            MAX_FILE_STREAM_HEADER
        );
        return;
    }

    let header: crate::protocol::FileStreamHeader = match serde_json::from_str(&header_line) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Failed to parse file stream header '{}': {}", header_line.trim(), e);
            return;
        }
    };

    // §3.3 routing: clipboard-blob streams accumulate bytes in memory and
    // land on the OS clipboard. File streams keep the existing temp-download
    // path. The two share auth-token verification and the QUIC drain dance,
    // but everything past the header is structurally different.
    if let crate::protocol::DeliveryTarget::Clipboard { mime_type, width, height } = header.delivery_target.clone() {
        handle_incoming_clipboard_blob_stream(reader, header, mime_type, width, height, addr, state, app).await;
        return;
    }

    // H-4: reject lying/huge sizes before File::create — no partial to clean up.
    if !file_stream_size_allowed(header.file_size) {
        tracing::warn!(
            "Rejecting file stream {} from {}: declared size {} exceeds {} byte cap",
            header.id,
            addr,
            header.file_size,
            MAX_FILE_STREAM_BYTES
        );
        return;
    }

    tracing::info!("Receiving File: {} ({} bytes) [ID: {}]", header.file_name, header.file_size, header.id);

    // 2. Prepare Output File
    // Use Cache Directory -> temp_downloads
    let root_cache_dir = match app.path().app_cache_dir() {
        Ok(p) => p,
        Err(e) => {
             tracing::error!("Failed to get cache dir: {}", e);
             return;
        }
    };

    let cache_dir = root_cache_dir.join("temp_downloads");

    if let Err(e) = std::fs::create_dir_all(&cache_dir) {
        tracing::error!("Failed to create cache dir: {}", e);
        return;
    }
    storage::set_dir_owner_only(&cache_dir);

    // Display name (header.file_name) is metadata only — never joined to a path.
    let ext = std::path::Path::new(&header.file_name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("bin");
    let file_path = match safe_store_path(&cache_dir, &header.id, ext) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Rejected file stream id {:?}: {}", header.id, e);
            return;
        }
    };
    // Preserve original name for UI only.
    let display_name = header.file_name.clone();

    let mut file = match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&file_path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("Failed to create file {:?}: {}", file_path, e);
            return;
        }
    };
    storage::set_owner_only(&file_path);

    // 3. No app-layer auth token to verify — sender identity is already
    //    authenticated by the QUIC mTLS handshake (see issue #9 follow-up).
    tracing::info!("Starting Download...");

    // 4. Stream Data (Zero-Copy-ish)
    let start_time = std::time::Instant::now();

    // reader is BufReader<RecvStream>. We loop manually so we can emit progress.
    // total_written counts bytes written to disk (post-decompression on the compressed
    // path), so the progress percentage matches header.file_size — the *uncompressed*
    // size — regardless of whether the wire payload was compressed.

    let mut buf = vec![0u8; 1024 * 1024]; // 1MB Buffer
    let mut total_written = 0u64;
    let mut last_emit = std::time::Instant::now();
    let mut chunk_count = 0;
    // SHA-256 over plaintext (post-decompression) bytes. Both arms below feed
    // the same hasher, so the digest matches the sender's regardless of compression.
    let mut hasher = Sha256::new();
    // Disk write failure (ENOSPC, I/O error) leaves a partial file behind.
    // Flag it so we delete the partial and return silently below — distinct
    // from a digest mismatch, which emits file-corrupt. Either way the next
    // same-id retry must not hit "exists or symlink" from our leftover.
    let mut write_failed = false;

    if header.compressed {
        tracing::info!("[Receiver] Starting ZSTD Stream. Expecting {} bytes (decompressed).", header.file_size);
        let mut decoder = async_compression::tokio::bufread::ZstdDecoder::new(reader);
        loop {
            match tokio::time::timeout(STREAM_READ_TIMEOUT, decoder.read(&mut buf)).await {
                Err(_) => {
                    tracing::error!("Decompressed stream read timed out; dropping partial.");
                    write_failed = true;
                    break;
                }
                Ok(Err(e)) => {
                    tracing::error!("Decompressed Stream Read Error: {}", e);
                    break;
                }
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => {
                    if let Err(e) = file.write_all(&buf[0..n]).await {
                        tracing::error!("File Write Error: {}", e);
                        write_failed = true;
                        break;
                    }
                    hasher.update(&buf[0..n]);
                    total_written += n as u64;
                    // Zip-bomb guard: decompressed bytes count against
                    // MAX_DECOMP_BUDGET, clamped to the declared size.
                    if total_written > header.file_size.min(MAX_DECOMP_BUDGET) {
                        tracing::warn!(
                            "File stream {} exceeded decomp budget; aborting, partial removed.",
                            header.id
                        );
                        drop(file);
                        let _ = tokio::fs::remove_file(&file_path).await;
                        return;
                    }
                    chunk_count += 1;

                    if last_emit.elapsed().as_millis() > 200 {
                        let _ = app.emit("file-progress", serde_json::json!({
                            "id": header.id,
                            "fileName": display_name,
                            "total": header.file_size,
                            "transferred": total_written
                        }));
                        last_emit = std::time::Instant::now();
                    }
                }
            }
        }
    } else {
        tracing::info!("[Receiver] Starting RAW Stream. Expecting {} bytes.", header.file_size);
        loop {
            match tokio::time::timeout(STREAM_READ_TIMEOUT, reader.read(&mut buf)).await {
                Err(_) => {
                    tracing::error!("File stream read timed out; dropping partial.");
                    write_failed = true;
                    break;
                }
                Ok(Err(e)) => {
                    tracing::error!("Stream Read Error: {}", e);
                    break;
                }
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => {
                    if let Err(e) = file.write_all(&buf[0..n]).await {
                          tracing::error!("File Write Error: {}", e);
                          write_failed = true;
                          break;
                    }
                    hasher.update(&buf[0..n]);
                    total_written += n as u64;
                    // Over-cap guard: a lying header (or endless sender) can't
                    // fill the disk — abort and remove the partial.
                    if stream_over_budget(total_written, header.file_size) {
                        tracing::warn!(
                            "File stream {} exceeded cap; aborting, partial removed.",
                            header.id
                        );
                        drop(file);
                        let _ = tokio::fs::remove_file(&file_path).await;
                        return;
                    }
                    chunk_count += 1;

                    // Emit Progress (Throttled 200ms)
                    if last_emit.elapsed().as_millis() > 200 {
                         let _ = app.emit("file-progress", serde_json::json!({
                             "id": header.id,
                             "fileName": display_name,
                             "total": header.file_size,
                             "transferred": total_written
                         }));
                         last_emit = std::time::Instant::now();
                    }
                }
            }
        }
    }

    let total_time = start_time.elapsed();
    let mb = total_written as f64 / 1_000_000.0;
    let speed = mb / total_time.as_secs_f64();
    tracing::info!("File Stream Completed. Written {} chunks ({} bytes) in {:?}. Speed: {:.2} MB/s", chunk_count, total_written, total_time, speed);

    // Disk write failed mid-stream: drop the partial so a same-id retry
    // doesn't hit "exists or symlink", and return without emitting
    // file-received or file-corrupt (this is a write error, not a digest
    // mismatch — the mismatch arm below keeps its file-corrupt emit).
    if write_failed {
        drop(file);
        let _ = tokio::fs::remove_file(&file_path).await;
        return;
    }

    // Final Progress
    let _ = app.emit("file-progress", serde_json::json!({
         "id": header.id,
         "fileName": display_name,
         "total": header.file_size,
         "transferred": total_written
     }));

     // Integrity: compare SHA-256 over received plaintext against the
     // sender's digest. Mismatch → delete partial, emit file-corrupt, never
     // touch the clipboard. Legacy senders (sha256 == None) get a size-only
     // check flagged `integrity: legacy`.
     let actual: [u8; 32] = hasher.finalize().into();
     match check_digest(header.sha256, actual) {
         Integrity::Verified => {
             let _ = app.emit("file-received", serde_json::json!({
                 "id": header.id, "file_name": display_name,
                 "file_size": header.file_size, "file_index": header.file_index,
                 "path": file_path.to_string_lossy(), "integrity": "verified",
             }));
             // ... rest of success path (size check, clipboard set, notification)
             // falls through below.
         }
         Integrity::Legacy => {
             // Legacy sender: no digest, so the size check IS the integrity
             // check. Truncation → delete partial, emit file-corrupt, never
             // emit file-received.
             if total_written != header.file_size {
                 tracing::warn!("Legacy file size mismatch id={} idx={}: expected {}, got {} — dropping partial",
                     header.id, header.file_index, header.file_size, total_written);
                 drop(file);
                 let _ = tokio::fs::remove_file(&file_path).await;
                 let _ = app.emit("file-corrupt", serde_json::json!({
                     "id": header.id,
                     "file_index": header.file_index,
                     "integrity": "legacy-size-mismatch",
                     "expected": header.file_size,
                     "actual": total_written,
                 }));
                 return;
             }
             let _ = app.emit("file-received", serde_json::json!({
                 "id": header.id, "file_name": display_name,
                 "file_size": header.file_size, "file_index": header.file_index,
                 "path": file_path.to_string_lossy(), "integrity": "legacy",
             }));
         }
        Integrity::Mismatch => {
            tracing::warn!("Digest mismatch id={} idx={}", header.id, header.file_index);
            drop(file);
            let _ = tokio::fs::remove_file(&file_path).await;
            let _ = app.emit("file-corrupt", serde_json::json!({
                "id": header.id,
                "file_index": header.file_index,
                "integrity": "mismatch",
                "expected": hex32(&header.sha256.unwrap()),
                "actual": hex32(&actual),
            }));
            return;
        }
     }

     // Notification
     let settings = state.settings.lock().unwrap();
     if settings.notify_large_files && header.file_size > settings.max_auto_download_size {
         let body = format!("Download complete: {}", display_name);
         send_notification(&app, "Download Complete", &body, false, None, "history", NotificationPayload::None);
     }

    // 5. Verify Size
    if total_written == header.file_size {
        tracing::info!("File Transfer Verified OK");
        if let Some(path_str) = file_path.to_str() {
             crate::clipboard::set_clipboard_paths(&app, vec![path_str.to_string()]);
        }
    } else {
        tracing::warn!("File Transfer Incomplete! Expected {}, got {}", header.file_size, total_written);
    }
}

/// Gate for remote PeerRemoval targeting our own device id: always true —
/// a remote self-removal surfaces as a user approval request, never a silent
/// factory reset. `sender_fingerprint` (peer's cert SHA-256 hex) is plumbed
/// for cert-bound approval matching; keep its type `Option<String>` exactly.
pub(crate) fn remote_self_removal_needs_approval(target_id: &str, local_id: &str, _sender_fingerprint: &Option<String>) -> bool {
    target_id == local_id
}

/// Authorize a third-party kick: the kicker's presenting cert must resolve
/// to an explicitly trusted or manual peer. Fail-closed on missing/unknown
/// certs and on gossip-only identities. (A trusted peer can still kick
/// another member — full membership authorization is Phase C1.)
pub(crate) fn peer_removal_kicker_authorized(
    sender_fingerprint: &Option<String>,
    known_peers: &std::collections::HashMap<String, crate::peer::Peer>,
) -> bool {
    sender_fingerprint
        .as_deref()
        .and_then(|fp| resolve_sender_device_id(fp, known_peers))
        .is_some()
}

/// Bind a presenting mTLS cert to its paired device id: hex-encode each
/// pinned fingerprint in `known_peers` and match `sender_fingerprint`
/// (full lowercase hex from transport.rs). None = unknown cert.
///
/// H-3: only explicitly trusted or manual entries resolve — a
/// gossip-learned fingerprint (untrusted, non-manual) must never satisfy
/// sender verification without an explicit trust action.
pub(crate) fn resolve_sender_device_id(
    sender_fingerprint: &str,
    known_peers: &std::collections::HashMap<String, crate::peer::Peer>,
) -> Option<String> {
    known_peers.values().filter(|p| p.is_trusted || p.is_manual).find_map(|p| {
        let fp = p.fingerprint.as_ref()?;
        let hex: String = fp.iter().map(|b| format!("{:02x}", b)).collect();
        if hex.eq_ignore_ascii_case(sender_fingerprint) {
            Some(p.id.clone())
        } else {
            None
        }
    })
}

/// H-2 verdict for an inbound clipboard payload: the claimed `sender_id`
/// must equal the device id the presenting cert resolves to; unknown or
/// missing fingerprints drop (fail-closed), as does our own device id
/// (self-echo check on device id, not spoofable hostname). Returns the
/// verified id on accept.
pub(crate) fn verify_clipboard_sender(
    claimed_sender_id: &str,
    sender_fingerprint: &Option<String>,
    known_peers: &std::collections::HashMap<String, crate::peer::Peer>,
    local_device_id: &str,
) -> Option<String> {
    let actual = resolve_sender_device_id(sender_fingerprint.as_deref()?, known_peers)?;
    if actual != claimed_sender_id {
        return None;
    }
    if actual == local_device_id {
        return None;
    }
    Some(actual)
}

/// H-3 gate for unsolicited-ClusterInfo imports (gossip, untrusted until an
/// explicit trust action): persist only when an import is manual — mirrors
/// the PeerDiscovery `if peer.is_manual` gate.
pub(crate) fn cluster_info_imports_persistable(imported: &[crate::peer::Peer]) -> bool {
    imported.iter().any(|p| p.is_manual)
}

/// H-3 gate: never dial untrusted gossip imports — probe only imports that
/// are trusted or manual.
pub(crate) fn cluster_info_imports_to_probe(imported: Vec<crate::peer::Peer>) -> Vec<crate::peer::Peer> {
    imported.into_iter().filter(|p| p.is_trusted || p.is_manual).collect()
}

pub(crate) async fn handle_message(msg: Message, addr: std::net::SocketAddr, sender_fingerprint: Option<String>, listener_state: AppState, listener_handle: tauri::AppHandle, transport_inside: Transport) {
    match msg {
        Message::Clipboard(payload) => {
            tracing::debug!("Received Clipboard from {}", addr);
            let text = payload.text.clone();
            let id = payload.id.clone();
            let ts = payload.timestamp;
            let sender = payload.sender.clone();
            // H-2: bind the claimed sender_id to the presenting mTLS cert.
            // Spoofed, unknown, missing, or self (device-id) senders drop here.
            let verified_sender_id = {
                let kp = listener_state.known_peers.lock().unwrap();
                let local_id = listener_state.local_device_id.lock().unwrap().clone();
                match verify_clipboard_sender(&payload.sender_id, &sender_fingerprint, &kp, &local_id) {
                    Some(v) => v,
                    None => {
                        tracing::warn!("Dropping clipboard with unverified sender_id {:?}", payload.sender_id);
                        return;
                    }
                }
            };
            {
                            // Verify Timestamp Freshness (120s threshold)
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();

                            let diff = if now > ts {
                                now - ts
                            } else {
                                ts - now // Future timestamp (clock skew)
                            };

                            if diff > 120 {
                                tracing::warn!("Ignored stale clipboard message from {} (Timestamp: {}, Now: {}, Diff: {}s)", sender, ts, now, diff);
                                return;
                            }

                            // Self-echo already dropped by the cert-bound gate above (device id, not hostname).

                            // Loop/Dedupe Check — must match the sender-side
                            // signature in clipboard::common::payload_signature
                            // so a blob received from a peer correctly suppresses
                            // an immediate re-broadcast back to the cluster.
                            let content_signature =
                                crate::clipboard::common::payload_signature(&payload);

                            {
                                let mut last = listener_state.last_clipboard_content.lock().unwrap();
                                if *last == content_signature {
                                    tracing::debug!("Ignoring clipboard message - content matches last_clipboard_content");
                                    return;
                                }
                                *last = content_signature;
                            }

                            // Check Auto-Receive Setting
                            tracing::debug!("Received clipboard {} bytes from {}", text.len(), sender);

                            if let Some(files) = &payload.files {
                                if !files.is_empty() {
                                    #[cfg(desktop)]
                                    {
                                        let should_badge = if let Some(window) = listener_handle.get_webview_window("main") {
                                            match window.is_focused() {
                                                Ok(focused) => !focused,
                                                Err(_) => true,
                                            }
                                        } else {
                                            true
                                        };

                                        if should_badge {
                                            crate::tray::set_badge(&listener_handle, true);
                                        }
                                    }
                                }
                            }

                            // Create Payload Object (already created above as 'payload' or fallback)
                            // Use the one we constructed or parsed
                            let payload_obj = crate::protocol::ClipboardPayload {
                                id: id.clone(),
                                text: text.clone(),
                                files: payload.files.clone(),
                                blob: payload.blob.clone(),
                                formats: payload.formats.clone(),
                                timestamp: ts,
                                sender: sender.clone(),
                                sender_id: payload.sender_id.clone(),
                            };

                            // FILE HANDLING
                            if let Some(files) = &payload.files {
                                if !files.is_empty() {
                                    tracing::info!("Received File Metadata from {}: {} files", sender, files.len());
                                    crate::clipboard::common::record_and_emit(&listener_handle, &listener_state, "clipboard-change", &payload_obj);

                                    // Auto-Download Logic
                                    let (auto_recv, enable_ft, size_limit, notify_large) = {
                                        let s = listener_state.settings.lock().unwrap();
                                        (s.auto_receive, s.enable_file_transfer, s.max_auto_download_size, s.notify_large_files)
                                    };

                                    if !enable_ft {
                                        tracing::info!("File transfer disabled in settings. Ignoring auto-download.");
                                    } else {
                                        let mut total_size = 0u64;
                                        for f in files { total_size += f.size; }

                                        tracing::info!("File Transfer Logic: AutoRecv={}, TotalSize={}, Limit={}, NotifyLarge={}", auto_recv, total_size, size_limit, notify_large);

                                        if auto_recv && total_size <= size_limit {
                                            tracing::info!("Auto-downloading {} files ({} bytes)", files.len(), total_size);
                                            // Request Each File
                                            for (idx, _file_meta) in files.iter().enumerate() {
                                                tracing::info!("Requesting file {}/{}", idx, files.len());
                                                let req_payload = crate::protocol::FileRequestPayload {
                                                    id: id.clone(),
                                                    file_index: idx,
                                                    offset: 0,
                                                };
                                                let msg = Message::FileRequest(req_payload);
                                                if let Ok(data) = serde_json::to_vec(&msg) {
                                                    let transport_clone = transport_inside.clone();
                                                    let addr_clone = addr;
                                                    tauri::async_runtime::spawn(async move {
                                                        let _ = transport_clone.send_message(addr_clone, &data).await;
                                                    });
                                                }
                                            }
                                        } else {
                                            // Too large or auto-recv off
                                            if notify_large {
                                                tracing::info!("Large file or manual mode. Sending notification.");
                                                let body = format!("Received {} files from {}. Click to download.", files.len(), sender);
                                                let _body = format!("Received {} files from {}. Click to download.", files.len(), sender);
                                                // Create Payload for Download Button
                                                let payload = NotificationPayload::DownloadAvailable {
                                                    msg_id: id.clone(),
                                                    file_count: files.len(),
                                                    peer_id: payload.sender_id.clone(),
                                                };
                                                send_notification(&listener_handle, "Files Available", &body, true, None, "history", payload);
                                            } else {
                                                tracing::warn!("Large file received but 'notify_large_files' is FALSE. No notification sent.");
                                            }
                                        }
                                    } // End if !enable_ft else
                                } // End if !files.is_empty()
                            } // End if let Some(files)

                            // BLOB HANDLING (image clipboard data)
                            // Race protection: any fresh clipboard event from
                            // a peer supersedes an older in-flight clipboard-
                            // blob fetch. Cleared here unconditionally; the
                            // descriptor-fetch branch below overwrites with
                            // its own id immediately. Bytes from the older
                            // fetch still drain off the wire (so QUIC stays
                            // happy) but are discarded by the file-stream
                            // listener's id check.
                            {
                                let mut slot = listener_state.in_flight_clipboard_fetch.lock().unwrap();
                                *slot = None;
                            }
                            if let Some(blob) = payload_obj.blob.clone() {
                                if blob.is_descriptor() {
                                    // §3.3 large-blob descriptor path. Bytes
                                    // ride the `clustercut-file` ALPN, not
                                    // inline. Decide auto-fetch vs. user-
                                    // confirm based on `max_auto_download_size`.
                                    let total_size = blob.total_size.unwrap_or(0);
                                    let mb = total_size as f64 / (1024.0 * 1024.0);
                                    let is_text = blob.mime_type.starts_with("text/");
                                    let kind_lower = if is_text { "text" } else { "image" };
                                    let kind_title = if is_text { "Text" } else { "Image" };
                                    let (auto_recv, enable_ft, size_limit) = {
                                        let s = listener_state.settings.lock().unwrap();
                                        (s.auto_receive, s.enable_file_transfer, s.max_auto_download_size)
                                    };
                                    tracing::info!(
                                        "Received clipboard descriptor from {}: mime={}, total={} bytes{} fetch_id={}",
                                        sender,
                                        blob.mime_type,
                                        total_size,
                                        match (blob.width, blob.height) {
                                            (Some(w), Some(h)) => format!(", {}x{},", w, h),
                                            _ => String::new(),
                                        },
                                        blob.fetch_id.as_deref().unwrap_or("?")
                                    );

                                    if !enable_ft {
                                        tracing::info!("File transfer disabled in settings. Ignoring large clipboard descriptor.");
                                    } else if !auto_recv {
                                        // Manual mode — stash for confirm-via-UI.
                                        tracing::info!("[Clipboard] Auto-receive OFF. Storing pending clipboard descriptor from {}", sender);
                                        {
                                            let mut pending = listener_state.pending_clipboard.lock().unwrap();
                                            *pending = Some(payload_obj.clone());
                                        }
                                        crate::clipboard::common::record_and_emit(&listener_handle, &listener_state, "clipboard-pending", &payload_obj);

                                        // Notification is the primary cue that an
                                        // accept is waiting — gate on
                                        // `notify_large_files` (defaults true) so
                                        // it fires even when `data_received` is
                                        // off, mirroring the file-transfer accept
                                        // notification.
                                        let notify_large = listener_state.settings.lock().unwrap().notify_large_files;
                                        if notify_large {
                                            let title = format!("Large Clipboard {}", kind_title);
                                            send_notification(
                                                &listener_handle,
                                                &title,
                                                &format!("{:.1} MB {} from {} — accept to receive.", mb, kind_lower, sender),
                                                true,
                                                Some(3),
                                                "history",
                                                NotificationPayload::None,
                                            );
                                        }
                                    } else if total_size > size_limit {
                                        // Tier B2 — over auto-download threshold. Stash and notify with Accept.
                                        tracing::info!(
                                            "[ClipboardBlob] Descriptor {} bytes exceeds auto-download limit {} bytes — awaiting accept",
                                            total_size,
                                            size_limit
                                        );
                                        {
                                            let mut pending = listener_state.pending_clipboard.lock().unwrap();
                                            *pending = Some(payload_obj.clone());
                                        }
                                        crate::clipboard::common::record_and_emit(&listener_handle, &listener_state, "clipboard-pending", &payload_obj);

                                        let notify_large = listener_state.settings.lock().unwrap().notify_large_files;
                                        if notify_large {
                                            let title = format!("Large Clipboard {}", kind_title);
                                            send_notification(
                                                &listener_handle,
                                                &title,
                                                &format!("{:.1} MB {} from {} — accept to receive.", mb, kind_lower, sender),
                                                true,
                                                Some(3),
                                                "history",
                                                NotificationPayload::None,
                                            );
                                        }
                                    } else {
                                        // Tier B1 — auto-fetch via file-transfer ALPN.
                                        tracing::info!(
                                            "[ClipboardBlob] Auto-fetching descriptor ({} bytes, mime={})",
                                            total_size,
                                            blob.mime_type
                                        );
                                        // Race protection: mark this fetch as the in-flight one.
                                        // A newer event arriving mid-stream will overwrite the slot
                                        // and the older payload's bytes will still drain off the
                                        // wire but won't land on the OS clipboard.
                                        {
                                            let mut slot = listener_state.in_flight_clipboard_fetch.lock().unwrap();
                                            *slot = Some(id.clone());
                                        }

                                        crate::clipboard::common::record_and_emit(&listener_handle, &listener_state, "clipboard-blob-fetching", &payload_obj);

                                        let notifications = listener_state.settings.lock().unwrap().notifications.clone();
                                        if notifications.data_received {
                                            let title = format!("Receiving Clipboard {}", kind_title);
                                            send_notification(
                                                &listener_handle,
                                                &title,
                                                &format!("Receiving {:.1} MB {} from {}…", mb, kind_lower, sender),
                                                false,
                                                Some(2),
                                                "history",
                                                NotificationPayload::None,
                                            );
                                        }

                                        let req_payload = crate::protocol::FileRequestPayload {
                                            id: id.clone(),
                                            file_index: 0,
                                            offset: 0,
                                        };
                                        let msg = Message::FileRequest(req_payload);
                                        if let Ok(data) = serde_json::to_vec(&msg) {
                                            let transport_clone = transport_inside.clone();
                                            let sender_addr = addr;
                                            tauri::async_runtime::spawn(async move {
                                                if let Err(e) = transport_clone.send_message(sender_addr, &data).await {
                                                    tracing::error!("Failed to send clipboard FileRequest to {}: {}", sender_addr, e);
                                                }
                                            });
                                        }
                                    }
                                } else {
                                    let blob_size = blob.decoded_len();
                                    tracing::info!(
                                        "Received clipboard image from {}: mime={}, decoded={} bytes{}",
                                        sender,
                                        blob.mime_type,
                                        blob_size,
                                        match (blob.width, blob.height) {
                                            (Some(w), Some(h)) => format!(", {}x{}", w, h),
                                            _ => String::new(),
                                        }
                                    );
                                    let auto_receiver = { listener_state.settings.lock().unwrap().auto_receive };
                                    if auto_receiver {
                                        crate::clipboard::set_clipboard_image(&listener_handle, blob);
                                        crate::clipboard::common::record_and_emit(&listener_handle, &listener_state, "clipboard-change", &payload_obj);
                                    } else {
                                        tracing::info!("[Clipboard] Auto-receive OFF. Storing pending blob from {}", sender);
                                        {
                                            let mut pending = listener_state.pending_clipboard.lock().unwrap();
                                            *pending = Some(payload_obj.clone());
                                        }
                                        crate::clipboard::common::record_and_emit(&listener_handle, &listener_state, "clipboard-pending", &payload_obj);
                                    }

                                    let notifications = listener_state.settings.lock().unwrap().notifications.clone();
                                    if notifications.data_received {
                                        // Large blobs (§3.3 v1) get a more specific
                                        // notification with the size, so users know
                                        // the (potentially many MB) image is now
                                        // available to paste even if there was a
                                        // perceptible transfer delay.
                                        if blob_size > crate::clipboard::common::LARGE_CLIPBOARD_BLOB_NOTIFY_THRESHOLD {
                                            let mb = blob_size as f64 / (1024.0 * 1024.0);
                                            send_notification(
                                                &listener_handle,
                                                "Large Image Received",
                                                &format!("{:.1} MB image from {} is now on the clipboard.", mb, sender),
                                                false,
                                                Some(3),
                                                "history",
                                                NotificationPayload::None,
                                            );
                                        } else {
                                            send_notification(&listener_handle, "Image Received", "Image copied to clipboard", false, Some(2), "history", NotificationPayload::None);
                                        }
                                    }
                                }
                            }

                            // RICH HANDLING (text + alternate formats like text/html, text/rtf).
                            // Takes precedence over plain TEXT HANDLING so destination apps see
                            // the multi-MIME buffet the source had. Backends that can't yet write
                            // multi-format fall back to plain text inside set_clipboard_rich.
                            let rich_formats = payload_obj
                                .formats
                                .as_ref()
                                .filter(|fs| !fs.is_empty())
                                .cloned();

                            if let Some(formats) = rich_formats {
                                tracing::info!(
                                    "Received clipboard rich from {}: text={} chars, formats=[{}]",
                                    sender,
                                    text.len(),
                                    formats.iter().map(|f| f.mime_type.as_str()).collect::<Vec<_>>().join(", ")
                                );
                                // GNOME-only two-stage promotion (issue #17 follow-up).
                                // mutter's `Meta.SelectionSource` is single-MIME and
                                // can't be subclassed for multi-MIME from GJS (GJS #255),
                                // so the extension's `_writeFormats` is last-write-wins.
                                // Writing the rich payload directly leaves *only* the
                                // final rich MIME advertised — plain-text consumers
                                // (gedit, GNOME Text Editor, OnlyOffice, browser inputs)
                                // then get nothing on paste. Apply plain text by default
                                // so the broad case works, stash the full payload, and
                                // emit `rich-promotion-available` so the UI can offer a
                                // one-click "switch to rich format" promotion. Other
                                // backends (Windows, macOS, wlroots) write all MIMEs
                                // atomically and don't need this path.
                                let needs_promotion_dance: bool = {
                                    #[cfg(target_os = "linux")]
                                    {
                                        matches!(
                                            crate::clipboard::get_backend(),
                                            crate::clipboard::ClipboardBackend::GnomeExtension
                                        ) && !text.trim().is_empty()
                                    }
                                    #[cfg(not(target_os = "linux"))]
                                    {
                                        false
                                    }
                                };

                                let auto_receiver = { listener_state.settings.lock().unwrap().auto_receive };
                                if auto_receiver {
                                    if needs_promotion_dance {
                                        {
                                            let mut stash = listener_state.pending_rich_promotion.lock().unwrap();
                                            *stash = Some(payload_obj.clone());
                                        }
                                        crate::clipboard::set_clipboard(&listener_handle, text.clone());
                                        crate::clipboard::common::record_and_emit(&listener_handle, &listener_state, "clipboard-change", &payload_obj);
                                    } else {
                                        crate::clipboard::set_clipboard_rich(&listener_handle, text.clone(), formats);
                                        crate::clipboard::common::record_and_emit(&listener_handle, &listener_state, "clipboard-change", &payload_obj);
                                    }
                                } else {
                                    tracing::info!("[Clipboard] Auto-receive OFF. Storing pending rich clipboard from {}", sender);
                                    {
                                        let mut pending = listener_state.pending_clipboard.lock().unwrap();
                                        *pending = Some(payload_obj.clone());
                                    }
                                    crate::clipboard::common::record_and_emit(&listener_handle, &listener_state, "clipboard-pending", &payload_obj);
                                }

                                if needs_promotion_dance {
                                    // The promotion notification is the *only* path
                                    // to the rich format on a GNOME receiver — without
                                    // it the user has no way to upgrade past the
                                    // plain-text fallback. Surface unconditionally,
                                    // not gated on the generic `data_received`
                                    // toggle (which is off by default and used for
                                    // purely informational pings).
                                    send_notification(
                                        &listener_handle,
                                        "Pasted as plain text",
                                        &format!(
                                            "From {}. Click \"Switch to Rich\" to upgrade.",
                                            sender
                                        ),
                                        false,
                                        Some(2),
                                        "history",
                                        NotificationPayload::PromoteRichClipboard,
                                    );
                                } else {
                                    let notifications = listener_state.settings.lock().unwrap().notifications.clone();
                                    if notifications.data_received {
                                        send_notification(
                                            &listener_handle,
                                            "Clipboard Received",
                                            "Formatted content copied to clipboard",
                                            false,
                                            Some(2),
                                            "history",
                                            NotificationPayload::None,
                                        );
                                    }
                                }
                            } else if !text.trim().is_empty() {
                                // TEXT HANDLING — plain text only, no rich formats present.
                                // `trim().is_empty()` (not just `is_empty()`) drops
                                // whitespace-only payloads — e.g. a single newline or
                                // space bouncing around the cluster, which would
                                // otherwise overwrite a useful clipboard on every peer.
                                // Symmetric with the broadcast-side guard in
                                // `clipboard::common::process_clipboard_change`.
                                tracing::info!(
                                    "Received clipboard text from {}: {} chars",
                                    sender,
                                    text.len()
                                );
                                let auto_receiver = { listener_state.settings.lock().unwrap().auto_receive };
                                if auto_receiver {
                                    crate::clipboard::set_clipboard(&listener_handle, text.clone());
                                    crate::clipboard::common::record_and_emit(&listener_handle, &listener_state, "clipboard-change", &payload_obj);
                                } else {
                                    // Manual Mode
                                    tracing::info!("[Clipboard] Auto-receive OFF. Storing pending clipboard from {}", sender);
                                    {
                                        let mut pending = listener_state.pending_clipboard.lock().unwrap();
                                        *pending = Some(payload_obj.clone());
                                    }
                                    crate::clipboard::common::record_and_emit(&listener_handle, &listener_state, "clipboard-pending", &payload_obj);
                                }

                                let notifications = listener_state.settings.lock().unwrap().notifications.clone();
                                if notifications.data_received {
                                    send_notification(&listener_handle, "Clipboard Received", "Content copied to clipboard", false, Some(2), "history", NotificationPayload::None);
                                }
                            }

                            // Relay Logic — re-broadcast to other cluster
                            // members (mTLS authenticates each hop; no
                            // app-layer encryption needed).
                            let auto_send = { listener_state.settings.lock().unwrap().auto_send };
                            if !auto_send {
                                return;
                            }

                            let sender_addr = addr;
                            // Relay with the verified id/hostname, never the attacker claim.
                            let mut relay_obj = payload_obj.clone();
                            relay_obj.sender_id = verified_sender_id.clone();
                            if let Some(peer) = listener_state.known_peers.lock().unwrap().get(&relay_obj.sender_id) {
                                relay_obj.sender = peer.hostname.clone();
                            }
                            let relay_data = serde_json::to_vec(&Message::Clipboard(relay_obj)).unwrap_or_default();
                            let peers = listener_state.get_peers();
                            for p in peers.values() {
                                let p_addr = std::net::SocketAddr::new(p.ip, p.port);
                                if p_addr == sender_addr { continue; }
                                let _ = transport_inside.send_message(p_addr, &relay_data).await;
                            }
            }
        }
        Message::HistoryDelete(id) => {
            tracing::info!("Received HistoryDelete for ID: {}", id);
            let _ = listener_handle.emit("history-delete", &id);
        }
        Message::PeerDiscovery(mut peer) => {
            tracing::debug!("Received PeerDiscovery for {}", peer.hostname);

            let local_id = listener_state.local_device_id.lock().unwrap().clone();
            if peer.id == local_id {
                // Collision Detection:
                // If the sender IP is NOT one of our local IPs, then it's a remote device with the same ID.
                // This shouldn't happen unless the device was cloned (e.g. VM clone).
                let sender_ip = addr.ip();
                if !net_util::is_local_ip(sender_ip) {
                     tracing::warn!("Device ID Collision Detected! Remote peer at {} has the same ID as me ({}).", sender_ip, local_id);
                     send_notification(&listener_handle,
                         "Configuration Error",
                         &format!("Device ID Collision! Another device at {} shares your ID. Please reset one device.", sender_ip),
                         true,
                         None,
                         "settings",
                         NotificationPayload::None
                     );
                }
                return;
            }

            {
                let mut pending = listener_state.pending_removals.lock().unwrap();
                if pending.remove(&peer.id).is_some() {
                    tracing::info!("[Discovery] Cancelled pending removal for {} due to Heartbeat/Packet.", peer.id);
                }
            }

            peer.ip = addr.ip();
            peer.port = addr.port();
            peer.last_seen = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

            {
                let kp = listener_state.known_peers.lock().unwrap();
                if let Some(existing) = kp.get(&peer.id) {
                     peer.is_manual = existing.is_manual;
                     // Don't let a gossip update without a fingerprint clobber an
                     // already-pinned one. Sticky pinning until re-pair.
                     if peer.fingerprint.is_none() {
                         peer.fingerprint = existing.fingerprint.clone();
                     }
                } else {
                     peer.is_manual = false;
                }
            }

            let mut should_reply = false;
            {
                 let mut kp_lock = listener_state.known_peers.lock().unwrap();
                 let manual_id = format!("manual-{}", peer.ip);
                 if kp_lock.contains_key(&manual_id) {
                     tracing::info!("Replacing manual placeholder {} with real peer {}", manual_id, peer.id);
                     kp_lock.remove(&manual_id);
                     listener_state.peers.lock().unwrap().remove(&manual_id);
                     let _ = listener_handle.emit("peer-remove", &manual_id);
                     should_reply = true;
                     peer.is_manual = true;
                 }

                 let runtime_known = listener_state.peers.lock().unwrap().contains_key(&peer.id);
                 if !kp_lock.contains_key(&peer.id) && !runtime_known {
                     should_reply = true;
                 }

                  // Under v0.3 mTLS the gossip arrived over an authenticated
                  // QUIC connection, but authentication is not authorization:
                  // never auto-trust gossip — explicit user trust action required.
                  peer.is_trusted = false;

                 listener_state.add_peer(peer.clone());
                 let _ = listener_handle.emit("peer-update", crate::peer::PeerView::from_peer(&peer));

                 // Fire deferred join notification if this peer was pending verification
                 {
                     let mut pending_joins = listener_state.pending_join_notifications.lock().unwrap();
                     if pending_joins.remove(&peer.id) {
                         if listener_state.should_notify()
                             && listener_state.settings.lock().unwrap().notifications.device_join
                         {
                             tracing::info!("[Notification] Deferred 'Device Joined' fired for {} (confirmed by heartbeat)", peer.hostname);
                             send_notification(&listener_handle, "Device Joined", &format!("{} has joined your cluster", peer.hostname), false, Some(1), "devices", NotificationPayload::None);
                         }
                     }
                 }

                  if peer.is_manual {
                     kp_lock.insert(peer.id.clone(), peer.clone());
                     storage::save_known_peers(listener_handle.app_handle(), &kp_lock);
                 } else {
                     if kp_lock.contains_key(&peer.id) {
                         tracing::info!("Removing untrusted auto-peer {} from persistence.", peer.id);
                         kp_lock.remove(&peer.id);
                         storage::save_known_peers(listener_handle.app_handle(), &kp_lock);
                     }
                 }
            }

            if should_reply {
                tracing::debug!("Sending Discovery Reply to {}", addr);
                let local_id = listener_state.local_device_id.lock().unwrap().clone();
                let hostname = hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or("Unknown".to_string());
                let network_name = listener_state.network_name.lock().unwrap().clone();

                let my_peer = crate::peer::Peer {
                    id: local_id,
                    ip: transport_inside.local_addr().unwrap().ip(),
                    port: transport_inside.local_addr().unwrap().port(),
                    hostname,
                    last_seen: 0,
                    is_trusted: false,
                    is_manual: true,
                    network_name: Some(network_name),
                    signature: None,
                    fingerprint: Some(transport_inside.local_fingerprint()),
                    protocol_version: Some(crate::discovery::CLUSTERCUT_PROTOCOL_VERSION.to_string()),
                };

                let msg = Message::PeerDiscovery(my_peer);
                let data = serde_json::to_vec(&msg).unwrap_or_default();
                let transport_reply = transport_inside.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = transport_reply.send_message(addr, &data).await;
                });
            }

            // Anti-entropy: every time we hear from a peer (startup probe, mDNS
            // rediscovery, gossip), tell it our current cluster-name register so
            // peers that were offline during a rename converge. Gated on the
            // peer's protocol version inside send_cluster_name_to.
            {
                let name = listener_state.network_name.lock().unwrap().clone();
                let version = *listener_state.network_name_version.lock().unwrap();
                let origin = listener_state.network_name_origin.lock().unwrap().clone();
                let peer_addr = std::net::SocketAddr::new(peer.ip, peer.port);
                crate::net_util::send_cluster_name_to(
                    peer_addr,
                    peer.protocol_version.as_deref(),
                    name, version, origin,
                    &transport_inside,
                );
            }
        }
        Message::PeerRemoval(target_id) => {
            tracing::info!("Received PeerRemoval for {}", target_id);
            let local_id = listener_state.local_device_id.lock().unwrap().clone();

            if remote_self_removal_needs_approval(&target_id, &local_id, &sender_fingerprint) {
                // Root fix: remote peers can no longer trigger factory reset.
                // Only the local leave_network path (commands/peers.rs) calls perform_factory_reset.
                // Remote self-target → emit approval event for explicit user action.
                let _ = listener_handle.emit("peer-remove-approval-request", &sender_fingerprint);
                tracing::warn!("Ignoring remote self-removal from {:?}", sender_fingerprint);
                return;
            } else {
                // Third-party kick: the kicker must be an explicitly
                // trusted/manual peer — fail closed otherwise. (Full
                // membership authorization is Phase C1.)
                let authorized = {
                    let kp = listener_state.known_peers.lock().unwrap();
                    peer_removal_kicker_authorized(&sender_fingerprint, &kp)
                };
                if !authorized {
                    tracing::warn!("Ignoring PeerRemoval for {} from unauthorized sender {:?}", target_id, sender_fingerprint);
                    return;
                }
                // Tombstone the removed device so a member that missed this
                // broadcast can't gossip it back via membership sync.
                listener_state
                    .removed_peer_tombstones
                    .lock()
                    .unwrap()
                    .insert(target_id.clone());
                {
                    let mut kp = listener_state.known_peers.lock().unwrap();
                    if kp.remove(&target_id).is_some() {
                        storage::save_known_peers(listener_handle.app_handle(), &kp);
                    }
                }
                {
                    let mut peers = listener_state.peers.lock().unwrap();
                    if let Some(peer) = peers.remove(&target_id) {
                        drop(peers);
                        check_and_notify_leave(&listener_handle, &listener_state, &peer);
                    }
                }
                let _ = listener_handle.emit("peer-remove", &target_id);

                // The peer explicitly left. Our long-lived mDNS browse caches
                // and won't reliably re-resolve it when it re-appears under a
                // new cluster/identity, so kick off a fresh scan to pick up its
                // new cluster (and refresh everyone else) without needing an
                // app restart. Waits a couple seconds first so the leaver has
                // re-registered before we scan.
                crate::app::spawn_mdns_rescan(listener_state.clone(), listener_handle.clone());
            }
        }

        Message::FileRequest(req) => {
             // HANDLE FILE REQUEST (Sender). The connection is mTLS-pinned
             // to a paired peer, so we trust the request without an
             // app-layer auth token (issue #9 follow-up).
             tracing::info!("Received File Request from {}: ID={}, Index={}", addr, req.id, req.file_index);

             // H-2: only serve requests from a known (paired) cert. Fail
             // closed when the presenting fingerprint is missing or unpinned.
             {
                 let kp = listener_state.known_peers.lock().unwrap();
                 let known = sender_fingerprint
                     .as_deref()
                     .and_then(|fp| resolve_sender_device_id(fp, &kp))
                     .is_some();
                 if !known {
                     tracing::warn!("Dropping FileRequest with unknown sender fingerprint");
                     return;
                 }
             }

             // 2a. Clipboard-blob serve (§3.3): if `req.id` matches a
             // registered large clipboard blob, serve it with
             // `delivery_target = Clipboard{…}` so the receiver lands
             // the bytes on its OS clipboard. The temp file lives in
             // `temp_downloads/<id>.<ext>` (cleaned by the existing
             // startup `clear_cache`).
             let clipboard_blob_meta = {
                 let map = listener_state.local_clipboard_blobs.lock().unwrap();
                 map.get(&req.id).cloned()
             };

             if let Some(meta) = clipboard_blob_meta {
                                      let file_path = meta.path.clone();
                                      let mime_type = meta.mime_type.clone();
                                      let is_text = mime_type.starts_with("text/");
                                      let width = meta.width;
                                      let height = meta.height;
                                      let req_id = req.id.clone();
                                      let req_file_index = req.file_index;
                                      let serve_guard = ServeGuard::new(
                                          listener_state.serving_clipboard_blobs.clone(),
                                          req_id.clone(),
                                      );
                                      tauri::async_runtime::spawn(async move {
                                          let _serve_guard = serve_guard;
                                          let mut file = match File::open(&file_path).await {
                                              Ok(f) => f,
                                              Err(e) => {
                                                  tracing::error!(
                                                      "Failed to open clipboard-blob temp file {:?}: {}",
                                                      file_path, e
                                                  );
                                                  return;
                                              }
                                          };
                                           let file_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
                                           let file_name = file_path
                                               .file_name()
                                               .unwrap_or_default()
                                               .to_string_lossy()
                                               .to_string();
                                           let sha256 = match plaintext_sha256(&mut file).await {
                                               Ok(d) => d,
                                               Err(e) => {
                                                   tracing::warn!("Clipboard-blob hash failed, aborting send (fail-closed): {}", e);
                                                   return;
                                               }
                                           };
                                           tracing::info!(
                                               "Opening QUIC Stream to {} for clipboard-blob '{}' ({} bytes, mime={})",
                                               addr, file_name, file_size, mime_type
                                           );
                                           match transport_inside.send_file_stream(addr).await {
                                               Ok((_connection, mut stream)) => {
                                                   let header = crate::protocol::FileStreamHeader {
                                                       id: req_id,
                                                       file_index: req_file_index,
                                                       file_name,
                                                       file_size,
                                                       sha256: Some(sha256),
                                                       compressed: is_text,
                                                      delivery_target: crate::protocol::DeliveryTarget::Clipboard {
                                                          mime_type,
                                                          width,
                                                          height,
                                                      },
                                                  };
                                                  if let Ok(h_json) = serde_json::to_string(&header) {
                                                      if let Err(e) = stream.write_all(h_json.as_bytes()).await {
                                                          tracing::error!("Header Write Error: {}", e);
                                                          return;
                                                      }
                                                      if let Err(e) = stream.write_all(b"\n").await {
                                                          tracing::error!("Header Newline Error: {}", e);
                                                          return;
                                                      }
                                                  }
                                                  let mut buf = vec![0u8; 1024 * 1024];
                                                  let start_time = std::time::Instant::now();
                                                  let mut chunks_sent = 0;
                                                  if is_text {
                                                      tracing::info!("[Sender] Starting ZSTD clipboard-blob loop. File size: {}", file_size);
                                                      let mut encoder = async_compression::tokio::write::ZstdEncoder::with_quality(
                                                          stream,
                                                          async_compression::Level::Precise(crate::compression::ZSTD_LEVEL),
                                                      );
                                                      loop {
                                                          match file.read(&mut buf).await {
                                                              Ok(0) => break,
                                                              Ok(n) => {
                                                                  if let Err(e) = encoder.write_all(&buf[0..n]).await {
                                                                      tracing::error!("Clipboard-blob compressed stream write error: {}", e);
                                                                      break;
                                                                  }
                                                                  chunks_sent += 1;
                                                              }
                                                              Err(e) => { tracing::error!("Clipboard-blob file read error: {}", e); break; }
                                                          }
                                                      }
                                                      if let Err(e) = encoder.shutdown().await {
                                                          tracing::error!("Clipboard-blob encoder shutdown error: {}", e);
                                                      }
                                                      let mut stream = encoder.into_inner();
                                                      let total_time = start_time.elapsed();
                                                      tracing::info!(
                                                          "[Sender] Clipboard-blob ZSTD loop finished in {:?}. Chunks: {}",
                                                          total_time, chunks_sent
                                                      );
                                                      let _ = stream.finish();
                                                      drop(stream);
                                                  } else {
                                                      loop {
                                                          match file.read(&mut buf).await {
                                                              Ok(0) => break,
                                                              Ok(n) => {
                                                                  if let Err(e) = stream.write_all(&buf[0..n]).await {
                                                                      tracing::error!("Clipboard-blob stream write error: {}", e);
                                                                      break;
                                                                  }
                                                                  chunks_sent += 1;
                                                              }
                                                              Err(e) => { tracing::error!("Clipboard-blob file read error: {}", e); break; }
                                                          }
                                                      }
                                                      let total_time = start_time.elapsed();
                                                      tracing::info!(
                                                          "[Sender] Clipboard-blob stream finished in {:?}. Chunks: {}",
                                                          total_time, chunks_sent
                                                      );
                                                      let _ = stream.finish();
                                                      drop(stream);
                                                  }
                                                  let _ = tokio::time::timeout(
                                                      std::time::Duration::from_secs(300),
                                                      _connection.closed(),
                                                  ).await;
                                                  tracing::info!("Clipboard-blob sent successfully: {:?}", file_path);
                                              }
                                              Err(e) => tracing::error!("Failed to open clipboard-blob stream: {}", e),
                                          }
                                      });
                                      return;
                                 }

                                 // 2b. Find File Path (existing files path)
                                 let path = {
                                     let map = listener_state.local_files.lock().unwrap();
                                     if let Some(paths) = map.get(&req.id) {
                                         if req.file_index < paths.len() {
                                             Some(paths[req.file_index].clone())
                                         } else { None }
                                     } else { None }
                                 };

                                 if let Some(p_str) = path {
                                      let file_path = PathBuf::from(p_str.clone());
                                      let compress_enabled = listener_state.settings.lock().unwrap().compress_file_transfers;
                                      // 3. Open Stream & Send
                                      tauri::async_runtime::spawn(async move {
                                           // Open File
                                           let mut file = match File::open(&file_path).await {
                                               Ok(f) => f,
                                               Err(e) => { tracing::error!("Failed to open requested file: {}", e); return; }
                                           };
                                            let file_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
                                            let file_name = file_path.file_name().unwrap_or_default().to_string_lossy().to_string();
                                             let sha256 = match plaintext_sha256(&mut file).await {
                                                 Ok(d) => d,
                                                 Err(e) => {
                                                     tracing::warn!("File hash failed, aborting send (fail-closed): {}", e);
                                                     return;
                                                 }
                                             };

                                           tracing::info!("Opening QUIC Stream to {} for file '{}' ({} bytes)", addr, file_name, file_size);
                                           // Open QUIC Stream
                                           match transport_inside.send_file_stream(addr).await {
                                               Ok((_connection, mut stream)) => {
                                                   // Decide whether to compress this file (deterministic rules).
                                                   let compressed = compress_enabled
                                                       && crate::compression::should_compress(&file_name, file_size);

                                                   // Send Header (no auth_token; mTLS authenticates the sender).
                                                    let header = crate::protocol::FileStreamHeader {
                                                        id: req.id,
                                                        file_index: req.file_index,
                                                        file_name,
                                                        file_size,
                                                        sha256: Some(sha256),
                                                        compressed,
                                                       delivery_target: crate::protocol::DeliveryTarget::Disk,
                                                   };

                                                   if let Ok(h_json) = serde_json::to_string(&header) {
                                                       if let Err(e) = stream.write_all(h_json.as_bytes()).await { tracing::error!("Header Write Error: {}", e); return; }
                                                       if let Err(e) = stream.write_all(b"\n").await { tracing::error!("Header Newline Error: {}", e); return; }
                                                   }

                                                   // 5. Send File (raw or zstd-compressed depending on flag)
                                                   let mut buf = vec![0u8; 1024 * 1024]; // 1MB chunks
                                                   let mut chunks_sent = 0;
                                                   let start_time = std::time::Instant::now();

                                                   if compressed {
                                                       tracing::info!("[Sender] Starting ZSTD loop. File size: {}", file_size);
                                                       let mut encoder = async_compression::tokio::write::ZstdEncoder::with_quality(
                                                           stream,
                                                           async_compression::Level::Precise(crate::compression::ZSTD_LEVEL),
                                                       );
                                                       loop {
                                                           match file.read(&mut buf).await {
                                                               Ok(0) => break, // EOF
                                                               Ok(n) => {
                                                                   if let Err(e) = encoder.write_all(&buf[0..n]).await {
                                                                       tracing::error!("Compressed Stream Write Error: {}", e);
                                                                       break;
                                                                   }
                                                                   chunks_sent += 1;
                                                               }
                                                               Err(e) => { tracing::error!("File Read Error: {}", e); break; }
                                                           }
                                                       }
                                                       // Flush trailing zstd block before finishing the QUIC stream.
                                                       if let Err(e) = encoder.shutdown().await {
                                                           tracing::error!("Encoder Shutdown Error: {}", e);
                                                       }
                                                       let mut stream = encoder.into_inner();
                                                       let total_time = start_time.elapsed();
                                                       tracing::info!("[Sender] ZSTD loop finished in {:?}. Chunks: {}", total_time, chunks_sent);
                                                       let _ = stream.finish();
                                                       drop(stream);
                                                   } else {
                                                       tracing::info!("[Sender] Starting RAW loop. File size: {}", file_size);
                                                       loop {
                                                           match file.read(&mut buf).await {
                                                               Ok(0) => break, // EOF
                                                               Ok(n) => {
                                                                   // Write Raw Data
                                                                   if let Err(e) = stream.write_all(&buf[0..n]).await { tracing::error!("Stream Write Error: {}", e); break; }
                                                                   chunks_sent += 1;
                                                               }
                                                               Err(e) => { tracing::error!("File Read Error: {}", e); break; }
                                                           }
                                                       }
                                                       let total_time = start_time.elapsed();
                                                       tracing::info!("[Sender] Loop finished in {:?}. Chunks: {}", total_time, chunks_sent);
                                                       // Finish Stream (signals no more data will be written)
                                                       let _ = stream.finish();
                                                       drop(stream);
                                                   }

                                                   // Wait for the connection to close naturally.
                                                   // After all data is delivered and ACKed, both sides go idle,
                                                   // and the 30s idle timeout closes the connection.
                                                   // This is critical over high-latency links (e.g. VPN) where
                                                   // QUIC needs time to retransmit/deliver buffered data.
                                                   let _ = tokio::time::timeout(
                                                       std::time::Duration::from_secs(300),
                                                       _connection.closed()
                                                   ).await;

                                                   tracing::info!("File Sent Successfully: {}", p_str);
                                               }

                                               Err(e) => tracing::error!("Failed to open file stream: {}", e),
                                           }
                                      });
                                 } else {
                                     tracing::warn!("Requested file not found (ID: {}, Index: {})", req.id, req.file_index);
                                 }
        }
        Message::Ping => {
            tracing::debug!("Received Ping from {}. Sending Pong.", addr);
            // An authenticated Ping proves the sender is alive — refresh its
            // runtime entry so debounced removals/pruning don't fire on a
            // peer that is actively probing us.
            crate::presence::touch_peer_by_addr(&listener_state, addr);
            if let Ok(pong_data) = serde_json::to_vec(&Message::Pong) {
                let _ = transport_inside.send_message(addr, &pong_data).await;
            }
        }
        Message::ClusterInfoRequest => {
            // Post-pairing bootstrap reply (T6 → T7). The sender has already
            // passed our mTLS client-cert verifier (we just pinned its cert
            // in `handle_pairing_connection`), so the request is authenticated
            // and we can hand over our cluster state without further checks.
            let cluster_id = listener_state.cluster_id.lock().unwrap().clone();
            if cluster_id.is_empty() {
                tracing::warn!("ClusterInfoRequest from {} but we have no cluster_id", addr);
                return;
            }
            let known_peers_vec: Vec<_> = listener_state
                .known_peers
                .lock()
                .unwrap()
                .values()
                .cloned()
                .collect();
            let network_name = listener_state.network_name.lock().unwrap().clone();
            let network_name_version = *listener_state.network_name_version.lock().unwrap();
            let network_name_origin = listener_state.network_name_origin.lock().unwrap().clone();
            // Tell the joiner whether this cluster is provisioned so it can
            // converge onto the shared PIN (and persist it) rather than keep
            // its own per-device one. See ClusterInfo::cluster_mode.
            let cluster_mode = listener_state.settings.lock().unwrap().cluster_mode.clone();
            let info = crate::protocol::ClusterInfo {
                cluster_id,
                known_peers: known_peers_vec,
                network_name,
                network_name_version,
                network_name_origin,
                cluster_mode,
            };
            tracing::debug!("Replying to ClusterInfoRequest from {}", addr);
            match serde_json::to_vec(&Message::ClusterInfo(info)) {
                Ok(bytes) => {
                    if let Err(e) = transport_inside.send_message(addr, &bytes).await {
                        tracing::warn!("Failed to send ClusterInfo to {}: {}", addr, e);
                    }
                }
                Err(e) => tracing::error!("Failed to serialise ClusterInfo: {}", e),
            }
        }
        Message::ClusterInfo(info) => {
            // T7 reply to an in-progress `start_pairing`. mTLS already
            // authenticated the responder; we just hand off into the
            // pending oneshot. A stray ClusterInfo with no waiter is a
            // protocol-level no-op (logged + dropped).
            // Only the pairing responder's reply may satisfy the pairing
            // waiter — the anti-entropy loop also requests ClusterInfo, and
            // one of its replies landing mid-pairing must not be mistaken
            // for the responder's bootstrap (wrong cluster adoption).
            let waiter = {
                let mut slot = listener_state.pending_cluster_info.lock().unwrap();
                if slot.as_ref().map_or(false, |(expected, _)| *expected == addr) {
                    slot.take().map(|(_, tx)| tx)
                } else {
                    None
                }
            };
            match waiter {
                Some(tx) => {
                    let _ = tx.send(info);
                }
                None => {
                    // Unsolicited ClusterInfo = reply to an anti-entropy
                    // membership-sync request (the sender passed mTLS, so it
                    // is a paired member). Merge members we're missing.
                    let local_cluster = listener_state.cluster_id.lock().unwrap().clone();
                    if local_cluster.is_empty() || info.cluster_id != local_cluster {
                        tracing::warn!(
                            "Ignoring ClusterInfo from {} for foreign/unset cluster ({})",
                            addr,
                            info.cluster_id
                        );
                        return;
                    }
                    let imported = crate::presence::merge_cluster_membership(&listener_state, &info);
                    if imported.is_empty() {
                        return;
                    }
                    // H-3: gossip imports are untrusted — persist manual-only
                    // (mirrors the PeerDiscovery gate), never dial untrusted imports.
                    if cluster_info_imports_persistable(&imported) {
                        let kp = listener_state.known_peers.lock().unwrap();
                        storage::save_known_peers(listener_handle.app_handle(), &kp);
                    }
                    for peer in cluster_info_imports_to_probe(imported) {
                        tracing::info!(
                            "[Presence] Membership sync: learned {} ({}) from {}",
                            peer.hostname, peer.id, addr
                        );
                        let s = listener_state.clone();
                        let t = transport_inside.clone();
                        let a = listener_handle.clone();
                        tauri::async_runtime::spawn(async move {
                            let _ = crate::net_util::probe_ip(peer.ip, peer.port, s, t, a, false).await;
                        });
                    }
                }
            }
        }
        Message::ClusterName { name, version, origin } => {
            // Converge the shared cluster-name register (last-write-wins by
            // version, ties by origin). On a win: adopt, persist, re-register
            // mDNS, notify the UI, and re-gossip to other peers (excluding the
            // sender). If we are strictly newer, push our register back so the
            // sender converges up.
            let (local_version, local_origin) = {
                let v = *listener_state.network_name_version.lock().unwrap();
                let o = listener_state.network_name_origin.lock().unwrap().clone();
                (v, o)
            };

            if crate::cluster_name::incoming_register_wins(
                local_version, &local_origin, version, &origin,
            ) {
                {
                    *listener_state.network_name.lock().unwrap() = name.clone();
                    *listener_state.network_name_version.lock().unwrap() = version;
                    *listener_state.network_name_origin.lock().unwrap() = origin.clone();
                }
                crate::storage::save_network_name(&listener_handle, &name);
                crate::storage::save_network_name_version(&listener_handle, version);
                crate::storage::save_network_name_origin(&listener_handle, &origin);

                // Re-register mDNS with the adopted name.
                let device_id = listener_state.local_device_id.lock().unwrap().clone();
                let port = listener_state
                    .transport
                    .lock()
                    .unwrap()
                    .as_ref()
                    .and_then(|t| t.local_addr().ok())
                    .map(|a| a.port())
                    .unwrap_or(4654);
                if let Some(discovery) = listener_state.discovery.lock().unwrap().as_mut() {
                    let _ = discovery.register(&device_id, &name, port);
                }

                let _ = listener_handle.emit("network-update", ());
                tracing::info!("Adopted cluster name '{}' (v{} from {})", name, version, origin);

                // Re-gossip to everyone except the sender.
                crate::net_util::broadcast_cluster_name(
                    &name, version, &origin,
                    &listener_state, &transport_inside, Some(addr),
                );
            } else if local_version > version
                || (local_version == version && local_origin > origin)
            {
                // We hold a strictly-newer register; push it back to the sender
                // so it converges up. (Equal version + equal origin is a no-op.)
                let local_name = listener_state.network_name.lock().unwrap().clone();
                // Look up the sender's protocol version from known peers by addr.
                let sender_proto = listener_state
                    .get_peers()
                    .values()
                    .find(|p| std::net::SocketAddr::new(p.ip, p.port) == addr)
                    .and_then(|p| p.protocol_version.clone());
                crate::net_util::send_cluster_name_to(
                    addr,
                    sender_proto.as_deref(),
                    local_name,
                    local_version,
                    local_origin,
                    &transport_inside,
                );
            }
        }
        Message::Pong => {
             tracing::debug!("Received Pong from {}. Connection Verified.", addr);
             crate::presence::touch_peer_by_addr(&listener_state, addr);
             // Fire deferred join notification if the responding peer was pending
             let peer_id_opt = {
                 let peers = listener_state.peers.lock().unwrap();
                 peers.values().find(|p| p.ip == addr.ip() && p.port == addr.port()).map(|p| (p.id.clone(), p.hostname.clone()))
             };
             if let Some((peer_id, hostname)) = peer_id_opt {
                 let mut pending_joins = listener_state.pending_join_notifications.lock().unwrap();
                 if pending_joins.remove(&peer_id) {
                     if listener_state.should_notify()
                         && listener_state.settings.lock().unwrap().notifications.device_join
                     {
                         tracing::info!("[Notification] Deferred 'Device Joined' fired for {} (confirmed by Pong)", hostname);
                         send_notification(&listener_handle, "Device Joined", &format!("{} has joined your cluster", hostname), false, Some(1), "devices", NotificationPayload::None);
                     }
                 }
             }
        }
    }
}

#[cfg(test)]
mod traversal_tests {
    use super::{safe_store_path, check_digest, Integrity};
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("cc_trav_{}_{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn rejects_dotdot_id_and_abs_filename() {
        let d = tmp("rejects_dotdot");
        assert!(safe_store_path(&d, "../../evil", "png").is_err());
        assert!(safe_store_path(&d, "/abs", "png").is_err());
        assert!(safe_store_path(&d, "a/b", "png").is_err());
        // Windows separator
        assert!(safe_store_path(&d, "..\\evil", "png").is_err());
    }

    #[test]
    #[cfg(unix)]
    fn rejects_symlink_at_target() {
        let d = tmp("rejects_symlink");
        let id = uuid::Uuid::new_v4().to_string();
        let target = d.join(format!("{id}.png"));
        let outside = d.join("outside.txt");
        std::fs::write(&outside, b"x").unwrap();
        symlink(&outside, &target).unwrap();
        assert!(safe_store_path(&d, &id, "png").is_err());
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn valid_uuid_passes_and_stays_inside() {
        let d = tmp("valid_uuid");
        let id = uuid::Uuid::new_v4().to_string();
        let p = safe_store_path(&d, &id, "png").unwrap();
        assert!(p.starts_with(&d));
        assert_eq!(p.extension().unwrap(), "png");
    }

    #[test]
    fn check_digest_match_is_verified() {
        let digest = [9u8; 32];
        assert_eq!(check_digest(Some(digest), digest), Integrity::Verified);
    }

    #[test]
    fn check_digest_single_byte_flip_is_mismatch() {
        let mut flipped = [9u8; 32];
        flipped[0] ^= 0x01;
        assert_eq!(check_digest(Some([9u8; 32]), flipped), Integrity::Mismatch);
    }

    #[test]
    fn check_digest_none_is_legacy() {
        assert_eq!(check_digest(None, [9u8; 32]), Integrity::Legacy);
    }

    #[test]
    fn peer_removal_self_never_resets_remotely() {
        // Task 1 gate: a remote PeerRemoval targeting our own id ALWAYS needs
        // explicit user approval — never a silent reset — regardless of the
        // sender fingerprint. (Cert-bound fingerprint matching lands in Tasks
        // 2-3; the param is plumbed but not yet compared, hence the name.)
        use super::remote_self_removal_needs_approval;
        // Non-matching fingerprint → approval, no reset.
        assert!(remote_self_removal_needs_approval("local-id", "local-id", &Some("other-fp".into())));
        // Missing fingerprint → approval, no reset.
        assert!(remote_self_removal_needs_approval("local-id", "local-id", &None));
        // Even a matching fingerprint goes through approval (no silent self-wipe).
        assert!(remote_self_removal_needs_approval("local-id", "local-id", &Some("local-fp".into())));
        // Different target → normal tombstone path, no approval.
        assert!(!remote_self_removal_needs_approval("other-id", "local-id", &Some("other-fp".into())));
    }

    #[test]
    fn clipboard_rejects_sender_mismatch() {
        // H-2: payload.sender_id = "victim-id" but the presenting cert
        // fingerprint maps to "attacker-id" → the handler must drop it.
        // (handle_message needs a live AppHandle, unbuildable in unit
        // tests, so this locks the exact verdict production branches on;
        // clipboard_branch_binds_sender_to_cert below locks the wiring.)
        use super::{resolve_sender_device_id, verify_clipboard_sender};
        use std::collections::HashMap;
        fn peer(id: &str, hostname: &str, fp: &[u8]) -> crate::peer::Peer {
            crate::peer::Peer {
                id: id.to_string(),
                ip: "10.0.0.2".parse().unwrap(),
                port: 4654,
                hostname: hostname.to_string(),
                last_seen: 0,
                is_trusted: true,
                is_manual: false,
                network_name: None,
                signature: None,
                fingerprint: Some(fp.to_vec()),
                protocol_version: None,
            }
        }
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
        let attacker_fp = [7u8; 32];
        let victim_fp = [9u8; 32];
        let local_fp = [3u8; 32];
        let mut kp = HashMap::new();
        kp.insert("attacker-id".to_string(), peer("attacker-id", "attacker", &attacker_fp));
        kp.insert("victim-id".to_string(), peer("victim-id", "victim", &victim_fp));
        kp.insert("local-id".to_string(), peer("local-id", "mine", &local_fp));
        // Resolver binds the fingerprint to the presenting device, not the claim.
        assert_eq!(
            resolve_sender_device_id(&hex(&attacker_fp), &kp).as_deref(),
            Some("attacker-id")
        );
        // Spoofed sender_id over the attacker's cert → drop (None).
        assert_eq!(
            verify_clipboard_sender("victim-id", &Some(hex(&attacker_fp)), &kp, "local-id"),
            None
        );
        // Matching claim → verified id returned.
        assert_eq!(
            verify_clipboard_sender("attacker-id", &Some(hex(&attacker_fp)), &kp, "local-id"),
            Some("attacker-id".to_string())
        );
        // Unknown fingerprint → drop (fail-closed).
        assert_eq!(
            verify_clipboard_sender("attacker-id", &Some(hex(&[1u8; 32])), &kp, "local-id"),
            None
        );
        // Missing fingerprint → drop (fail-closed).
        assert_eq!(verify_clipboard_sender("attacker-id", &None, &kp, "local-id"), None);
        // Own device id (not hostname) → drop as self-echo.
        assert_eq!(
            verify_clipboard_sender("local-id", &Some(hex(&local_fp)), &kp, "local-id"),
            None
        );
    }

    #[test]
    fn gossip_fingerprint_never_verifies_sender() {
        // H-3/H-2: a gossip-learned fingerprint (untrusted, non-manual)
        // must not satisfy sender verification — explicit trust required.
        use super::{resolve_sender_device_id, verify_clipboard_sender};
        use std::collections::HashMap;
        fn gpeer(id: &str, fp: &[u8]) -> crate::peer::Peer {
            crate::peer::Peer {
                id: id.to_string(),
                ip: "10.0.0.9".parse().unwrap(),
                port: 4654,
                hostname: format!("host-{id}"),
                last_seen: 0,
                is_trusted: false,
                is_manual: false,
                network_name: None,
                signature: None,
                fingerprint: Some(fp.to_vec()),
                protocol_version: None,
            }
        }
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
        let gossip_fp = [7u8; 32];
        let mut kp = HashMap::new();
        kp.insert("gossip-id".to_string(), gpeer("gossip-id", &gossip_fp));
        assert_eq!(resolve_sender_device_id(&hex(&gossip_fp), &kp), None);
        assert_eq!(
            verify_clipboard_sender("gossip-id", &Some(hex(&gossip_fp)), &kp, "local-id"),
            None
        );
    }

    #[test]
    fn clipboard_branch_binds_sender_to_cert() {
        // Wiring lock: the Clipboard arm of handle_message must resolve the
        // sender via cert fingerprint (not trust payload.sender_id) and must
        // no longer self-check by spoofable hostname. Restoring the blind
        // trust / hostname check fails here.
        let src = include_str!("handlers.rs");
        let arm_start = src
            .find("Message::Clipboard(payload) => {")
            .expect("Clipboard arm must exist in handle_message");
        let after = &src[arm_start..];
        let next_arm = after[1..]
            .find("\n        Message::HistoryDelete(id) => {")
            .map(|i| arm_start + 1 + i)
            .unwrap_or(src.len());
        let arm = &src[arm_start..next_arm];
        assert!(
            arm.contains("verify_clipboard_sender("),
            "Clipboard arm must verify sender_id against the presenting cert"
        );
        assert!(
            arm.contains("verified_sender_id"),
            "Clipboard relay must re-serialize with the verified id, never the attacker claim"
        );
        assert!(
            !arm.contains("get_hostname_internal"),
            "Clipboard arm must not self-check by spoofable hostname (device-id check instead)"
        );
    }

    #[test]
    fn file_request_branch_requires_known_fingerprint() {
        // Wiring lock: the FileRequest arm serves bytes, so it must drop
        // requests whose presenting cert is missing/unpinned. Removing the
        // resolve_sender_device_id call from this arm fails here.
        let src = include_str!("handlers.rs");
        let arm_start = src
            .find("Message::FileRequest(req) => {")
            .expect("FileRequest arm must exist in handle_message");
        let after = &src[arm_start..];
        let next_arm = after[1..]
            .find("\n        Message::")
            .map(|i| arm_start + 1 + i)
            .unwrap_or(src.len());
        let arm = &src[arm_start..next_arm];
        assert!(
            arm.contains("resolve_sender_device_id("),
            "FileRequest arm must resolve the presenting cert against known_peers"
        );
    }

    #[test]
    fn peer_discovery_gossip_never_auto_trusted() {
        // Wiring lock (H-3): the PeerDiscovery arm must never auto-trust
        // gossip (`is_trusted = true`) and the persist gate must be
        // manual-only (no `|| peer.is_trusted`). Restoring either fails
        // here. (handle_message needs a live AppHandle, unbuildable in
        // unit tests, so this locks the wiring; presence.rs
        // gossip_import_is_untrusted locks the merge behavior.)
        let src = include_str!("handlers.rs");
        let arm_start = src
            .find("Message::PeerDiscovery(mut peer) => {")
            .expect("PeerDiscovery arm must exist in handle_message");
        let after = &src[arm_start..];
        let next_arm = after[1..]
            .find("\n        Message::")
            .map(|i| arm_start + 1 + i)
            .unwrap_or(src.len());
        let arm = &src[arm_start..next_arm];
        assert!(
            !arm.contains("is_trusted = true"),
            "PeerDiscovery arm must never auto-trust gossip (explicit trust action required)"
        );
        assert!(
            !arm.contains("|| peer.is_trusted"),
            "PeerDiscovery persist gate must be manual-only"
        );
    }

    #[test]
    fn cluster_info_untrusted_imports_not_persisted_or_probed() {
        // H-3: merge output is untrusted + non-manual → no disk persist, no dial.
        use super::{cluster_info_imports_persistable, cluster_info_imports_to_probe};
        fn peer(id: &str, is_trusted: bool, is_manual: bool) -> crate::peer::Peer {
            crate::peer::Peer {
                id: id.to_string(),
                ip: "10.0.0.2".parse().unwrap(),
                port: 4654,
                hostname: format!("host-{id}"),
                last_seen: 0,
                is_trusted,
                is_manual,
                network_name: None,
                signature: None,
                fingerprint: Some(vec![1, 2, 3]),
                protocol_version: None,
            }
        }
        let gossip = vec![peer("new-id", false, false)];
        assert!(!cluster_info_imports_persistable(&gossip));
        assert!(cluster_info_imports_to_probe(gossip).is_empty());
        // Trusted-but-not-manual: dialed, never written to disk.
        let trusted = vec![peer("trusted-id", true, false)];
        assert!(!cluster_info_imports_persistable(&trusted));
        assert_eq!(cluster_info_imports_to_probe(trusted).len(), 1);
    }

    #[test]
    fn cluster_info_manual_imports_persisted_and_probed() {
        // Guard against over-blocking: manual imports keep persist + probe.
        use super::{cluster_info_imports_persistable, cluster_info_imports_to_probe};
        let manual = vec![crate::peer::Peer {
            id: "manual-id".to_string(),
            ip: "10.0.0.3".parse().unwrap(),
            port: 4654,
            hostname: "host-manual-id".to_string(),
            last_seen: 0,
            is_trusted: false,
            is_manual: true,
            network_name: None,
            signature: None,
            fingerprint: Some(vec![1, 2, 3]),
            protocol_version: None,
        }];
        assert!(cluster_info_imports_persistable(&manual));
        assert_eq!(cluster_info_imports_to_probe(manual).len(), 1);
    }

    #[test]
    fn cluster_info_arm_gates_persist_and_probe() {
        // Wiring lock (H-3): the unsolicited-ClusterInfo arm must not
        // unconditionally save_known_peers / probe_ip its imports — gossip
        // imports are untrusted until an explicit trust action. Restoring
        // the unconditional save+probe fails here. (handle_message needs a
        // live AppHandle, unbuildable in unit tests; the gate verdicts are
        // covered behaviorally by cluster_info_*_imports_* below.)
        let src = include_str!("handlers.rs");
        let arm_start = src
            .find("Message::ClusterInfo(info) => {")
            .expect("ClusterInfo arm must exist in handle_message");
        let after = &src[arm_start..];
        let next_arm = after[1..]
            .find("\n        Message::")
            .map(|i| arm_start + 1 + i)
            .unwrap_or(src.len());
        let arm = &src[arm_start..next_arm];
        assert!(
            arm.contains("cluster_info_imports_persistable("),
            "ClusterInfo arm must gate persistence on manual-only imports"
        );
        assert!(
            arm.contains("cluster_info_imports_to_probe("),
            "ClusterInfo arm must gate probing on trusted/manual imports"
        );
    }

    #[test]
    fn file_stream_rejects_oversize_header() {
        // H-4 RED: the file-stream header line must be capped at 8KB so a
        // >8KB header without newline returns before File::create.
        // (handle_incoming_file_stream needs QUIC + AppHandle, unbuildable
        // in unit tests, so this locks the wiring like Tasks 1-3.)
        let src = include_str!("handlers.rs");
        let fn_start = src
            .find("pub(crate) async fn handle_incoming_file_stream")
            .expect("file-stream handler must exist");
        // Scope to the handler body: the test module below mentions these
        // constant names, so an unbounded slice would self-match.
        let fn_end = src[fn_start..]
            .find("/// Gate for remote PeerRemoval")
            .expect("handler body must end before the PeerRemoval gate");
        let arm = &src[fn_start..fn_start + fn_end];
        assert!(
            arm.contains("MAX_FILE_STREAM_HEADER"),
            "file-stream header read must be capped at MAX_FILE_STREAM_HEADER (8KB)"
        );
    }

    #[test]
    fn file_stream_aborts_over_cap() {
        // H-4 RED: header.file_size past the cap must abort before
        // File::create, and loop overruns must drop the partial file.
        let src = include_str!("handlers.rs");
        let fn_start = src
            .find("pub(crate) async fn handle_incoming_file_stream")
            .expect("file-stream handler must exist");
        let fn_end = src[fn_start..]
            .find("/// Gate for remote PeerRemoval")
            .expect("handler body must end before the PeerRemoval gate");
        let arm = &src[fn_start..fn_start + fn_end];
        assert!(
            arm.contains("MAX_FILE_STREAM_BYTES"),
            "file-stream must pre-check header.file_size against MAX_FILE_STREAM_BYTES"
        );
        assert!(
            arm.contains("MAX_DECOMP_BUDGET"),
            "zstd file-stream path must budget decompressed bytes"
        );
        assert!(
            arm.contains("STREAM_READ_TIMEOUT"),
            "file-stream reads must be wrapped in STREAM_READ_TIMEOUT"
        );
        let cap_pos = arm
            .find("MAX_FILE_STREAM_BYTES")
            .expect("cap check must exist");
        let create_pos = arm.find("create_new").expect("create_new must exist");
        assert!(
            cap_pos < create_pos,
            "oversize pre-check must run before File::create (no partial to clean up)"
        );
    }

    #[test]
    fn file_stream_caps_are_exact() {
        // H-4: exact required values — 8KB header, 2GiB size, 2GiB decomp, 30s.
        use super::{
            MAX_DECOMP_BUDGET, MAX_FILE_STREAM_BYTES, MAX_FILE_STREAM_HEADER,
            STREAM_READ_TIMEOUT,
        };
        assert_eq!(MAX_FILE_STREAM_HEADER, 8 * 1024);
        assert_eq!(MAX_FILE_STREAM_BYTES, 2_147_483_648);
        assert_eq!(MAX_DECOMP_BUDGET, 2_147_483_648);
        assert_eq!(STREAM_READ_TIMEOUT, std::time::Duration::from_secs(30));
    }

    #[test]
    fn file_stream_header_verdict_trips_over_8k() {
        use super::file_stream_header_allowed;
        assert!(file_stream_header_allowed(8 * 1024));
        assert!(!file_stream_header_allowed(8 * 1024 + 1));
    }

    #[test]
    fn file_stream_size_verdict_rejects_u64_max() {
        // H-4: header.file_size = u64::MAX with the 2GiB cap → reject, so the
        // handler returns before File::create (no partial to remove).
        use super::{file_stream_size_allowed, stream_over_budget};
        assert!(file_stream_size_allowed(2_147_483_648));
        assert!(!file_stream_size_allowed(u64::MAX));
        // And a stream that keeps flowing past the clamp aborts: the
        // enforceable limit is min(declared, cap), so a lying header still
        // trips at 2GiB and the partial is removed.
        assert!(!stream_over_budget(2_147_483_648, u64::MAX));
        assert!(stream_over_budget(2_147_483_648 + 1, u64::MAX));
        assert!(stream_over_budget(11, 10));
        assert!(!stream_over_budget(10, 10));
    }

    #[test]
    fn legacy_truncation_drops_partial() {
        // Legacy senders have no digest: a truncated transfer must not
        // emit file-received and keep the partial — delete + file-corrupt.
        let src = include_str!("handlers.rs");
        let fs_start = src
            .find("pub(crate) async fn handle_incoming_file_stream")
            .expect("file-stream handler must exist");
        let fs = &src[fs_start..];
        let arm_start = fs_start
            + fs
                .find("Integrity::Legacy => {")
                .expect("Legacy arm must exist");
        let after = &src[arm_start..];
        let arm_end = after
            .find("Integrity::Mismatch => {")
            .map(|i| arm_start + i)
            .unwrap_or(src.len());
        let arm = &src[arm_start..arm_end];
        assert!(
            arm.contains("remove_file"),
            "Legacy size mismatch must delete the partial file"
        );
        assert!(
            arm.contains("file-corrupt"),
            "Legacy size mismatch must emit file-corrupt, not file-received"
        );
    }

    #[test]
    fn blob_stream_reads_are_timed_out() {
        // Slowloris lock: the clipboard-blob drain loop must wrap every
        // read in STREAM_READ_TIMEOUT, like the file path does.
        let src = include_str!("handlers.rs");
        let fn_start = src
            .find("async fn handle_incoming_clipboard_blob_stream")
            .expect("blob-stream handler must exist");
        let fn_end = src[fn_start..]
            .find("pub(crate) async fn handle_incoming_file_stream")
            .expect("blob body must end before the file-stream handler");
        let body = &src[fn_start..fn_start + fn_end];
        // The macro's main read (not just the over-cap remainder drain)
        // must be timeout-wrapped: count timeout-wrapped reads — drain
        // macro + remainder drain = at least 2.
        let count = body.matches("tokio::time::timeout(STREAM_READ_TIMEOUT").count();
        assert!(
            count >= 2,
            "blob-stream main read must be timeout-wrapped (found {} timeout reads)",
            count
        );
    }

    #[test]
    fn peer_removal_kicker_must_be_trusted() {
        // Third-party kicks: unknown/missing certs and gossip-only
        // identities are refused; a trusted peer's kick is admitted.
        use super::peer_removal_kicker_authorized;
        use std::collections::HashMap;
        fn peer(id: &str, is_trusted: bool, fp: &[u8]) -> crate::peer::Peer {
            crate::peer::Peer {
                id: id.to_string(),
                ip: "10.0.0.2".parse().unwrap(),
                port: 4654,
                hostname: format!("host-{id}"),
                last_seen: 0,
                is_trusted,
                is_manual: false,
                network_name: None,
                signature: None,
                fingerprint: Some(fp.to_vec()),
                protocol_version: None,
            }
        }
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
        let trusted_fp = [5u8; 32];
        let gossip_fp = [6u8; 32];
        let mut kp = HashMap::new();
        kp.insert("trusted".to_string(), peer("trusted", true, &trusted_fp));
        kp.insert("gossip".to_string(), peer("gossip", false, &gossip_fp));
        assert!(peer_removal_kicker_authorized(&Some(hex(&trusted_fp)), &kp));
        assert!(!peer_removal_kicker_authorized(&Some(hex(&gossip_fp)), &kp));
        assert!(!peer_removal_kicker_authorized(&Some(hex(&[1u8; 32])), &kp));
        assert!(!peer_removal_kicker_authorized(&None, &kp));
    }

    #[test]
    fn peer_removal_arm_authorizes_third_party_kicks() {
        // Wiring lock: the PeerRemoval arm must authorize non-self kicks
        // via peer_removal_kicker_authorized — any paired peer tombstoning
        // any other device id with no check fails here.
        let src = include_str!("handlers.rs");
        let arm_start = src
            .find("Message::PeerRemoval(target_id) => {")
            .expect("PeerRemoval arm must exist in handle_message");
        let after = &src[arm_start..];
        let next_arm = after[1..]
            .find("\n        Message::")
            .map(|i| arm_start + 1 + i)
            .unwrap_or(src.len());
        let arm = &src[arm_start..next_arm];
        assert!(
            arm.contains("peer_removal_kicker_authorized("),
            "PeerRemoval arm must authorize the kicker for non-self removals"
        );
    }

    #[test]
    fn peer_removal_self_branch_never_resets() {
        // Wiring lock: the PeerRemoval arm of handle_message must not call
        // perform_factory_reset — self-targets go through approval only.
        // Reintroducing the unconditional self-wipe in this arm fails here.
        // (Scoped to the arm so a future user-approved reset elsewhere stays legal.)
        let src = include_str!("handlers.rs");
        let arm_start = src
            .find("Message::PeerRemoval(target_id) => {")
            .expect("PeerRemoval arm must exist in handle_message");
        let after = &src[arm_start..];
        let next_arm = after[1..]
            .find("\n        Message::")
            .map(|i| arm_start + 1 + i)
            .unwrap_or(src.len());
        let arm = &src[arm_start..next_arm];
        // Call syntax (with paren) so prose comments mentioning the function
        // name don't trip this; the restored self-wipe calls it as
        // `perform_factory_reset(` / `crate::perform_factory_reset(`.
        assert!(
            !arm.contains("perform_factory_reset("),
            "PeerRemoval arm must not call perform_factory_reset (self-wipe goes through approval)"
        );
    }
}
