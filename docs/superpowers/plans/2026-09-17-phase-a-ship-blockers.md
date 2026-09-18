# Phase A Ship-Blockers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close Phase A P0 ship-blockers (traversal, integrity digest, log/zeroize, permissions) without breaking LAN sync UX.

**Architecture:** Fix both file-write sinks with UUID-validated `safe_store_path` + `create_new`; add optional SHA-256 plaintext digest on `FileStreamHeader` (wire 0.4.0, read floor stays 0.3.3); delete payload log + wrap secrets in `Zeroizing` + move log dir; extend `set_owner_only` to all AppConfig writes with 0700 parents.

**Tech Stack:** Rust (tauri 2, tokio, serde_json, sha2 0.10 already present, uuid 1.19 with v4, zeroize 1 NEW), cargo test.

**Spec:** `docs/SECURITY-HARDENING-SPEC.md` (§4 A1–A4, §5, §7 rollout step 1, §8 acceptance for Phase A)

## Global Constraints

- Wire write version becomes `0.4.0` in `src-tauri/src/discovery.rs:27`; read-compat floor in `src-tauri/src/net_util.rs:30-38` stays `>=0.3.3`.
- All new wire fields MUST be `Option + #[serde(default)]` following existing `compressed`/`delivery_target`/`content_hash` pattern; never bare `[u8;32]`.
- `ClipboardBlob.content_hash` (`src-tauri/src/protocol.rs:50`) is broadcast-dedup only — never use as integrity proof.
- F1–F4 must not regress: auto text/image sync, manual file approve flow, history recall, mDNS + manual CIDR + remote peers, offline-first.
- No `canonicalize().unwrap_or()` gate; TOCTOU safety comes from `create_new` + `symlink_metadata` pre-check.
- Display name (`header.file_name`) stored only in metadata/emit, never joined to a path.
- `sha256 == None` (pre-0.4.0 peer) → accept with size-only check + `integrity=legacy` flag in emit; never hard-reject in 0.4.4.
- Log grep `rg "Decrypted Clipboard from.*text" src-tauri/src` must be empty after Task 3.
- Do not add new dependencies except `zeroize = "1"` in this plan.

---

### Task 1: A1 Path traversal fix (both sinks)

**Files:**
- Modify: `src-tauri/src/handlers.rs:18-47` (blob `id` sink `stage_received_clipboard_blob`)
- Modify: `src-tauri/src/handlers.rs:382-416` (file `file_name` sink, delete collision loop `392-408`, replace `File::create`)
- Test: `src-tauri/src/handlers.rs` (add `#[cfg(test)] mod traversal_tests` at end of file, or extend existing test module if present)

**Interfaces:**
- Consumes: `crate::clipboard::common::extension_for_clipboard_mime(mime: &str) -> &'static str` (existing, returns fixed static str — no validation needed on `ext` beyond alnum filter).
- Produces: `fn safe_store_path(cache_dir: &std::path::Path, id: &str, ext: &str) -> anyhow::Result<std::path::PathBuf>` — Task 2 reuses this path helper (receiver writes verified bytes to the returned path; no re-derivation from peer strings). If `anyhow` is not already a dependency, use `Result<PathBuf, String>` instead with identical semantics.

- [ ] **Step 1: Write failing traversal tests**

```rust
#[cfg(test)]
mod traversal_tests {
    use super::safe_store_path;
    use std::os::unix::fs::symlink;

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("cc_trav_{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn rejects_dotdot_id_and_abs_filename() {
        let d = tmp();
        assert!(safe_store_path(&d, "../../evil", "png").is_err());
        assert!(safe_store_path(&d, "/abs", "png").is_err());
        assert!(safe_store_path(&d, "a/b", "png").is_err());
        // Windows separator
        assert!(safe_store_path(&d, "..\\evil", "png").is_err());
    }

    #[test]
    fn rejects_symlink_at_target() {
        let d = tmp();
        let id = uuid::Uuid::new_v4().to_string();
        let target = d.join(format!("{id}.png"));
        let outside = d.join("outside.txt");
        std::fs::write(&outside, b"x").unwrap();
        symlink(&outside, &target).unwrap();
        assert!(safe_store_path(&d, &id, "png").is_err());
        let _ = std::fs::remove_file(&target);
    }

    #[test]
    fn valid_uuid_passes_and_stays_inside() {
        let d = tmp();
        let id = uuid::Uuid::new_v4().to_string();
        let p = safe_store_path(&d, &id, "png").unwrap();
        assert!(p.starts_with(&d));
        assert_eq!(p.extension().unwrap(), "png");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clustercut traversal_tests --lib 2>&1 | tail -20`
Expected: FAIL with `cannot find function safe_store_path` (helper does not exist yet).

- [ ] **Step 3: Add `safe_store_path` helper at top of handlers.rs (after imports)**

```rust
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
```

- [ ] **Step 4: Fix blob sink `stage_received_clipboard_blob` (`handlers.rs:27-35`)**

Replace:
```rust
let ext = crate::clipboard::common::extension_for_clipboard_mime(mime_type);
let path = cache_dir.join(format!("{}.{}", id, ext));
std::fs::write(&path, bytes).ok()?;
```
With:
```rust
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
            return None;
        }
    }
    Err(e) => {
        tracing::warn!("Blob stage create_new failed {:?}: {}", path, e);
        return None;
    }
}
```

- [ ] **Step 5: Fix file sink (`handlers.rs:389-416`) — delete collision loop, use UUID path + create_new**

Replace the block from `// Handle name collision` through `File::create(&file_path).await` with:
```rust
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

let file = match tokio::fs::OpenOptions::new()
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
```
Then replace every later use of `header.file_name` for filesystem purposes with `file_path`; keep `display_name`/`header.file_name` only in `file-progress` / `file-received` emits and notification body. Delete the `while file_path.exists()` `(n)` loop entirely (UUID removes need).

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p clustercut traversal_tests --lib 2>&1 | tail -10`
Expected: PASS (4 tests or 3 tests, 0 failures).

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/handlers.rs
git commit -m "fix: A1 traversal-safe store path for blob and file sinks"
```

---

### Task 2: A2 Integrity digest (SHA-256 plaintext, wire 0.4.0)

**Files:**
- Modify: `src-tauri/src/protocol.rs:242-256` (`FileStreamHeader` — add sha256 field + test)
- Modify: `src-tauri/src/discovery.rs:27` (bump `CLUSTERCUT_PROTOCOL_VERSION` to `"0.4.0"`)
- Modify: `src-tauri/src/handlers.rs:430-534` (receiver: hash post-decompression bytes, compare on EOF, mismatch → delete partial + emit `file-corrupt`)
- Modify: sender send path in `src-tauri/src/clipboard/common.rs` (hash while reading file/blob bytes, fill header; find `FileStreamHeader {` construction via grep — exactly one site)
- Test: `src-tauri/src/protocol.rs` tests module (old-reader-parses-new-header + legacy-missing-sha256)

**Interfaces:**
- Consumes: Task 1 `safe_store_path` (receiver writes to validated path before hashing completes; on mismatch deletes the file at that path).
- Produces: `FileStreamHeader.sha256: Option<[u8;32]>` with `#[serde(default)]`; `integrity=legacy` string flag in `file-received` emit JSON when `sha256 == None`; new `file-corrupt` emit JSON `{id, file_index, expected, actual}`. Later phases (B1/C4) key off `integrity` flag; keep the exact key name `integrity`.

- [ ] **Step 1: Write failing protocol tests (append to `protocol.rs` tests module)**

```rust
#[test]
fn file_stream_header_new_sha256_defaults_to_none_for_legacy() {
    // Old 0.3.4 sender omits sha256 entirely — must parse as None.
    let old = r#"{"id":"a","file_index":0,"file_name":"x.bin","file_size":10}"#;
    let h: FileStreamHeader = serde_json::from_str(old).unwrap();
    assert!(h.sha256.is_none());
}

#[test]
fn file_stream_header_new_reader_parses_new_header_with_digest() {
    let mut h = FileStreamHeader {
        id: "a".into(),
        file_index: 0,
        file_name: "x.bin".into(),
        file_size: 3,
        compressed: false,
        delivery_target: DeliveryTarget::Disk,
        sha256: Some([7u8; 32]),
    };
    let s = serde_json::to_string(&h).unwrap();
    let back: FileStreamHeader = serde_json::from_str(&s).unwrap();
    assert_eq!(back.sha256, Some([7u8; 32]));
    // Old-reader simulation: strip sha256 key, must still parse.
    let stripped = s.replace(r#","sha256":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7]"#, "");
    let legacy: FileStreamHeader = serde_json::from_str(&stripped).unwrap();
    assert!(legacy.sha256.is_none());
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p clustercut protocol::tests::file_stream_header_new --lib 2>&1 | tail -10`
Expected: FAIL (`no field sha256` / struct has no field).

- [ ] **Step 3: Add digest field + bump version**

In `protocol.rs`:
```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileStreamHeader {
    pub id: String,
    pub file_index: usize,
    pub file_name: String,
    pub file_size: u64,
    /// SHA-256 of *plaintext* (post-decompression). Option+default = wire-compat:
    /// old 0.3.4 readers ignore it, old senders parse as None.
    #[serde(default)]
    pub sha256: Option<[u8; 32]>,
    #[serde(default)]
    pub compressed: bool,
    #[serde(default = "default_delivery_target")]
    pub delivery_target: DeliveryTarget,
}
```
In `discovery.rs:27`:
```rust
pub const CLUSTERCUT_PROTOCOL_VERSION: &str = "0.4.0";
```
Leave `net_util.rs:30-38` floor untouched (`>=0.3.3`).

- [ ] **Step 4: Sender — fill digest (in `clipboard/common.rs` where `FileStreamHeader` is built)**

```rust
use sha2::{Digest, Sha256};
// while reading file bytes (before optional zstd compress):
let mut hasher = Sha256::new();
// feed each plaintext chunk: hasher.update(&chunk);
let digest: [u8; 32] = hasher.finalize().into();
// ... FileStreamHeader { ..., sha256: Some(digest), ... }
```
If the send path streams from disk, hash the plaintext chunks as they are read (same loop that feeds the compressor/writer). Blob `DeliveryTarget::Clipboard` path uses the identical header — same one-line fill.

- [ ] **Step 5: Receiver — verify in `handlers.rs` file-stream handler (both compressed + raw arms)**

Add before the read loop:
```rust
use sha2::{Digest, Sha256};
let mut hasher = Sha256::new();
```
Inside each `Ok(n)` arm after `file.write_all(&buf[0..n]).await` succeeds, add:
```rust
hasher.update(&buf[0..n]);
```
After the loop, before `file-received` emit:
```rust
if let Some(expected) = header.sha256 {
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != expected {
        tracing::warn!("Digest mismatch id={} idx={}", header.id, header.file_index);
        drop(file);
        let _ = tokio::fs::remove_file(&file_path).await;
        let _ = app.emit("file-corrupt", serde_json::json!({
            "id": header.id,
            "file_index": header.file_index,
            "integrity": "mismatch",
        }));
        return;
    }
    let _ = app.emit("file-received", serde_json::json!({
        "id": header.id, "file_name": header.file_name,
        "file_size": header.file_size, "file_index": header.file_index,
        "path": file_path.to_string_lossy(), "integrity": "verified",
    }));
    // ... rest of success path (size check, clipboard set, notification)
    return;
}
// Legacy sender: size-only check + flag.
let _ = app.emit("file-received", serde_json::json!({
    "id": header.id, "file_name": header.file_name,
    "file_size": header.file_size, "file_index": header.file_index,
    "path": file_path.to_string_lossy(), "integrity": "legacy",
}));
```
Keep the existing `total_written == header.file_size` size check as well (truncation fails even for legacy). On 1-byte flip with digest present: delete partial, emit `file-corrupt`, never call `set_clipboard_paths`.

- [ ] **Step 6: Run tests**

Run: `cargo test -p clustercut --lib protocol:: 2>&1 | tail -5`
Expected: PASS. Then: `cargo test -p clustercut --lib 2>&1 | tail -5`
Expected: PASS (no regressions).

- [ ] **Step 7: Commit**

```bash
git add src-tauri/src/protocol.rs src-tauri/src/discovery.rs src-tauri/src/handlers.rs src-tauri/src/clipboard/common.rs
git commit -m "feat: A2 sha256 plaintext digest on FileStreamHeader, wire 0.4.0"
```

---

### Task 3: A3 Log + memory hygiene

**Files:**
- Modify: `src-tauri/src/handlers.rs:589` (delete payload-content log line)
- Modify: `src-tauri/Cargo.toml` (add `zeroize = "1"`)
- Modify: `src-tauri/src/state.rs:60,197` (`network_pin: Arc<Mutex<String>>` → `Arc<Mutex<zeroize::Zeroizing<String>>>`)
- Modify: `src-tauri/src/app.rs:73-83` (log dir `std::env::temp_dir().join("ClusterCutLogs")` → `app_log_dir()` with 0700/0600; keep `pairing_debug_logs` gating)
- Modify: `src-tauri/src/pairing/mod.rs:628,783`, `src-tauri/src/commands/identity.rs:17-18,89-107`, `src-tauri/src/lib.rs:777,794`, `src-tauri/src/storage.rs:369-466` (adjust to `Zeroizing` deref; `clear()` on eviction/factory-reset; `remove_file` best-effort 1-pass zero overwrite)

**Interfaces:**
- Consumes: none from Task 1/2 (orthogonal).
- Produces: `network_pin` type is `Arc<Mutex<Zeroizing<String>>>` — all readers must `lock().unwrap().clone()` into a `Zeroizing<String>` (deref to `&str` where a `&str` is needed); `clear()` semantics on eviction. No other task depends on log-dir path except tests asserting 0700.

- [ ] **Step 1: Write failing hygiene checks**

Shell (not cargo — documents the lint):
```bash
rg "Decrypted Clipboard from.*text" src-tauri/src/handlers.rs && echo "LINT-FAIL-payload-log-present" || echo "LINT-OK"
grep -q 'zeroize' src-tauri/Cargo.toml && echo "DEP-OK" || echo "DEP-FAIL-zeroize-missing"
```
Expected before fix: `LINT-FAIL-payload-log-present`, `DEP-FAIL-zeroize-missing`.

- [ ] **Step 2: Delete payload log + add dep**

Delete `handlers.rs:589`:
```rust
tracing::debug!("Decrypted Clipboard from {}: {}...", sender, if text.len() > 20 { &text[0..20] } else { &text });
```
Replace with:
```rust
tracing::debug!("Received clipboard {} bytes from {}", text.len(), sender);
```
In `Cargo.toml` under `[dependencies]` add:
```toml
zeroize = "1"
```

- [ ] **Step 3: Wrap PIN + key material**

In `state.rs`:
```rust
pub network_pin: std::sync::Arc<std::sync::Mutex<zeroize::Zeroizing<String>>>,
// init:
network_pin: std::sync::Arc::new(std::sync::Mutex::new(zeroize::Zeroizing::new(String::new()))),
```
At every assignment site (`pairing/mod.rs:628`, `commands/identity.rs:89`, `lib.rs:777`, `app.rs:747`): wrap assigned value with `zeroize::Zeroizing::new(pin)`. At read sites needing `&str`, deref (`&*guard` or `guard.as_str()`). On eviction/factory-reset (`perform_factory_reset`, kick path): call `guard.zeroize()` / `clear()` before dropping. In `storage::remove_file`-adjacent secret delete helper: best-effort 1-pass zero overwrite of file bytes before `remove_file`, ignore errors, with comment documenting non-guarantee on SSD/CoW:
```rust
// ponytail: 1-pass zeros only; SSD wear-levelling/CoW may retain copies — no guarantee.
```

- [ ] **Step 4: Move log dir out of temp_dir with restricted perms**

In `app.rs` (around lines 73-83), replace:
```rust
let log_dir = std::env::temp_dir().join("ClusterCutLogs");
```
with (inside `setup`, where `app: &tauri::App` is available):
```rust
let log_dir = app.path().app_log_dir().unwrap_or_else(|_| std::env::temp_dir().join("ClusterCutLogs"));
std::fs::create_dir_all(&log_dir).ok();
crate::storage::set_dir_owner_only(&log_dir);
```
`set_dir_owner_only`/`set_owner_only` are made `pub(crate)` in Task 4 (Unix chmod 0700/0600; Windows DACL). If Task 3 executes before Task 4, inline the 5-line Unix `set_permissions` chmod instead of importing (same semantics, no cycle). Keep file appends at `0600` by calling `set_owner_only(&log_file)` after creating/rotating each log file. Keep `pairing_debug_logs == false` default silencing verbose pairing output. Also add CI lint (`.github/workflows/ci.yml` or `Justfile`): `rg "Decrypted Clipboard from.*text" src-tauri/src && exit 1 || exit 0`.

- [ ] **Step 5: Verify**

Run: `rg "Decrypted Clipboard from.*text" src-tauri/src && echo FAIL || echo LINT-OK`
Expected: `LINT-OK`.
Run: `cargo test -p clustercut --lib 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src-tauri/src/handlers.rs src-tauri/Cargo.toml src-tauri/src/state.rs src-tauri/src/app.rs src-tauri/src/pairing/mod.rs src-tauri/src/commands/identity.rs src-tauri/src/lib.rs src-tauri/src/storage.rs
git commit -m "fix: A3 redact payload logs, zeroize PIN, restrict log dir"
```

---

### Task 4: A4 Permission hotfix (ships with A1)

**Files:**
- Modify: `src-tauri/src/storage.rs:13-25` (`set_owner_only` + new `set_dir_owner_only`; apply to every AppConfig write)
- Test: extend `src-tauri/src/storage.rs` `perms_tests` module (dir 0700 + file 0600 assertions)

**Interfaces:**
- Consumes: none (orthogonal to Tasks 1–3).
- Produces: every file under AppConfig (`device_cert.der`, `known_peers.json`, `settings.json`, `device_id`, `cluster_id`, `network_name*`, `temp_downloads/*`) is `0600`, every parent dir created by the app is `0700`. Windows: explicit OWNER+SYSTEM-only DACL via `windows` ACL API (replace no-op).

- [ ] **Step 1: Write failing perms tests**

```rust
#[test]
fn app_config_files_and_dirs_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let base = std::env::temp_dir().join(format!("cc_perms_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    super::set_dir_owner_only(&base);
    super::set_owner_only(&base.join("settings.json"));
    std::fs::write(base.join("settings.json"), b"{}").unwrap();
    super::set_owner_only(&base.join("settings.json"));
    let dm = std::fs::metadata(&base).unwrap().permissions().mode();
    let fm = std::fs::metadata(base.join("settings.json")).unwrap().permissions().mode();
    let _ = std::fs::remove_dir_all(&base);
    assert_eq!(dm & 0o777, 0o700, "dir {:o}", dm & 0o777);
    assert_eq!(fm & 0o777, 0o600, "file {:o}", fm & 0o777);
}
```
Run: `cargo test -p clustercut perms_tests --lib 2>&1 | tail -10` → FAIL (`set_dir_owner_only` missing).

- [ ] **Step 2: Implement `set_dir_owner_only` + extend coverage**

```rust
fn set_dir_owner_only(path: &std::path::Path) {
    let _ = std::fs::create_dir_all(path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
            tracing::warn!("Failed to set 0700 on {}: {}", path.display(), e);
        }
    }
    #[cfg(windows)]
    {
        restrict_dacl_owner_system_only(path);
    }
}

/// Windows-only: replace inherited ACL with owner+SYSTEM full-access only.
/// Uses the existing `windows` crate dep (Cargo.toml:76). Best-effort, logs and returns on any error.
/// Exact sequence: wide-path → `CreateWellKnownSid(WinLocalSystemSid)` for SYSTEM,
/// `GetNamedSecurityInfoW(path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION)` for owner SID,
/// two `EXPLICIT_ACCESS_W { grfAccessMode: SET_ACCESS, grfAccessPermissions: 0x1F01FF (GENERIC_ALL),
/// grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT, Trustee: { TrusteeForm: TRUSTEE_IS_SID, ... } }`,
/// `SetEntriesInAclW` → new ACL, `SetNamedSecurityInfoW(path, SE_FILE_OBJECT,
/// DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, None, None, Some(acl), None)`.
#[cfg(windows)]
fn restrict_dacl_owner_system_only(path: &std::path::Path) {
    // Implement exactly the sequence above; on any Err log with
    // tracing::warn!("DACL harden failed {}: ...", path.display()) and return.
    // Must compile under `cfg(windows)` with the `windows` crate features already in Cargo.toml:76
    // (add "Security" + "Security_Authorization" style features if the exact module path needs them).
}
```
Add matching Windows `restrict_dacl_owner_system_only(path)` using the already-present `windows` crate (target `cfg(windows)` dep at `Cargo.toml:76`), and call `set_owner_only` after every `fs::write` / `fs::create_dir_all` for: `device_cert.der`, `known_peers.json`, `settings.json`, `device_id`, `cluster_id`, `network_name*`, and `temp_downloads/*` creation in `handlers.rs`/`common.rs` (import from `storage` or duplicate the 5-line Unix chmod if import would create a cycle — prefer `crate::storage::set_owner_only` made `pub(crate)`).

- [ ] **Step 3: Apply to all writes**

In `storage.rs`, after each `fs::create_dir_all(parent)` for AppConfig files add `set_dir_owner_only(parent)`; after each `fs::write(path, …)` add `set_owner_only(&path)`. Covered names: `save_network_name`, version/origin/mode saves, `save_network_pin`, `harden_secret_files` loop over `["device_key.der", "network_pin"]`, `save_settings`, peer-db save, id/cluster-id saves. Make both helpers `pub(crate)` so `handlers.rs:32,384` and `clipboard/common.rs:590` cache-dir creations can call `set_dir_owner_only`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p clustercut perms_tests settings_tests --lib 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/storage.rs src-tauri/src/handlers.rs src-tauri/src/clipboard/common.rs
git commit -m "fix: A4 owner-only perms on all AppConfig writes + 0700 dirs"
```

---

## Verification (Phase A acceptance)

- `cargo test -p clustercut --lib` green (traversal vectors both sinks + symlink race, digest mismatch/truncation, legacy-proto fallback, old-reader-parses-new-header).
- `rg "Decrypted Clipboard from.*text" src-tauri/src` empty.
- Manual: copy/paste text+image <1s LAN, file approve flow unchanged, history recall works, cold-read of AppConfig files shows 0600/0700 on Unix.
- No `content_hash`-as-integrity anywhere: `rg "content_hash" src-tauri/src` shows only dedup/broadcast sites, no compare-on-receive.
