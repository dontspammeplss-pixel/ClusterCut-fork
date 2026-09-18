# Security H-Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate remote-wipe, spoof, gossip-enroll, and unbounded-stream compromise paths by paired peers.

**Architecture:** Plumb the presenting mTLS fingerprint from `transport.rs` into `handle_message` once, then gate all identity-sensitive branches on it; bound the file stream with header/size/decompression/timeout caps mirroring the existing blob-path pattern.

**Tech Stack:** Rust (Tauri 2, Quinn QUIC, rustls custom verifier, tokio, zstd), existing `cargo test` suite.

**Spec:** `docs/SECURITY-AUDIT-REPORT.md` (rev 2026-09-18; revised audit: H-1..H-4 CONFIRMED, M-1 PARTIAL, M-2 CONFIRMED in-mem, M-3/M-5 CONFIRMED, L-1 PARTIAL, L-2 mostly CONFIRMED with firewall/openUrl STALE). This plan covers H only; M/L queued next; shell removal deferred per scope decision.

## Global Constraints

- No new external deps; stdlib + tokio/quinn/rustls already in tree only.
- `file_name` stays display-only; both sinks keep `create_new` + `safe_store_path` (`src-tauri/src/handlers.rs:14-28`).
- Pairing TCP cap=1 + 10-failure lockout untouched (`src-tauri/src/state.rs:227-252`, `src-tauri/src/app.rs:1128-1146`).
- One fix at a time, minimal runnable check per fix, atomic commit per task.

---

### Task 1: H-1 — Gate self-wipe on cert-bound identity + approval

**Files:**
- Modify: `src-tauri/src/handlers.rs:689` (`handle_message` signature), `:1331-1341` (PeerRemoval self branch)
- Modify: `src-tauri/src/transport.rs:290-294` (`on_receive_message` callback args)
- Modify: `src-tauri/src/app.rs:1186-1191` (dispatch sites pass fingerprint)
- Test: `src-tauri/src/handlers.rs` existing `#[cfg(test)]` module (add `peer_removal_self_requires_sender_match`)

**Interfaces:**
- Consumes: `transport_inside.local_fingerprint()` / peer cert fingerprint `String` already available in verifier (`transport.rs:481-518`).
- Produces: `handle_message(msg: Message, addr: SocketAddr, sender_fingerprint: Option<String>, ...)` — Tasks 2-3 consume `sender_fingerprint`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn peer_removal_self_requires_sender_match() {
    // Remote PeerRemoval targeting local id from a NON-matching fingerprint must NOT reset.
    // Assert: perform_factory_reset not called; emits "peer-remove-approval-request" instead.
    // Skeleton: call handle_message(Message::PeerRemoval(local_id), addr, Some("other-fp"), ...)
    // and assert known_peers/local state unchanged.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clustercut peer_removal_self_requires_sender_match -- --nocapture`
Expected: FAIL (self-wipe still unconditional at `handlers.rs:1335-1341`)

- [ ] **Step 3: Write minimal implementation**

```rust
// handlers.rs:1331…
Message::PeerRemoval(target_id) => {
    let local_id = listener_state.local_device_id.lock().unwrap().clone();
    if target_id == local_id {
        // Root fix: remote peers can no longer trigger factory reset.
        // Only the local leave_network path (commands/peers.rs:224) calls perform_factory_reset.
        // Remote self-target → emit approval event for explicit user action.
        let _ = listener_handle.emit("peer-remove-approval-request", &sender_fingerprint);
        tracing::warn!("Ignoring remote self-removal from {:?}", sender_fingerprint);
        return;
    }
    // …existing tombstone path unchanged…
}
```

Plumbing (same task, no separate commit):

```rust
// transport.rs:293 — pass fingerprint through:
on_receive_message(buf, remote_addr, peer_fingerprint)
// app.rs:1186 — forward it into handle_message(msg, addr, peer_fingerprint, …)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clustercut peer_removal_self_requires_sender_match -- --nocapture`
Expected: PASS; then `cargo test -p clustercut` — no regressions.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/handlers.rs src-tauri/src/transport.rs src-tauri/src/app.rs
git commit -m "fix(security): gate PeerRemoval self-wipe on cert identity + approval"
```

### Task 2: H-2 — Bind sender_id to presenting cert

**Files:**
- Modify: `src-tauri/src/handlers.rs:696-774` (Clipboard branch), `:716-722` (self check), `:1163-1178` (relay)
- Test: `src-tauri/src/handlers.rs` `#[cfg(test)]` (add `clipboard_rejects_sender_mismatch`)

**Interfaces:**
- Consumes: `sender_fingerprint: Option<String>` from Task 1.
- Produces: `fn resolve_sender_device_id(sender_fingerprint: &str, known_peers) -> Option<String>` used by clipboard + FileRequest (`handlers.rs:1376-1378` same-task hardening).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn clipboard_rejects_sender_mismatch() {
    // payload.sender_id = "victim-id" but sender_fingerprint maps to "attacker-id"
    // Assert: handler drops payload (no clipboard write, no relay emit).
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clustercut clipboard_rejects_sender_mismatch -- --nocapture`
Expected: FAIL (payload trusted blindly at `handlers.rs:696,773`)

- [ ] **Step 3: Write minimal implementation**

```rust
// Replace hostname self-check (handlers.rs:716-722) with device-id check:
let claimed = payload.sender_id.clone();
let actual = resolve_sender_device_id(&sender_fp, &listener_state); // known_peers fingerprint lookup
if actual.as_deref() != Some(claimed.as_str()) {
    tracing::warn!("Dropping clipboard with sender mismatch");
    return;
}
if claimed == *listener_state.local_device_id.lock().unwrap() { return; } // device-id, not hostname
// Relay (1163-1178): re-serialize with verified `actual`, never attacker `sender/sender_id`.
```

Apply identical check to `Message::FileRequest` sender at `handlers.rs:1376-1378` in the same diff.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clustercut clipboard_rejects_sender_mismatch -- --nocapture`
Expected: PASS; then full `cargo test -p clustercut`.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/handlers.rs
git commit -m "fix(security): bind clipboard/file sender_id to mTLS fingerprint"
```

### Task 3: H-3 — Drop gossip auto-trust

**Files:**
- Modify: `src-tauri/src/handlers.rs:1251-1283` (`PeerDiscovery` trust + persist `:1274-1276`)
- Modify: `src-tauri/src/presence.rs:187-220` (`merge_cluster_membership`, `:214`)
- Test: `src-tauri/src/presence.rs` tests (add `gossip_import_is_untrusted`)

**Interfaces:**
- Consumes: nothing new (uses existing `is_manual`, tombstone set).
- Produces: gossip imports always `is_trusted=false` until explicit user trust action.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn gossip_import_is_untrusted() {
    // merge_cluster_membership with fresh fingerprinted entry from trusted sender
    // Assert: imported peer has is_trusted == false and is NOT persisted/dialed.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p clustercut gossip_import_is_untrusted -- --nocapture`
Expected: FAIL (`is_trusted=true` unconditional at `handlers.rs:1255`, `presence.rs:214`)

- [ ] **Step 3: Write minimal implementation**

```rust
// handlers.rs:1251… PeerDiscovery branch:
peer.is_trusted = false; // never auto-trust gossip; explicit trust action required
// persist gate (1274-1276): only if peer.is_manual (drop `|| peer.is_trusted`):
if peer.is_manual { storage::save_known_peers(handle, &kp); }
// presence.rs:214: same — p.is_trusted = false for merged entries.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p clustercut gossip_import_is_untrusted -- --nocapture`
Expected: PASS; then `cargo test -p clustercut`.

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/handlers.rs src-tauri/src/presence.rs
git commit -m "fix(security): gossip imports never auto-trusted"
```

### Task 4: H-4 — Bound file stream (header + size + decomp + timeout)

**Files:**
- Modify: `src-tauri/src/handlers.rs:441-687` (header `:448`, size `:470-516`, loops `:544-608`, verify `:637-686`), `:213-216` (blob discard budget)
- Modify: `src-tauri/src/protocol.rs:246,254` (document caps next to `file_size`/`compressed`)
- Test: `src-tauri/src/handlers.rs` `#[cfg(test)]` (add `file_stream_rejects_oversize_header` + `file_stream_aborts_over_cap`)

**Interfaces:**
- Consumes: `AppSettings` for override (default cap constant).
- Produces: `const MAX_FILE_STREAM_HEADER: usize = 8192; const MAX_FILE_STREAM_BYTES: u64 = 2_147_483_648; const MAX_DECOMP_BUDGET: u64 = 2_147_483_648; const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(30);`

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn file_stream_rejects_oversize_header() {
    // Feed >8KB header without newline → assert handler returns before File::create.
}
#[test]
fn file_stream_aborts_over_cap() {
    // header.file_size = u64::MAX with small cap → assert abort, partial file removed.
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p clustercut file_stream_ -- --nocapture`
Expected: FAIL (unbounded `read_line` at `:448`, no `file_size` check before create)

- [ ] **Step 3: Write minimal implementation**

```rust
const MAX_FILE_STREAM_HEADER: usize = 8 * 1024;
const MAX_FILE_STREAM_BYTES: u64 = 2 * 1024 * 1024 * 1024; // settings-overrideable follow-up (M-track)
const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(30);

// Header: cap line length
let mut limited = reader.take((MAX_FILE_STREAM_HEADER + 1) as u64);
let n = tokio::time::timeout(STREAM_READ_TIMEOUT, limited.read_line(&mut header_line)).await??;
if header_line.len() > MAX_FILE_STREAM_HEADER { return; }

// Pre-check before File::create (handlers.rs:470…):
if header.file_size > MAX_FILE_STREAM_BYTES { tracing::warn!("reject oversize"); return; }
// Loops (544-608): wrap each read in timeout; track total_written (+decompressed for zstd);
// abort + remove partial file when total exceeds min(header.file_size, MAX_FILE_STREAM_BYTES).
// Blob discard (213-216): same timeout + byte budget, then break.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p clustercut file_stream_ -- --nocapture`
Expected: PASS; then `cargo test -p clustercut` + `just hygiene` (log redaction still clean).

- [ ] **Step 5: Commit**

```bash
git add src-tauri/src/handlers.rs src-tauri/src/protocol.rs
git commit -m "fix(security): cap file-stream header, size, decompression, timeout"
```

---

## Queued next (M/L — not in this plan)

- M-1: propagate error instead of `"000000"` fallback (`storage.rs:533-538`).
- M-2: log failure count/hash, never PIN bytes (`pairing/mod.rs:918-929`).
- M-3: prefix ≥/24 + address-count cap (`commands/peers.rs:141`).
- M-5: inbound stream concurrency cap + per-IP rate + read timeouts (`transport.rs:251,278`, `app.rs:1186,1198`).
- M-4: honest Clear/Delete + secrets-sync disclosure.
- L-1: unverified-advertiser label + display sanitize.
- L-2: pin `user-notify` rev=`9ea5de5`, remove `tauri-plugin-shell` (`app.rs:563`), scope `opener:default`. Shell removal verified safe: zero `shell::Command` uses, no shell perms, no frontend `plugin-shell` import; `opener` stays for `openUrl`.
