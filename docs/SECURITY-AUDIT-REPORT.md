# ClusterCut — Independent Security Audit Report

**Target:** ClusterCut v0.4.3 (Tauri 2 + Rust backend, React frontend)
**Scope:** Fully local + Tailscale-enabled clipboard and filesync application
**Date (UTC):** 2026-09-18
**Auditor role:** Independent, adversarial. No trust in code comments, docs, or specs. All claims verified against source.
**Repository:** `/ClusterCut-main` (commit `2f76e14` at time of audit)
**Method:** Manual source review of `src-tauri/src/**`, `src/**`, `src-tauri/capabilities/`, `src-tauri/tauri.conf.json`, `Cargo.toml`, `package.json`, `scripts/*`, `Justfile`, `vite.config.ts`, `gnome-extension/*`; adversarial greps for backdoor/C2/exfil/RCE indicators; three parallel deep-dives (crypto/pairing, transport/discovery, persistence/supply-chain) with independent spot-verification.

---

## Executive Summary

**No backdoor, no command-and-control, no telemetry, no remote code execution found.**

- No `skip_verify` / `accept_all` / `insecure` flags. The single `dangerous()` is the standard rustls custom-verifier hook, and both verifiers still enforce SHA-256 cert pinning **plus** WebPKI handshake-signature verification (`src-tauri/src/transport.rs:458-479,529-550`).
- No hardcoded keys, master keys, or weak default credentials in the reachable auth path, with one exception noted below (`storage.rs:537`).
- No external network calls. No updater plugin, no update check, no telemetry SDK. Only external URL in config is `schema.tauri.app` (`tauri.conf.json:2`). All traffic is mDNS + QUIC/mTLS to LAN or manually-added peers. Pairing TCP is deliberately plaintext but runs SPAKE2-PAKE and leaks nothing.
- `build.rs` is `tauri_build::build()` only. No `postinstall`/`preinstall` hooks. npm deps are mainstream (`@tauri-apps/*`, react, tailwind). CSP is tight (`tauri.conf.json:27`). Tauri capability set is minimal (`capabilities/default.json:8-21`).
- The cryptographic core is sound: SPAKE2 pairing with direction-separated ChaCha20-Poly1305 confirmation frames, then QUIC + TLS 1.3 mutual cert-pinning for steady state, with brute-force lockout, single-flight pairing, and owner-only secret file permissions.

**The real exposure is insider/lateral, not outsider.** Once a device is paired (or its `device_key.der` is stolen), there is no least-privilege: any paired peer can spoof senders, delete history, enroll phantom peers via gossip, fill the victim's disk via the file stream, and — most severely — remotely wipe any member via `PeerRemoval`. Clipboard/file content is plaintext at rest and auto-syncs by default, so copied secrets fan out to every paired peer.

---

## Scope and Attack Surface

| Surface | What was reviewed |
|---|---|
| Pairing / key exchange | `pairing/mod.rs`, `pairing/crypto.rs`, `protocol.rs:367-396`, `state.rs`, `storage.rs` |
| Steady-state transport | `transport.rs`, `protocol.rs`, `handlers.rs`, `compression.rs` |
| Discovery / presence | `discovery.rs`, `presence.rs`, `peer.rs`, `net_util.rs`, `netmon.rs` |
| Clipboard backends | `clipboard/*.rs` (watcher, wayland, dbus_clipboard, rich, preview, history_store, common, plugin) |
| IPC / frontend | `commands/*.rs`, `lib.rs`, `app.rs`, `src/App.tsx`, `src/types.ts`, `src/components/**`, `src/lib/protocol.ts` |
| OS integration | `dbus.rs`, `tray.rs`, `shortcuts.rs`, `diagnostics.rs`, `gnome-extension/*` |
| Config / supply chain | `tauri.conf.json`, `capabilities/default.json`, `Cargo.toml`, `Cargo.lock`, `package.json`, `scripts/*`, `Justfile`, `vite.config.ts` |

Listeners (verified):

- QUIC/UDP on `0.0.0.0:4654` (`transport.rs:46`, bound in `app.rs:648`, random-port fallback `app.rs:651-652`).
- Plaintext-TCP pairing on `0.0.0.0:<same-port>` (`transport.rs:703-704`, started `app.rs:1116`).
- mDNS advertisement of the bound port (`discovery.rs:100-107`).
- D-Bus session service `app.clustercut.clustercut` at `/org/gnome/Shell/Extensions/ClusterCut` (`dbus.rs:117-123`), session-local only.
- No HTTP server, no localhost TCP listener. No CORS surface (`Cargo.toml` has no axum/actix/warp).

---

## Findings

Severity scale: **Critical** (immediate compromise/wipe) · **High** (csrf-equivalent data loss/DoS by paired peer) · **Medium** (meaningful hardening gap) · **Low** (defense-in-depth / hygiene).

### H-1 — Any paired peer can remotely wipe any member via `PeerRemoval` [High]

- `handle_message` → `PeerRemoval(target)` deletes + tombstones any entry (`handlers.rs:1343-1363`).
- When `target` equals the victim's own ID, the victim runs `perform_factory_reset()` (`handlers.rs:1335-1341`).
- There is no check binding the affected identity to the presenting mTLS cert. Any single paired (or compromised) peer can force any member — including one it has never directly approved — down the factory-reset path.
- **Fix:** require the mTLS fingerprint to match the affected identity for self-targeted removal at minimum; ideally require explicit user approval for all membership removals, or restrict removal authority to the device itself.

### H-2 — No sender↔cert binding; clipboard spoofing / pastejacking by any paired peer [High]

- `Message::Clipboard` handler checks only: ±120 s timestamp (`handlers.rs:698-713`), `sender` hostname ≠ own hostname (`handlers.rs:716-722` — hostname, not device ID, spoofable), single-slot dedup (`handlers.rs:731-738`), `auto_receive` gate.
- `payload.sender_id` / `sender` (`protocol.rs:187-203`) are unauthenticated string claims consumed at `handlers.rs:692-774` with no verification against the mTLS peer's fingerprint.
- Any paired peer overwrites the OS clipboard when `auto_receive` is on (text `handlers.rs:1145`, image `handlers.rs:994`, blob `handlers.rs:365,424`, rich HTML/RTF `handlers.rs:1084`).
- Relay (`handlers.rs:1163-1178`) rebroadcasts gated only on `auto_send`; single-slot dedup is bypassed with distinct payloads → cluster-wide relay storm from one malicious peer.
- **Fix:** bind `sender_id` to the presenting cert fingerprint; compare device ID (not hostname) for self-detection; consider per-peer send authorization or content confirmation for HTML/RTF.

### H-3 — Transitive gossip trust lets one paired peer enroll arbitrary devices [High]

- Inbound `PeerDiscovery` over an authenticated connection sets `peer.is_trusted = true` unconditionally and persists it (`handlers.rs:1251-1283`, persisted `handlers.rs:1274-1276`).
- Same pattern in `presence.rs:214` and `merge_cluster_membership` (`presence.rs:187-220`). Merge skips self / `manual-` / tombstoned / unfingerprinted (`presence.rs:196-209`), but the fingerprint for an "imported" peer is bytes the already-trusted sender claimed.
- Sender IP/port are correctly overwritten from the socket (`handlers.rs:1215-1216`) and fingerprint stickiness preserved (`handlers.rs:1225-1227`) — but neither stops a trusted sender from minting fresh IDs with fresh certs.
- **Fix:** never auto-trust gossip imports; require per-device user approval (or at minimum TOFU display + explicit trust action) before persisting or dialing.

### H-4 — Unbounded inbound file stream: disk-fill and decompression bomb [High]

- Control stream is capped (`read_to_end(64 MB)`, `transport.rs:289-290`); clipboard-blob streams are MIME-capped (text 100 MB, image 500 MB, `clipboard/common.rs:31,42`, enforced in `drain!`, `handlers.rs:199-241`).
- File stream (`handlers.rs:441-687`) is the gap:
  - Header via unbounded `read_line` (`handlers.rs:448`) — a peer that never sends `\n` grows the buffer without bound.
  - `header.file_size: u64` (`protocol.rs:246`) never validated before `File::create` (`handlers.rs:470-516`); receive loops (`handlers.rs:544-608`) break only on EOF. No total cap, no timeout. `max_auto_download_size` only decides auto-vs-manual; the manual Download path is unbounded. No free-space check.
  - `header.compressed` is sender-chosen (`protocol.rs:254`), honored blindly; zstd output hashed/written with no expansion cap; size/digest check happens after bytes are on disk (`handlers.rs:637-686`).
  - Post-cap discard loop on the blob path (`handlers.rs:213-216`) reads to EOF with no byte budget/timeout: a malicious `compressed` stream forces unbounded decode-and-discard CPU.
- Path traversal is **not** exploitable: `safe_store_path` requires UUID store name, alnum-capped ext, refuses pre-existing/symlink paths, both sinks use `create_new` (`handlers.rs:14-28,103,505-509`); `file_name` is display-only; serve side is self-populated map lookup with index bounds check (`handlers.rs:1387-1390,1526-1533`).
- **Fix:** cap header line to a few KB; pre-check `file_size` against a max (with settings override); abort mid-stream when `total_written` exceeds it; enforce total decompressed-byte budget + per-stream read timeout on file and blob paths.

### M-1 — Hardcoded `"000000"` PIN fallback [Medium]

- `load_network_pin` returns `String::from("000000")` when the config path cannot be resolved (`storage.rs:533-538`). Reachability is low (requires broken `AppConfig`), but a hardcoded weak PIN exists in the auth path.
- **Fix:** propagate an error / refuse pairing instead of defaulting.

### M-2 — Live PIN leaked into diagnostics channel [Medium]

- Responder dumps the live PIN (`len` + raw bytes) into the in-memory diagnostics channel on every T2 AEAD failure (`pairing/mod.rs:918-929`). Never persisted to the file log by design, but exposed to anyone who can view the Debug diagnostics panel.
- **Fix:** log only the failure count / truncated hash, never PIN material.

### M-3 — CIDR scan has no prefix guard: self-inflicted OOM + network sweep [Medium]

- `add_manual_peer` materializes every address (`commands/peers.rs:141` `net.iter().collect()`): `/16` = 65k probes, `/8` = 16M, `/0` = instant OOM. Self-IP skip compares one local address (`peers.rs:154`). Probes run in 50-wide batches (`peers.rs:143-163`).
- No hostname resolution in the remote path (only `SocketAddr`/`IpAddr`/`IpNetwork` accepted; hostnames rejected at `peers.rs:114,173`) — classic SSRF-via-hostname and DNS rebinding are absent. `probe_ip` (`net_util.rs:141-266`, 2 s timeout) discloses device ID, hostname, network name, proto version, cert fingerprint (`net_util.rs:159-171`) to whatever listens, and gives a QUIC port-scan oracle — but cannot speak HTTP or read localhost TCP services.
- **Fix:** cap prefix (e.g. ≥ /24 or explicit address-count cap); skip loopback/link-local/multicast.

### M-4 — Plaintext-at-rest clipboard + auto-sync defaults; Clear/Delete do not propagate [Medium]

- `HistoryStore` is RAM (`state.rs:107-109`); staged files plaintext under `app_cache/temp_downloads/` (`clipboard/common.rs:577-614`, `handlers.rs:73-129`). No at-rest encryption, no memory zeroize (only the PIN is `Zeroizing`, `state.rs:58-60`).
- Defaults `auto_send=true, auto_receive=true` (`storage.rs:740-744`): a copied password broadcasts to every paired peer and sits in each peer's RAM + temp files until eviction (200 MB budget) or restart. No password-manager detection, no exclusion list, no per-item "don't sync". History does not survive restart; `clear_cache` wipes `temp_downloads` at boot (`app.rs:631`) — bounds the window to the session.
- File perms are good: 0600/0700 via `set_owner_only`/`set_dir_owner_only` on staged blobs, cache dir, all `AppConfig` writes, plus `umask(0o077)` (`app.rs:106-109`) and retroactive `harden_secret_files` (`app.rs:731`, `storage.rs:478-487`). Log dir owner-only with 0600 rotation (`app.rs:80-98`). Logs carry only lengths/MIMEs/hostnames (e.g. `handlers.rs:1138-1142`); content-redaction enforced by `just hygiene` (`Justfile:513-520`).
- Deception-grade gap: frontend "Clear" is `setClipboardHistory([])` only (`App.tsx:1286-1287`, no backend call — backend store and staged files survive). Backend `delete_history_item` removes local store+file (`commands/clipboard.rs:186-192`), but the peer `HistoryDelete` handler only emits a UI event (`handlers.rs:1181-1184`) — the peer keeps re-callable content.
- **Fix:** make Clear/Delete purge backend store + staged files and propagate backing removal, or relabel the buttons; document "copied secrets sync in plaintext to all paired peers" in Settings.

### M-5 — Missing stream concurrency caps, per-IP throttling, and read timeouts [Medium]

- Pairing has cap=1 (`app.rs:1136-1146`) + 10-AEAD-failure sticky lockout until manual re-arm (`state.rs:182,233-252`, enforced `app.rs:1128-1135`) + 10 s timeouts (`transport.rs:643,680-686`). Good.
- No concurrency cap on inbound bi/uni streams (`transport.rs:278-321` spawns per stream; `app.rs:1186,1198` spawns per message) — a paired peer opens streams at will (memory/CPU DoS). No per-IP throttling, no clipboard/file-request rate limiting.
- Timeouts exist on probe (2 s), heartbeat send (2 s, `app.rs:381`), anti-entropy (3 s, `presence.rs:354`), fan-out (3 s, `peers.rs:216,263`), send drain (30 s, `transport.rs:170`), QUIC idle (30 s, `transport.rs:395,583`). Missing on control-stream `read_to_end` (trickle-hold) and file/blob streams (stall short of QUIC idle).
- **Fix:** cap inbound stream concurrency + per-IP rates; add per-stream read timeouts.

### L-1 — mDNS fields treated as semi-trusted display strings [Low]

- mDNS TXT (`id`, `n`, `h`, `proto`, `version`) unauthenticated (`discovery.rs:92-98`). Resolver does the right thing for trust: `is_trusted` only if a fingerprint is already pinned (`app.rs:940-945`), runtime peer carries stored fingerprint forward (`app.rs:944-945,971-973`), join toast is mTLS ping-verified before notifying (`app.rs:1006-1024`) else deferred (`app.rs:1022`). Spoofed records alone create display-only runtime entries (`app.rs:956-984`) and cannot pass the QUIC handshake.
- Residual: `hostname`/`network_name` from TXT flow into `peer-update` events and notification bodies (`app.rs:1019`, `handlers.rs:1269`) — impersonation ("IT-Helpdesk laptop") and cluster-confusion. React escapes HTML; risk is social, not XSS.
- **Fix:** label undiscovered advertisers as unverified; sanitize/truncate display strings.

### L-2 — Unpinned git dependency; dead shell surface; minor local surfaces [Low]

- `user-notify = { git = "https://github.com/Simon-Laux/user-notify" }` (`Cargo.toml:69`) has no rev/tag pin. `Cargo.lock` pins `9ea5de5` today, but regen can track upstream tip. Pin `rev =`.
- `tauri-plugin-shell` initialized (`app.rs:563`) with zero shell permissions in `capabilities/default.json` — dead weight. Backend `Command::new` uses are fixed strings only: `osascript` with `\`/`"` escaping (`lib.rs:194-207`), `netsh`/`powershell` with constant sentinel (`net_util.rs:288-359`). No command injection. Only two hardcoded https URLs reach `openUrl` (`App.tsx:388,397`); no peer input flows into it. No `eval`/`innerHTML`/`dangerouslySetInnerHTML` in `src/`; history renders as React text nodes (`HistoryView.tsx:159,191`).
- `clustercut://action/download?msg_id&peer_id&file_count` deep-link (`App.tsx:207-225`) triggers `request_file` with no proof a notification existed — any local process/website can fire it; needs valid UUIDs and only causes outbound requests. Consider a nonce/allowlist. D-Bus session interface exposes `quit`/`toggle_*` to same-user bus clients (`dbus.rs:63-115`) — local nuisance at most; same-user attackers already own the clipboard. `log_frontend` (`commands/system.rs:56-64`) lets the WebView write arbitrary strings to the backend log — local-only log injection. Peer image bytes go through the `image` crate decoder (`clipboard/common.rs:192-235`) — standard parser surface, size-capped (500 MB); keep patched.

---

## What Was Explicitly Checked and Found Clean

- No C2/telemetry: `grep -r updater|telemetry|analytics` across configs empty; no update check; no external fetch; no hardcoded IPs/URLs in Rust (only `schema.tauri.app`).
- No RCE: no shell execution of peer/user input; no FS write from network-controlled paths; no `eval`; CSP `frame-src 'none'`, `object-src 'none'`; no remote WebView URLs (devUrl is localhost dev-only).
- No backdoor bypass: no `skip_verify`/`accept_all`; pairing kill-switch defaults on (`storage.rs:725-727,754`); `pairing_debug_logs` widens verbosity only (`pairing/mod.rs:678-689`), never alters accept/verify decisions.
- Crypto review spot-checks: SPAKE2 (`Ed25519Group`, identity `b"clustercut-connect"`, `crypto.rs:13-35`) → HKDF-SHA256 into direction-distinct `k_i2r`/`k_r2i` bound to role-labelled transcript (`crypto.rs:53-113`); fresh 96-bit nonce per frame (`crypto.rs:115-122`); T2-shape enforcement (`pairing/mod.rs:858-872`); T3-only-after-T2-verifies (no offline oracle); downgrade guards (proto floor `pairing/mod.rs:120-138`, legacy frames rejected `protocol.rs:664-686`).
- Residual downgrade note: `sha256: None` headers accepted as `Integrity::Legacy` with size-only check (`handlers.rs:648-655,269-270`).

---

## Remediation Priority

1. **Authorize destructive/authenticated messages** (H-1, H-2, H-3): bind `sender_id` to cert fingerprint; gate self-wipe and all removals; drop gossip auto-trust.
2. **Bound the file path** (H-4): header-line cap, `file_size` pre-check + mid-stream abort, decompressed budget, per-stream timeouts.
3. **Inbound concurrency + timeouts + CIDR guard** (M-3, M-5).
4. **Pairing hygiene** (M-1, M-2): remove `"000000"` fallback; stop logging PIN material.
5. **Honest data lifecycle** (M-4): real Clear/Delete semantics + secrets-sync disclosure.
6. **Supply-chain tightening** (L-2): pin `user-notify` rev; remove `tauri-plugin-shell`; scope `opener:default`.

---

## Limitations

- Static review only; no dynamic testing, fuzzing, or traffic analysis was performed.
- Linux clipboard backends (Wayland `wlr-data-control`, GNOME extension D-Bus bridging) and OS-specific permission prompts were reviewed at the code level only.
- Cryptographic primitives (SPAKE2, ChaCha20-Poly1305, HKDF-SHA256, rustls/quinn) were assumed correct as implementations; review focused on their composition, transcript binding, nonce management, and authentication gaps.

---

*End of report.*
