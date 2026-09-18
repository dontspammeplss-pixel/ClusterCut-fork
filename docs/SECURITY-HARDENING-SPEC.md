# ClusterCut Security Hardening — Engineering Specification
Version: 1.1 | Date: 2026-09-17 | Base: v0.4.3 | Wire proto: 0.3.4 → 0.4.0
Review status: independently validated 2026-09-17 — §4 snippets A1/A2 corrected, §§5/7 compat fixed. Do not build from v1.0.

## 0. Purpose
Implementation blueprint for all findings in the 2026-09-17 independent audit. Secure without breaking core UX: copy→paste sync, smart file transfer, history, manual mode, remote/VPN peers.

Out of scope: cloud relay, accounts/MFA-as-login (no login exists), E2E re-encryption inside tailnet (mTLS is the E2E layer).

## 1. Threat model (LOCKED)
- T1 LAN attacker (passive sniff + active MITM on pairing), no PIN.
- T2 Compromised-but-paired peer (malicious `file_name`, `id`, `sender`, oversized/ZSTD-bomb payloads, replay).
- T3 Local attacker (other OS user/process, stolen disk, forensic carve).
- T4 Malicious link/file content (deep-link URL, filename → notification/XML/render).
- Trust boundary: paired peer MAY read what you sync; OS clipboard and session bus are inherently sniffable (X11/session-bus literally; Wayland/macOS/Win same-user readers trivial, cross-user needs privilege). Tailscale (when enabled) is the network gate; app enforces it at socket layer.
- Non-goals: keyloggers on host, compromised OS kernel, physical RAM freeze.
- Explicit non-trust: `ClipboardBlob.content_hash` (`protocol.rs:50`) is a broadcast-dedup fingerprint only — never a security check. Do not accept it as integrity proof.

## 2. Requirements
### 2.1 Functional (must not regress)
- F1 Auto text/image sync <1s LAN, manual file approve flow unchanged.
- F2 History recall, pending-clipboard confirm, mesh relay (1 hop, allow-listed).
- F3 LAN mDNS discovery + manual CIDR add + remote/VPN peers.
- F4 Offline-first; no account, no cloud.
### 2.2 Security
- S1 No arbitrary file write from peer input (traversal/symlink).
- S2 Corruption integrity (not malicious-peer integrity): SHA-256 plaintext digest on every file/blob detects truncation, bit-flips, ZSTD-decoder mismatch before consume. It does NOT stop a compromised-but-paired peer (T2) — such a peer computes a correct digest for malicious bytes. Malicious-peer defence is consent/caps/tombstones (S7), not digests.
- S3 Encryption at rest for history, blobs, peer DB, settings secrets (keychain-bound key).
- S4 TLS 1.3 only; pairing stays SPAKE2 but with decay backoff + fingerprint confirm.
- S5 No secret bytes in logs; zeroize key/PIN material.
- S6 Tailscale enforce mode (bind + verify), default off for LAN compat.
- S7 Bounded decompression/transfer sizes; no silent mass exfiltration (per-peer + per-type consent, relay hop-limit).

## 3. Work breakdown (phases)
- Phase A (P0, ship-blocker): A1 traversal, A2 integrity digest, A3 log redaction + zeroize, A4 rest-permissions hotfix.
- Phase B (P0): B1 encryption at rest (keychain data key).
- Phase C (P1): C1 pairing backoff + fingerprint confirm + persistent tombstones, C2 TLS 1.3 pin, C3 transfer caps, C4 exfiltration guardrails, C5 Tailscale enforce.
- Phase D (P2): D1 supply-chain/CI, D2 toast/XML/deep-link hardening, D3 firewall narrowing.

## 4. Detailed design
### A1 Path traversal fix — `handlers.rs:34` (blob `id` sink), `handlers.rs:389-416` (file `file_name` sink)
Fix BOTH sinks (the `id` sink at `:34` is independently exploitable, not just `file_name`). `ext` needs no fix — `extension_for_clipboard_mime()` (`common.rs:556-568`) returns `&'static str` from a fixed match.
```rust
// NEW helper in handlers.rs (or net_util.rs)
fn safe_store_path(cache_dir: &Path, id: &str, ext: &str) -> Result<PathBuf> {
    // Reject — don't mint a fresh UUID (that hides the attack in logs).
    let id = Uuid::parse_str(id)?;
    let ext = ext.chars().filter(|c| c.is_ascii_alphanumeric()).take(10).collect::<String>();
    let p = cache_dir.join(format!("{id}.{ext}"));
    // No canonicalize() check here: target does not exist yet so
    // canonicalize() falls back to `p` and the check is vacuous.
    // TOCTOU safety comes from create_new + symlink_metadata below.
    if p.symlink_metadata().is_ok() { bail!("exists or symlink") }
    Ok(p)
}
```
- Display name (`header.file_name`) stored only in metadata/emit, never joined. Sanitize for UI with existing React text-node path.
- `File::create` → `OpenOptions::new().write(true).create_new(true)` + `symlink_metadata` pre-check (reject if exists/symlink). No `canonicalize().unwrap_or()` gate.
- Collision: UUID removes need for ` (n)` loop; delete `handlers.rs:392-408`.
- Tests: `../../x`, `/abs`, `a/b`, `..\` (Windows), symlink-at-target, `id=../../evil`, pre-created symlink race — all stay inside `temp_downloads/` / fail closed.

### A2 Integrity digest — `protocol.rs:242-256` (`FileStreamHeader`), `protocol.rs:24-51` (`ClipboardBlob`), `handlers.rs:430-534`
Bump `CLUSTERCUT_PROTOCOL_VERSION = "0.4.0"` (`discovery.rs:27`, `net_util.rs:30-38` floor stays `>=0.3.3` for read, write is `0.4.0`).
```rust
pub struct FileStreamHeader {
    pub id: String, pub file_name: String, pub file_size: u64,
    #[serde(default)] pub sha256: Option<[u8; 32]>, // NEW: SHA-256 of *plaintext* (post-decompression). Option+default = wire-compat: old 0.3.4 readers ignore it, old senders parse as None.
    pub compressed: bool, pub file_index: usize, // existing (keep serde(default) on compressed/delivery_target)
}
pub struct ClipboardBlobHeader { pub id: String, pub file_size: u64, #[serde(default)] pub sha256: Option<[u8; 32]>, pub mime_type: String }
```
- Sender (`clipboard/common.rs` send path): hash while reading; fill header.
- Receiver: `ring::digest`/`sha2` hasher fed on post-decompression bytes; on EOF compare; mismatch → delete partial, emit `file-corrupt` (not `file-received`), never set clipboard.
- Back-compat (required, not optional): `sha256/origin_id/hop` MUST be `Option + #[serde(default)]` following the existing `compressed`/`delivery_target`/`content_hash` pattern — a bare `[u8;32]` breaks old-reader deserialization (hard proto break). If peer `proto < 0.4.0` (`sha256 == None`), accept with size-only check + `integrity=legacy` flag in emit; senders always send digest. Enforcement (reject-legacy) only at 0.6.0, not 0.4.4.
- Tests: 1-byte flip fails; truncation fails; legacy peer warns; old-reader-parses-new-header regression test.

### A3 Log + memory hygiene — `handlers.rs:589`, `state.rs:50,60,69`, `app.rs:77-83` (log dir; not 564-577)
- Delete `:589` payload log. Add `debug_assert!` lint: `rg "Decrypted Clipboard from.*text" ` in CI must be empty.
- Add `zeroize = "1"` to `Cargo.toml`. Wrap: `network_pin: Zeroizing<String>` (or `Arc<Mutex<Zeroizing<String>>>`), key `Vec<u8>` → `Zeroizing<Vec<u8>>`; `clear()` on eviction/factory-reset; `remove_file` → best-effort overwrite (1-pass zeros, ignore errors) + document non-guarantee on SSD.
- Move log dir out of `temp_dir()` to `app_log_dir()` with `0700/0600`; keep level gating (`pairing_debug_logs` off by default).

### A4 Permission hotfix (ships with A1) — `storage.rs:13-325`
Extend `set_owner_only` to every `AppConfig/*` write + `0700` on parent `create_dir_all` (add `set_dir_owner_only`). Apply to: `device_cert.der`, `known_peers.json`, `settings.json`, `device_id`, `cluster_id`, `network_name*`, `temp_downloads/*`. Windows: replace no-op with explicit DACL (OWNER+SYSTEM only) via `windows` ACL API; keep Unix `0o600/0o700`.

### B1 Encryption at rest — `storage.rs`, `history_store.rs`, `common.rs:595`, `handlers.rs:35`
- New dep: `keyring = "3"` + existing `chacha20poly1305`, `rand`. (`chacha` today is pairing-only: `pairing/crypto.rs:131-151`.)
- `DataKey`: 32B, generated once via `OsRng`, stored in OS keychain service=`app.clustercut.clustercut`, account=`data-key-v1`. Never on disk. Fallback (headless/keychain absent): prompt for user passphrase → Argon2id (m=64MiB, t=3, p=4, 32B output, random 16B salt stored in `AppConfig/data-key-salt`) → wrap DataKey; if declined, run memory-only history with persistent banner (history lost on restart — by design, document it).
- Envelope: `nonce(12B random, stored alongside file) || ciphertext || tag` per file (XChaCha20-Poly1305 or ChaCha20Poly1305 with random nonce, never reused); AAD = `b"clustercut" || file_purpose (u8) || version (u8)`. Secrets split: list is `network_pin`, `device_key.der`, peer fingerprints in `known_peers.json`, new `per_peer` consent map.
- Cover: `known_peers.json.enc`, `settings.secrets.enc` (split secrets from non-secrets so version diffs stay readable), `temp_downloads/*.enc` (decrypt-stream on recall/send), history Disk entries point at `.enc`.
- Migration (crash-safe): on first run, for each plaintext file: write `.enc.tmp` → fsync → rename to `.enc` → `remove_file` plaintext → fsync dir. Re-run skips existing `.enc`. `harden_secret_files()` extended to delete stray plaintext after verified encrypt. Never delete plaintext before `.enc` verifies (decrypt-round-trip check).
- Tests: cold read without keychain fails closed; wrong-key decrypt fails; migration idempotent; crash-between-tmp-and-rename resumes cleanly.

### C1 Pairing — `pairing/*`, `state.rs:182,237-259`, `app.rs:1049-1092`
- Backoff: replace sticky lockout with per-IP token bucket (e.g. 5 fails/5min/IP) + global ceiling (20 fails/10min) with decay; keep manual `rearm_pairing` as override. Prevents permanent DoS from one attacker.
- Fingerprint confirm (TOFU+confirm): after SPAKE2 success, both sides show `SHA256(cert)[0:16]` as 4-word list; user taps Match. MITM with guessed PIN now fails closed. Wire: version-gated `FingerprintConfirm` step inside existing QUIC `ClusterInfo` exchange (no new port): 0.4.0 senders include `responder_confirm`; 0.3.x peers omit it (`#[serde(default)]`) and fall back to PIN-only with `integrity=legacy`-style `confirm=legacy` flag in UI. Abort path: either side taps Mismatch → drop pairing, tombstone candidate fingerprint for 10min, log generic failure.
- Persistent tombstones: move kick list from `state.rs:168-175` memory set to `AppConfig/kicked.json` (encrypted per B1); filter on load + gossip import (`presence.rs:187-220` must honor tombstone).
- Keep: single-flight semaphore, 10s timeout, 8KB frame cap, KC round.

### C2 TLS 1.3 only — `transport.rs:373-384` (server), `transport.rs:568-587` (client), `transport.rs:458-545` (verifiers)
```rust
crypto.versions = vec![&rustls::version::TLS13]; // set on BOTH server and client configs
```
Delete BOTH `verify_tls12_signature` impls (`:458-465`, `:529-536`); keep `verify_tls13_signature`. Pin rcgen profile: validity 825d, EKU=client+serverAuth, SAN=`clustercut` only (today 3 SANs at `transport.rs:341-349`). QUIC behavior unchanged. Test: `SSLKEYLOG`/version assert that 1.2 handshake fails.

### C3 Transfer caps — `handlers.rs:430-495`, `transport.rs:289`
- Absolute caps (settings-overridable): single file 2GB default, blob per existing MIME caps, decompressed-ratio cap 100:1 or 1GB max (whichever first) on ZSTD path; pre-check `header.file_size` against cap before `File::create`; pre-check disk free space.
- `transport.rs:289` `read_to_end(64MB)` stays for control stream; file uni-stream gets explicit `max_file_bytes` guard.

### C4 Exfiltration guardrails (UX-safe) — `storage.rs:578`, `common.rs:1143-1210`, `handlers.rs:264-1026`
- Defaults + migration: `auto_send_text=true`, `auto_send_files=false` (file needs 1-click; `ManualSync` flow already exists). Existing installs migrate `auto_send → (auto_send_text, auto_send_files=auto_send)` once so F2 relay behavior doesn't silently change; fresh installs get the safe default. Add per-peer `{sync_text, sync_files}` (default inherit-global). Global pause-on-password-manager (detect 1Password/Bitwarden/KeePass owner, 10s hold — heuristic, fingerprintable, document false positives) + high-entropy prompt (>28 chars, entropy>4.5 bits/char → "Send secret?").
- Relay: max 1 hop; only relay to peers with `sync_text=true` and not the origin; add `#[serde(default)] origin_id: Option<String>` + `#[serde(default)] hop: u8` (defaults `None`/`0` for legacy) to `ClipboardPayload` (`protocol.rs:186-203`). Legacy peers relay unbounded — flag them in UI until 0.6.0 enforcement.
- D-Bus: `dbus.rs:62-115` exposes only toggles/signals today — there is no server-side `Write*` method. Add caller-UID check (`GetConnectionUnixUser`, require UID == self UID) to all mutating methods there AND to the GNOME-extension client calls (`dbus_clipboard.rs:137-169` `WriteBlob`/`WriteFormats`, `extension.js:69,73,777-781`); signals unchanged. Reject `file_count` > 64 at notify time (`handlers.rs:670-672` caps `files.len()` before `NotificationPayload::DownloadAvailable`) and validate `file_index < file_count` in `request_file` (`commands/clipboard.rs:326-333`, `lib.rs:865-899`).

### C5 Tailscale enforce — `net_util.rs`, `commands/peers.rs:102-180`, `app.rs:812-818`
- Setting `net_mode: Lan | Tailscale | Auto` (default `Lan` for compat).
- Tailscale mode: discover own `100.x` via `tailscale ip -4` (or `local-ip-address` filter `100.64/10`); bind QUIC + mDNS to that IP only (mDNS off, use direct `probe_ip` of tailnet peers); on inbound, `tailscale whois <ip>` must return tailnet identity; reject non-`100.64/10` remotes. Cache whois 5min.
- Future: `tsnet` embed for ACL-native identity. Firewall (`net_util.rs:335-350`): narrow from `remoteip=any profile=any` to `remoteip=100.64.0.0/10,<RFC1918> profile=private,domain`.

### D1 Supply chain + CI
- Replace `user-notify` git dep with crates.io or vendor + `cargo-vet`; DELETE unused `tauri_plugin_shell::init()` / `tauri_plugin_dialog::init()` (`app.rs:492-495`) — do not "scope capabilities" for them (Tauri v2 is deny-by-default; `capabilities/default.json` already grants no `shell:*`/`dialog:*`, so they are inert bloat; correct fix is removal). Zero call-sites today. Add CI: `cargo audit`, `cargo deny`, `npm audit`, `rg` secret-log lint, `cargo test` traversal/digest/migration tests.

### D2 Toast / deep-link — `lib.rs:69-95` (Windows toast XML), `app.rs:515-517,533-535` + `tauri.conf.json:30-35` (deep-link register/emit), `App.tsx:192-242` (frontend router)
- XML-escape `<>&"'` (today only `&` at `lib.rs:77`; `title`/`body` from peer `hostname`/`file_name` via `handlers.rs:667,675` are unescaped) + URL-encode `msg_id/peer_id` (`lib.rs:72-73` has no encoding); strict route match (`parsed.pathname==="/action/download"`, not `includes("action/download")` at `App.tsx:198,207` — `clustercut://evil?action/download-fake` matches today); allow-list `view ∈ {devices,history,settings}` (today `App.tsx:228-235` passes any `?view=` to `setActiveView(v as any)`); cap `file_count ≤ 64` with `NaN`/negative reject + bound frontend `request_file` loop (`App.tsx:210-222` `parseInt` uncapped; backend `lib.rs:512-513,659,670` `for i in 0..count` uncapped) and validate `file_index < file_count` server-side.

## 5. Config schema (additive, `storage.rs:517-559` struct + `573-595` Default + `598-632` load)
```json
{
  "net_mode": "lan",
  "per_peer": { "<peer_id>": {"sync_text": true, "sync_files": false} },
  "auto_send_text": true, "auto_send_files": false,
  "max_file_bytes": 2147483648, "max_decompressed_bytes": 1073741824,
  "require_fingerprint_confirm": true
}
```
All new keys MUST be `#[serde(default)]` (+ `default_*` fns) AND all existing required fields retrofitted with `#[serde(default)]` — today the first 8 fields lack it and `load_settings:610` is `serde_json::from_str(&content).unwrap_or_default()`, so any unknown/missing-field parse failure resets the ENTIRE file to `Default`. "No reset of existing installs" holds only after that hardening, not as a current property.

## 6. Verification
- Unit: traversal vectors (both sinks + symlink race), digest mismatch/truncation, legacy-proto fallback, old-reader-parses-new-header (new `Option` fields ignored), keychain-absent fallback, backoff decay, tombstone persistence, whois reject, `file_count`/`file_index` bounds, strict deep-link route + `view` allow-list.
- Integration: two-instance LAN sync, Tailscale-mode over `100.x` (netns), ZSTD bomb (1000:1) capped, 2GB cap enforced, stolen-disk (no keychain → unreadable).
- Manual UAT: copy/paste text+image, file approve, history recall, kick persistence, firewall prompt.
- CI gates: `cargo audit` clean, secret-log grep empty, `tsc` + `cargo test` green.

## 7. Rollout
1. A1+A2+A3+A4 → 0.4.4 (writers send digest; readers accept `None` as `integrity=legacy` with size-only check — no reader break BECAUSE new fields are `Option+default`; no enforcement yet).
2. B1 → 0.5.0 (crash-safe migration runs once, banner if keychain unavailable).
3. C1–C5 → 0.6.0 (proto 0.4.0 enforcement: digest+hop required, legacy peers flagged/blocked per policy).
4. D1–D3 → hardening point releases.

## 8. Acceptance
Ship-blockers closed iff: traversal suite green (both sinks + symlink race), every consumed non-legacy file digest-verified (`integrity=legacy` only for pre-0.4.0 peers, flagged in UI; zero `content_hash`-as-integrity), no payload bytes in logs (grep + runtime test), at-rest ciphertext verified by cold read, TLS1.3-only handshake verified (`SSLKEYLOG`/version assert), Tailscale-only mode rejects non-tailnet IP, per-peer/file consent UAT passes (incl. `file_count≤64`, `file_index` validation, strict deep-link route).

## 9. Risks
- Keychain loss → history unrecoverable (by design; document + export option).
- Fingerprint-confirm adds 1 tap to first pairing (accepted).
- Strict caps may block huge legit transfers (overridable in settings).
- Residual → C1: any trusted peer can kick any other member (`peer_removal_kicker_authorized` only admits trusted/manual kickers); full membership authorization (roles/quorum) is C1. Gossip pins remain handshake-usable for convergence but never authorize (H-2) nor persist.
