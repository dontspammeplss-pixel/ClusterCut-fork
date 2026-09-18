use crate::peer::Peer;
use names::Generator;
use rand::Rng;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tauri::{path::BaseDirectory, AppHandle, Manager};

/// Restrict a file to owner-only access. On Unix sets mode 0600. On Windows
/// replaces the inherited DACL with an owner+SYSTEM-only one (see
/// `restrict_dacl_owner_system_only`). Best-effort — logs on failure, never
/// panics.
pub(crate) fn set_owner_only(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            tracing::warn!("Failed to set 0600 on {}: {}", path.display(), e);
        }
    }
    #[cfg(windows)]
    {
        restrict_dacl_owner_system_only(path);
    }
}

/// Create a directory (and parents) restricted to owner-only access. On Unix
/// sets mode 0700. Best-effort — logs on failure, never panics.
pub(crate) fn set_dir_owner_only(path: &Path) {
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

/// Windows-only: replace the inherited ACL with an owner+SYSTEM full-access
/// only DACL. Best-effort, logs and returns on any error.
#[cfg(windows)]
fn restrict_dacl_owner_system_only(path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::{LocalFree, HLOCAL, WIN32_ERROR};
    use windows::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
        NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
        TRUSTEE_W,
    };
    use windows::Win32::Security::{
        CreateWellKnownSid, WinLocalSystemSid, ACL, DACL_SECURITY_INFORMATION,
        OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSID, PSECURITY_DESCRIPTOR,
        // Lives in Win32::Security (accctrl.h), not in the Authorization submodule.
        SUB_CONTAINERS_AND_OBJECTS_INHERIT,
    };
    use windows::core::{PCWSTR, PWSTR};

    let fail = |why: &str| {
        tracing::warn!("DACL harden failed {}: {}", path.display(), why);
    };
    let check = |r: WIN32_ERROR, why: &str| -> bool {
        if r.0 != 0 {
            fail(&format!("{} (win32 {})", why, r.0));
            false
        } else {
            true
        }
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let pcw = PCWSTR(wide.as_ptr());

    // SYSTEM SID for the second ACE.
    let mut system_buf = [0u8; 68];
    let mut system_len = system_buf.len() as u32;
    if CreateWellKnownSid(
        WinLocalSystemSid,
        None,
        Some(PSID(system_buf.as_mut_ptr() as *mut _)),
        &mut system_len,
    )
    .is_err()
    {
        fail("CreateWellKnownSid");
        return;
    }
    let system_sid = PSID(system_buf.as_mut_ptr() as *mut _);

    // Owner SID of the file/dir.
    let mut owner: PSID = PSID(std::ptr::null_mut());
    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let r = unsafe {
        GetNamedSecurityInfoW(
            pcw,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner as *mut PSID),
            None,
            None,
            None,
            &mut descriptor as *mut PSECURITY_DESCRIPTOR,
        )
    };
    if !check(r, "GetNamedSecurityInfoW") {
        return;
    }
    if owner.0.is_null() {
        unsafe { LocalFree(Some(HLOCAL(descriptor.0 as *mut _))) };
        fail("no owner SID");
        return;
    }

    // Two full-access ACEs (0x1F01FF): owner + SYSTEM, inherited by children.
    let trustee = |sid: PSID| TRUSTEE_W {
        pMultipleTrustee: std::ptr::null_mut(),
        MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: PWSTR(sid.0 as *mut u16),
    };
    let entries = [
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: 0x1F01FF,
            grfAccessMode: SET_ACCESS,
            grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Trustee: trustee(owner),
        },
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: 0x1F01FF,
            grfAccessMode: SET_ACCESS,
            grfInheritance: SUB_CONTAINERS_AND_OBJECTS_INHERIT,
            Trustee: trustee(system_sid),
        },
    ];
    let mut new_acl: *mut ACL = std::ptr::null_mut();
    let r = unsafe { SetEntriesInAclW(Some(&entries), None, &mut new_acl) };
    if !check(r, "SetEntriesInAclW") {
        unsafe { LocalFree(Some(HLOCAL(descriptor.0 as *mut _))) };
        return;
    }
    let info: OBJECT_SECURITY_INFORMATION =
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let r = unsafe {
        SetNamedSecurityInfoW(pcw, SE_FILE_OBJECT, info, None, None, Some(new_acl as *const ACL), None)
    };
    unsafe {
        LocalFree(Some(HLOCAL(new_acl as *mut _)));
        LocalFree(Some(HLOCAL(descriptor.0 as *mut _)));
    }
    check(r, "SetNamedSecurityInfoW");
}

/// Best-effort secure delete: overwrite the file's bytes with zeros (1-pass)
/// before unlinking. All errors ignored — the `remove_file` still runs.
// ponytail: 1-pass zeros only; SSD wear-levelling/CoW may retain copies — no guarantee.
pub fn secure_delete(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        if meta.is_file() && meta.len() > 0 {
            if let Ok(mut f) = fs::OpenOptions::new().write(true).open(path) {
                use std::io::Write;
                let mut remaining = meta.len();
                let zeros = [0u8; 4096];
                while remaining > 0 {
                    let n = (remaining as usize).min(zeros.len());
                    if f.write_all(&zeros[..n]).is_err() {
                        break;
                    }
                    remaining -= n as u64;
                }
                let _ = f.flush();
                let _ = f.sync_all();
            }
        }
    }
    let _ = fs::remove_file(path);
}

pub fn load_network_name(app: &AppHandle) -> String {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("network_name", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(_) => return String::from("unknown-network"),
    };

    if path.exists() {
        if let Ok(name) = fs::read_to_string(&path) {
            if !name.trim().is_empty() {
                tracing::debug!("Loaded Network Name: {}", name);
                return name;
            }
        }
    }

    // Generate new name if missing
    let mut generator = Generator::default();
    let new_name = generator
        .next()
        .unwrap_or_else(|| "unnamed-network".to_string());

    // Save it
    save_network_name(app, &new_name);
    tracing::info!("Generated new Network Name: {}", new_name);
    new_name
}

pub fn save_network_name(app: &AppHandle, name: &str) {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("network_name", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(_) => return,
    };

    if let Some(parent) = path.parent() {
        set_dir_owner_only(parent);
    }
    if fs::write(&path, name).is_ok() {
        set_owner_only(&path);
    }
}

/// Load the cluster-name version counter. Missing/invalid file → 0 (pre-issue
/// default; an upgraded install starts unversioned and converges by origin).
pub fn load_network_name_version(app: &AppHandle) -> u64 {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("network_name_version", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(_) => return 0,
    };
    if let Ok(s) = fs::read_to_string(&path) {
        if let Ok(v) = s.trim().parse::<u64>() {
            return v;
        }
    }
    0
}

pub fn save_network_name_version(app: &AppHandle, version: u64) {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("network_name_version", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(_) => return,
    };
    if let Some(parent) = path.parent() {
        set_dir_owner_only(parent);
    }
    if fs::write(&path, version.to_string()).is_ok() {
        set_owner_only(&path);
    }
}

/// Load the device_id that set the current cluster name (tie-breaker). Missing
/// file → empty string; callers seed it with the local device_id at startup so
/// an unversioned install has a well-formed origin.
pub fn load_network_name_origin(app: &AppHandle) -> String {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("network_name_origin", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(_) => return String::new(),
    };
    if let Ok(s) = fs::read_to_string(&path) {
        let trimmed = s.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    String::new()
}

pub fn save_network_name_origin(app: &AppHandle, origin: &str) {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("network_name_origin", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(_) => return,
    };
    if let Some(parent) = path.parent() {
        set_dir_owner_only(parent);
    }
    if fs::write(&path, origin).is_ok() {
        set_owner_only(&path);
    }
}

pub fn load_cluster_id(app: &AppHandle) -> Option<String> {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("cluster_id", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to resolve cluster id path: {}", e);
            return None;
        }
    };

    if !path.exists() {
        return None;
    }

    match fs::read_to_string(&path) {
        Ok(s) => {
            let trimmed = s.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                tracing::debug!("Loaded cluster_id from disk.");
                Some(trimmed)
            }
        }
        Err(e) => {
            tracing::warn!("Failed to read cluster_id file: {}", e);
            None
        }
    }
}

pub fn save_cluster_id(app: &AppHandle, id: &str) {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("cluster_id", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to resolve cluster_id path for saving: {}", e);
            return;
        }
    };

    if let Some(parent) = path.parent() {
        set_dir_owner_only(parent);
    }

    if let Err(e) = fs::write(&path, id) {
        tracing::error!("Failed to write cluster_id file: {}", e);
    } else {
        set_owner_only(&path);
        tracing::debug!("Saved cluster_id to disk.");
    }
}

/// Delete the legacy `cluster_key.bin` file from earlier versions. v0.3+
/// no longer treats the cluster key as a secret (mTLS replaces its role);
/// the file is wiped on first boot of the new build to avoid leaving a
/// stale 32-byte secret on disk.
pub fn wipe_legacy_cluster_key(app: &AppHandle) {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("cluster_key.bin", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(_) => return,
    };
    if path.exists() {
        secure_delete(&path);
        tracing::info!("Attempted wipe of legacy cluster_key.bin at {:?}", path);
    }
}

pub fn load_known_peers(app: &AppHandle) -> HashMap<String, Peer> {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("known_peers.json", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to resolve config path: {}", e);
            return HashMap::new();
        }
    };

    if !path.exists() {
        return HashMap::new();
    }

    match fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<HashMap<String, Peer>>(&content) {
            Ok(peers) => {
                tracing::info!("Loaded {} known peers from disk at {:?}", peers.len(), path);
                peers
            }
            Err(e) => {
                tracing::error!("Failed to parse known peers: {}", e);
                HashMap::new()
            }
        },
        Err(e) => {
            tracing::warn!("Failed to read known peers file: {}", e);
            HashMap::new()
        }
    }
}

/// H-3: gossip imports (untrusted, non-manual) are handshake pins and
/// re-probe targets only — they must never reach disk. Any later
/// `save_known_peers` of the full map would otherwise flush in-memory
/// gossip to `known_peers.json`, persisting attacker-supplied fingerprints.
pub(crate) fn persistable_known_peers(peers: &HashMap<String, Peer>) -> HashMap<String, Peer> {
    peers
        .iter()
        .filter(|(_, p)| p.is_trusted || p.is_manual)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

pub fn save_known_peers(app: &AppHandle, peers: &HashMap<String, Peer>) {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("known_peers.json", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to resolve config path for saving: {}", e);
            return;
        }
    };

    if let Some(parent) = path.parent() {
        set_dir_owner_only(parent);
    }

    match serde_json::to_string_pretty(&persistable_known_peers(peers)) {
        Ok(json) => {
            if let Err(e) = fs::write(&path, json) {
                tracing::error!("Failed to write known peers file: {}", e);
            } else {
                set_owner_only(&path);
                tracing::debug!("Saved known peers to disk at {:?}", path);
            }
        }
        Err(e) => {
            tracing::error!("Failed to serialize known peers: {}", e);
        }
    }
}

pub fn load_device_cert(app: &AppHandle) -> Option<(Vec<u8>, Vec<u8>)> {
    let path_resolver = app.path();
    let cert_path = path_resolver
        .resolve("device_cert.der", BaseDirectory::AppConfig)
        .ok()?;
    let key_path = path_resolver
        .resolve("device_key.der", BaseDirectory::AppConfig)
        .ok()?;

    if !cert_path.exists() || !key_path.exists() {
        return None;
    }

    match (fs::read(&cert_path), fs::read(&key_path)) {
        (Ok(cert), Ok(key)) if !cert.is_empty() && !key.is_empty() => {
            tracing::debug!("Loaded device cert from disk.");
            Some((cert, key))
        }
        _ => None,
    }
}

pub fn save_device_cert(app: &AppHandle, cert_der: &[u8], key_der: &[u8]) {
    let path_resolver = app.path();
    let cert_path = match path_resolver.resolve("device_cert.der", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to resolve device cert path: {}", e);
            return;
        }
    };
    let key_path = match path_resolver.resolve("device_key.der", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to resolve device key path: {}", e);
            return;
        }
    };

    if let Some(parent) = cert_path.parent() {
        set_dir_owner_only(parent);
    }

    if let Err(e) = fs::write(&cert_path, cert_der) {
        tracing::error!("Failed to write device cert: {}", e);
        return;
    }
    set_owner_only(&cert_path);
    if let Err(e) = fs::write(&key_path, key_der) {
        tracing::error!("Failed to write device key: {}", e);
        return;
    }
    // The private key must not be world-readable (issue: secret file perms).
    set_owner_only(&key_path);
    tracing::debug!("Saved device cert to disk.");
}

/// Re-apply owner-only permissions to the on-disk secret files if they exist.
/// Run once at startup so installs created before this hardening landed get
/// fixed — `device_key.der` in particular is written only at first launch and
/// never rewritten, so the write-path hardening alone would never reach it.
pub fn harden_secret_files(app: &AppHandle) {
    let path_resolver = app.path();
    for name in ["device_key.der", "network_pin"] {
        if let Ok(path) = path_resolver.resolve(name, BaseDirectory::AppConfig) {
            if path.exists() {
                set_owner_only(&path);
            }
        }
    }
}

pub fn load_device_id(app: &AppHandle) -> String {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("device_id", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(_) => return String::new(),
    };

    if !path.exists() {
        return String::new();
    }

    fs::read_to_string(path).unwrap_or_default()
}

pub fn save_device_id(app: &AppHandle, id: &str) {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("device_id", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to resolve device_id path: {}", e);
            return;
        }
    };

    if let Some(parent) = path.parent() {
        set_dir_owner_only(parent);
    }

    if fs::write(&path, id).is_ok() {
        set_owner_only(&path);
    }
}

/// Generate a fresh 6-character lowercase-alphanumeric pairing PIN. No disk I/O.
fn generate_pin() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..6)
        .map(|_| {
            let idx = rand::thread_rng().gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

pub fn load_network_pin(app: &AppHandle) -> String {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("network_pin", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(_) => return String::from("000000"),
    };

    if path.exists() {
        if let Ok(pin) = fs::read_to_string(&path) {
            // Trim defensively. The PIN is fed straight into SPAKE2 as the
            // shared password, so even a single trailing byte (newline,
            // space) on one side and not the other makes the derived AEAD
            // sub-keys diverge and pairing fails on T2 — and the user-facing
            // symptom is a misleading "Pairing session expired"-class error
            // with no hint that whitespace was the cause. A legacy
            // network_pin file written by an older build (or hand-edited)
            // gets healed on the next load without any migration code.
            let trimmed = pin.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }

    // Generate a new PIN and persist it (provisioned-mode path / lazy default).
    let pin = generate_pin();
    tracing::info!("Generated a new network PIN.");
    save_network_pin(app, &pin);
    pin
}

pub fn save_network_pin(app: &AppHandle, pin: &str) {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("network_pin", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to resolve network_pin path: {}", e);
            return;
        }
    };

    if let Some(parent) = path.parent() {
        set_dir_owner_only(parent);
    }
    // Mirror the trim done on load_network_pin — keeps the on-disk file
    // canonical (no trailing whitespace from a pasted Settings input) so
    // even a build without the load-side trim would behave correctly.
    if fs::write(&path, pin.trim()).is_ok() {
        // The pairing PIN must not be world-readable (issue: secret file perms).
        set_owner_only(&path);
    }
}
/// Whether this device's pairing PIN should be persisted to disk. Only
/// provisioned mode keeps a stable, user-set PIN across restarts; auto mode is
/// ephemeral (issue 4).
pub(crate) fn pin_should_persist(mode: &str) -> bool {
    mode == "provisioned"
}

/// Whether a device joining a cluster should adopt the PIN it just paired with
/// as its own `network_pin`. Only provisioned clusters share a single PIN: the
/// joiner already typed the responder's (== the cluster's) PIN to complete
/// SPAKE2, so adopting it makes every device converge onto the admin's common
/// PIN. Auto clusters keep per-device ephemeral PINs, so they never adopt.
pub(crate) fn should_adopt_cluster_pin(mode: &str) -> bool {
    mode == "provisioned"
}

/// Establish this device's pairing PIN for the given cluster mode.
///
/// Provisioned mode persists the PIN (a user-set, memorable value must survive
/// restarts), so it reads (and lazily generates + saves) from disk. Auto mode
/// keeps the PIN ephemeral: any on-disk `network_pin` file is deleted and a
/// fresh PIN is generated in memory, never written to disk. The PIN is only
/// needed live during interactive pairing, so a per-launch value is sufficient
/// and avoids storing the secret. See issue 4.
pub fn establish_network_pin(app: &AppHandle, mode: &str) -> String {
    if pin_should_persist(mode) {
        return load_network_pin(app);
    }
    // Auto mode: delete any stored PIN, go ephemeral.
    if let Ok(path) = app.path().resolve("network_pin", BaseDirectory::AppConfig) {
        if path.exists() {
            secure_delete(&path);
        }
    }
    generate_pin()
}

// Helper to reset network state (Self-Destruct/Kick)
pub fn reset_network_state(app: &AppHandle) {
    let path_resolver = app.path();
    // Include the actual filenames used by load/save
    let config_files = [
        "cluster_id",
        "cluster_key.bin", // legacy from v0.2; deleted defensively
        "network_name",
        "network_pin",
        "known_peers.json",
    ];

    for filename in config_files {
        match path_resolver.resolve(filename, BaseDirectory::AppConfig) {
            Ok(path) => {
                if path.exists() {
                    secure_delete(&path);
                }
            }
            Err(e) => tracing::error!("Failed to resolve path for {}: {}", filename, e),
        }
    }
}

/// Regenerate just the cluster NAME: delete the on-disk name file and return a
/// fresh generated name (`load_network_name` regenerates and persists it). The
/// PIN is handled separately by `establish_network_pin` so its persistence
/// follows the cluster mode (ephemeral in auto — issue 4).
pub fn regenerate_network_name(app: &AppHandle) -> String {
    let path_resolver = app.path();
    if let Ok(path) = path_resolver.resolve("network_name", BaseDirectory::AppConfig) {
        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }
    load_network_name(app)
}
// --- Settings Persistance ---

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct NotificationSettings {
    pub device_join: bool,
    pub device_leave: bool,
    pub data_sent: bool,
    pub data_received: bool,
}

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            device_join: true,
            device_leave: true,
            data_sent: false,
            data_received: false,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AppSettings {
    pub custom_device_name: Option<String>,
    pub cluster_mode: String, // "auto" or "provisioned"
    pub auto_send: bool,
    pub auto_receive: bool,
    pub notifications: NotificationSettings,
    pub shortcut_send: Option<String>,
    pub shortcut_receive: Option<String>,
    pub enable_file_transfer: bool,
    pub max_auto_download_size: u64, // In bytes
    pub notify_large_files: bool,
    #[serde(default)]
    pub ignore_extension_missing: bool,
    #[serde(default)]
    pub flatpak_autostart: bool,
    #[serde(default)]
    pub compress_file_transfers: bool,
    /// Per WIRE-PROTOCOL-0.3.1 §H7: when off, the responder logs only a
    /// generic "pairing failed" line on AEAD-decrypt failures, so a
    /// passive observer can't tell a wrong-PIN attempt apart from any
    /// other framing/decrypt error. Flip on for verbose pairing diagnostics.
    #[serde(default)]
    pub pairing_debug_logs: bool,
    /// User-controlled pause for the SPAKE pairing listener. When `false`,
    /// inbound TCP pairing connections are dropped immediately at the accept
    /// loop, alongside the existing `pairing_locked_out` brute-force defence.
    /// Surfaced in the UI as a header-bar toggle (issue #16).
    #[serde(default = "default_pairing_accept_enabled")]
    pub pairing_accept_enabled: bool,
    /// Issue #18: when off, the Windows firewall rule is NOT auto-created at
    /// startup. Default-on for backward compatibility. Windows-only effect.
    #[serde(default = "default_true")]
    pub configure_firewall: bool,
    /// Issue #18: when off, the device does not advertise itself over mDNS
    /// (browsing/discovery of others stays active). Default-on.
    #[serde(default = "default_true")]
    pub mdns_advertising: bool,
    /// Max bytes of re-callable clipboard content (text + images) the History
    /// content store retains, across RAM + disk tiers. File transfers don't
    /// count. Default 200 MB; oldest entries evict first when exceeded.
    #[serde(default = "default_history_store_max_bytes")]
    pub history_store_max_bytes: u64,
}

fn default_pairing_accept_enabled() -> bool {
    true
}

fn default_true() -> bool {
    true
}

fn default_history_store_max_bytes() -> u64 {
    200 * 1024 * 1024
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            custom_device_name: None,
            cluster_mode: "auto".to_string(),
            auto_send: true,
            auto_receive: true,
            notifications: NotificationSettings::default(),
            shortcut_send: Some("CommandOrControl+Alt+C".to_string()),
            shortcut_receive: Some("CommandOrControl+Alt+V".to_string()),
            enable_file_transfer: true,
            max_auto_download_size: 50 * 1024 * 1024, // 50 MB
            notify_large_files: true,
            ignore_extension_missing: false,
            flatpak_autostart: false,
            compress_file_transfers: false,
            pairing_debug_logs: false,
            pairing_accept_enabled: true,
            configure_firewall: true,
            mdns_advertising: true,
            history_store_max_bytes: 200 * 1024 * 1024,
        }
    }
}

pub fn load_settings(app: &AppHandle) -> AppSettings {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("settings.json", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(_) => return AppSettings::default(),
    };

    if !path.exists() {
        return AppSettings::default();
    }

    match fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => AppSettings::default(),
    }
}

pub fn save_settings(app: &AppHandle, settings: &AppSettings) {
    let path_resolver = app.path();
    let path = match path_resolver.resolve("settings.json", BaseDirectory::AppConfig) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to resolve settings path: {}", e);
            return;
        }
    };

    if let Some(parent) = path.parent() {
        set_dir_owner_only(parent);
    }

    if let Ok(json) = serde_json::to_string_pretty(settings) {
        if fs::write(&path, json).is_ok() {
            set_owner_only(&path);
        }
    }
}

#[cfg(all(test, unix))]
mod perms_tests {
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn set_owner_only_sets_0600() {
        // Create a world-readable temp file, then harden it.
        let path = std::env::temp_dir().join(format!(
            "clustercut_perms_test_{}_0600",
            std::process::id()
        ));
        std::fs::write(&path, b"secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        super::set_owner_only(&path);

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode & 0o777, 0o600, "expected 0600, got {:o}", mode & 0o777);
    }

    #[test]
    fn app_config_files_and_dirs_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("cc_perms_{}_owner_only", std::process::id()));
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
}

#[cfg(test)]
mod settings_tests {
    use super::AppSettings;

    #[test]
    fn missing_new_fields_default_to_true() {
        // A settings.json written before issue #18 has neither field.
        // They must deserialize to `true`, not bool's serde default of false.
        let json = r#"{
            "custom_device_name": null,
            "cluster_mode": "auto",
            "auto_send": true,
            "auto_receive": true,
            "notifications": {"device_join": true, "device_leave": true, "data_sent": false, "data_received": false},
            "shortcut_send": null,
            "shortcut_receive": null,
            "enable_file_transfer": true,
            "max_auto_download_size": 52428800,
            "notify_large_files": true
        }"#;
        let s: AppSettings = serde_json::from_str(json).unwrap();
        assert!(s.configure_firewall);
        assert!(s.mdns_advertising);
    }

    #[test]
    fn explicit_false_round_trips() {
        let mut s = AppSettings::default();
        s.configure_firewall = false;
        s.mdns_advertising = false;
        let json = serde_json::to_string(&s).unwrap();
        let back: AppSettings = serde_json::from_str(&json).unwrap();
        assert!(!back.configure_firewall);
        assert!(!back.mdns_advertising);
    }

    #[test]
    fn defaults_are_true() {
        let s = AppSettings::default();
        assert!(s.configure_firewall);
        assert!(s.mdns_advertising);
    }
}

#[cfg(test)]
mod pin_tests {
    use super::{generate_pin, pin_should_persist, should_adopt_cluster_pin};

    #[test]
    fn generate_pin_is_six_lowercase_alnum() {
        let pin = generate_pin();
        assert_eq!(pin.len(), 6, "pin was {:?}", pin);
        assert!(
            pin.chars().all(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "unexpected chars in {:?}",
            pin
        );
    }

    #[test]
    fn only_provisioned_persists() {
        assert!(pin_should_persist("provisioned"));
        assert!(!pin_should_persist("auto"));
        assert!(!pin_should_persist("something-else"));
    }

    #[test]
    fn only_provisioned_adopts_cluster_pin_on_join() {
        // A joiner only converges onto the cluster's shared PIN when it is in
        // provisioned mode. Auto mode keeps its per-device ephemeral PIN.
        assert!(should_adopt_cluster_pin("provisioned"));
        assert!(!should_adopt_cluster_pin("auto"));
        assert!(!should_adopt_cluster_pin("something-else"));
    }
}

#[cfg(test)]
mod persist_tests {
    use super::persistable_known_peers;
    use crate::peer::Peer;
    use std::collections::HashMap;

    fn peer(id: &str, is_trusted: bool, is_manual: bool) -> Peer {
        Peer {
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

    #[test]
    fn gossip_never_persists() {
        let mut peers = HashMap::new();
        peers.insert("paired".to_string(), peer("paired", true, false));
        peers.insert("manual-10.0.0.9".to_string(), peer("manual-10.0.0.9", false, true));
        peers.insert("gossip".to_string(), peer("gossip", false, false));
        let out = persistable_known_peers(&peers);
        assert!(out.contains_key("paired"));
        assert!(out.contains_key("manual-10.0.0.9"));
        assert!(!out.contains_key("gossip"));
    }
}

#[cfg(test)]
mod secure_delete_tests {
    use super::secure_delete;

    #[test]
    fn removes_file_and_tolerates_missing() {
        let path = std::env::temp_dir().join(format!(
            "clustercut_secure_delete_test_{}",
            std::process::id()
        ));
        std::fs::write(&path, b"supersecretpin").unwrap();
        secure_delete(&path);
        assert!(!path.exists(), "file must be gone after secure_delete");
        // Missing path must not panic (best-effort).
        secure_delete(&path);
    }
}
