//! System-level commands: logging, exit, GNOME extension, launch args,
//! autostart, and native notifications.

use crate::state::AppState;
use crate::storage;
use tauri::{AppHandle, Manager};
// Only the GNOME-extension-state push below emits, and that is Linux-only.
#[cfg(target_os = "linux")]
use tauri::Emitter;
#[cfg(target_os = "macos")]
use crate::{NotificationPayload, send_notification};

/// UUID of the bundled GNOME Shell extension. Must match `metadata.json` and
/// the `EXTENSION_UUID` in `clipboard/watcher.rs`.
const EXTENSION_UUID: &str = "clustercut@keithvassallo.com";

/// GNOME Shell extension sources, embedded at compile time from the repo's
/// `gnome-extension/` directory.
///
/// Embedding rather than shipping them as a Tauri resource keeps the app and
/// the extension it installs in lockstep (no version skew between the two), and
/// means the install command needs no runtime path resolution — it works
/// identically in a dev build, a deb/rpm install and a Flatpak sandbox.
const EXTENSION_JS: &str = include_str!("../../../gnome-extension/extension.js");
const EXTENSION_METADATA: &str = include_str!("../../../gnome-extension/metadata.json");
const EXTENSION_ICON: &str =
    include_str!("../../../gnome-extension/icons/hicolor/symbolic/apps/clustercut-symbolic.svg");

#[derive(serde::Serialize)]
pub(crate) struct ExtensionStatus {
    pub(crate) is_gnome: bool,
    pub(crate) is_installed: bool,
    /// True when on GNOME Wayland without the extension — clipboard sync will NOT work
    pub(crate) clipboard_requires_extension: bool,
}

#[derive(serde::Serialize)]
pub(crate) struct ExtensionInstallResult {
    /// Directory the extension was written to, shown to the user.
    pub(crate) installed_to: String,
    /// True when GNOME Shell accepted the enable request right away, meaning the
    /// shell already knew about this UUID and the extension is live now. Normally
    /// false: the shell only scans for user extensions at startup, so a log out
    /// and back in is required before the extension can load.
    pub(crate) enabled: bool,
    /// True when the UUID is in `org.gnome.shell enabled-extensions`, so GNOME
    /// Shell will activate the extension on its next start. False means the
    /// enable request failed at both levels and the user may also have to switch
    /// it on in the Extensions app after logging back in.
    pub(crate) enabled_at_next_login: bool,
}

/// True when the extension's files exist in either location GNOME Shell scans.
///
/// Installed is not loaded: on GNOME Wayland the shell only scans these
/// directories at startup, so freshly written files stay inert until the next
/// session start.
fn extension_installed_on_disk() -> bool {
    let home = std::env::var("HOME").unwrap_or_default();
    let local = format!("{home}/.local/share/gnome-shell/extensions/{EXTENSION_UUID}");
    let system = format!("/usr/share/gnome-shell/extensions/{EXTENSION_UUID}");
    std::path::Path::new(&local).exists() || std::path::Path::new(&system).exists()
}

/// Everything the extension dialog needs to know about the extension's state,
/// pushed to the frontend on every observed change.
#[cfg(target_os = "linux")]
#[derive(serde::Serialize, Clone)]
pub(crate) struct GnomeExtensionState {
    /// The extension's D-Bus clipboard bridge answered its introspection probe:
    /// GNOME Shell has loaded and enabled it, so clipboard sync is running. This
    /// is the authoritative "the extension is live" signal — it is the same
    /// probe that promotes the clipboard backend to `GnomeExtension`.
    pub(crate) bridge_live: bool,
    /// The extension's files are present on disk. Installed does NOT imply
    /// loaded or enabled; see `extension_installed_on_disk`.
    pub(crate) installed: bool,
    /// GNOME on Wayland with no live bridge, i.e. clipboard sync is broken until
    /// the extension loads. False off GNOME and on X11, where the clipboard is
    /// read directly and no extension is involved.
    pub(crate) requires_extension: bool,
}

/// Current extension/bridge state as the UI needs it.
#[cfg(target_os = "linux")]
pub(crate) async fn gnome_extension_state() -> GnomeExtensionState {
    use crate::clipboard;
    let bridge_live = clipboard::dbus_clipboard::is_available_async().await;
    GnomeExtensionState {
        bridge_live,
        installed: extension_installed_on_disk(),
        requires_extension: clipboard::is_gnome() && clipboard::is_wayland() && !bridge_live,
    }
}

/// Push the current state to the frontend.
///
/// Called from the clipboard watcher on every transition and right after an
/// install, so the extension dialog tracks reality instead of freezing whatever
/// it saw when the app started.
#[cfg(target_os = "linux")]
pub(crate) async fn emit_gnome_extension_state(app: &AppHandle) {
    let _ = app.emit("gnome-extension-state", gnome_extension_state().await);
}

#[derive(serde::Serialize)]
pub(crate) struct ClipboardSandboxStatus {
    /// True when the Flatpak sandbox cannot reach a clipboard at all: a Wayland
    /// session, not GNOME (so the extension bridge doesn't apply), and backend
    /// detection came back Degraded. Compositors implementing
    /// `wp_security_context_v1` withhold the data-control globals from sandboxed
    /// clients, so clipboard sync cannot work in Flatpak there — the native
    /// package can. Reported so the UI can say so instead of failing silently.
    pub(crate) sandbox_blocked: bool,
    /// `XDG_CURRENT_DESKTOP`, e.g. "Hyprland" — named in the warning.
    pub(crate) desktop: String,
}

#[tauri::command]
pub(crate) async fn check_clipboard_sandbox_status() -> ClipboardSandboxStatus {
    #[cfg(target_os = "linux")]
    {
        use crate::clipboard;
        let sandbox_blocked = clipboard::is_flatpak()
            && clipboard::is_wayland()
            && !clipboard::is_gnome()
            && clipboard::get_backend() == clipboard::ClipboardBackend::Degraded;
        ClipboardSandboxStatus {
            sandbox_blocked,
            desktop: clipboard::desktop_name(),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        ClipboardSandboxStatus {
            sandbox_blocked: false,
            desktop: String::new(),
        }
    }
}

#[tauri::command]
pub(crate) fn log_frontend(message: String, level: Option<String>) {
    match level.as_deref() {
        Some("error") => tracing::error!("[Frontend] {}", message),
        Some("warn") => tracing::warn!("[Frontend] {}", message),
        Some("debug") => tracing::debug!("[Frontend] {}", message),
        Some("trace") => tracing::trace!("[Frontend] {}", message),
        _ => tracing::info!("[Frontend] {}", message),
    }
}

#[tauri::command]
pub(crate) async fn exit_app(app_handle: tauri::AppHandle) {
    app_handle.exit(0);
}

#[tauri::command]
pub(crate) async fn check_gnome_extension_status() -> ExtensionStatus {
    let xdg_current_desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    let is_gnome = xdg_current_desktop.contains("GNOME");

    if !is_gnome {
        return ExtensionStatus { is_gnome: false, is_installed: false, clipboard_requires_extension: false };
    }

    #[cfg(target_os = "linux")]
    let is_wayland = crate::clipboard::is_wayland();
    #[cfg(not(target_os = "linux"))]
    let is_wayland = false;

    // Try D-Bus first (works in Flatpak if permissions are set)
    if let Ok(connection) = zbus::Connection::session().await {
         let proxy_result: zbus::Result<zbus::Proxy> = zbus::Proxy::new(
             &connection,
             "org.gnome.Shell",
             "/org/gnome/Shell",
             "org.gnome.Shell.Extensions"
         ).await;

         if let Ok(proxy) = proxy_result {
              // Method: ListExtensions() -> a{sa{sv}}
              // Returns a map where key is UUID, value is properties
              // Use OwnedValue to avoid lifetime issues with DynamicDeserialize
              let call_result: zbus::Result<std::collections::HashMap<String, std::collections::HashMap<String, zbus::zvariant::OwnedValue>>> = proxy.call("ListExtensions", &()).await;

              if let Ok(extensions) = call_result {
                   let is_installed = extensions.contains_key(EXTENSION_UUID);
                   return ExtensionStatus {
                       is_gnome: true,
                       is_installed,
                       clipboard_requires_extension: is_wayland && !is_installed,
                   };
              }
         }
    }

    // Fallback to File Check (for native builds)
    let is_installed = extension_installed_on_disk();

    ExtensionStatus {
        is_gnome: true,
        is_installed,
        clipboard_requires_extension: is_wayland && !is_installed,
    }
}

/// Installs the ClusterCut GNOME Shell extension into the user's extension
/// directory from the sources embedded in this binary, then arranges for GNOME
/// Shell to load and enable it.
///
/// The extension is what makes clipboard sync work on GNOME Wayland: mutter
/// withholds the clipboard from background apps there, so the bridge has to run
/// inside the compositor. Users on other desktops never see this (the UI only
/// offers it on GNOME — see `check_gnome_extension_status`).
#[tauri::command]
pub(crate) async fn install_gnome_extension(app: AppHandle) -> Result<ExtensionInstallResult, String> {
    #[cfg(target_os = "linux")]
    {
        let result = install_gnome_extension_impl().await?;
        // Reflect the new on-disk state in the UI immediately.
        emit_gnome_extension_state(&app).await;
        Ok(result)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = app;
        Err("The ClusterCut GNOME extension can only be installed on Linux.".to_string())
    }
}

#[cfg(target_os = "linux")]
async fn install_gnome_extension_impl() -> Result<ExtensionInstallResult, String> {
    use std::io::Write;

    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let dest = std::path::Path::new(&home)
        .join(".local/share/gnome-shell/extensions")
        .join(EXTENSION_UUID);
    let icon_dir = dest.join("icons/hicolor/symbolic/apps");

    std::fs::create_dir_all(&icon_dir)
        .map_err(|e| format!("Could not create {}: {e}", dest.display()))?;

    let files: [(&std::path::PathBuf, &str); 3] = [
        (&dest.join("extension.js"), EXTENSION_JS),
        (&dest.join("metadata.json"), EXTENSION_METADATA),
        (&icon_dir.join("clustercut-symbolic.svg"), EXTENSION_ICON),
    ];
    for (path, contents) in files {
        let mut file = std::fs::File::create(path)
            .map_err(|e| format!("Could not write {}: {e}", path.display()))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| format!("Could not write {}: {e}", path.display()))?;
    }

    // Best-effort enable. This succeeds only when GNOME Shell has already
    // scanned this UUID (e.g. reinstalling over a previous session's install),
    // because `enableExtension` returns false for an unknown uuid.
    let mut enabled = false;
    if let Ok(connection) = zbus::Connection::session().await {
        let proxy = zbus::Proxy::new(
            &connection,
            "org.gnome.Shell",
            "/org/gnome/Shell",
            "org.gnome.Shell.Extensions",
        )
        .await;
        if let Ok(proxy) = proxy {
            let call: zbus::Result<bool> = proxy.call("EnableExtension", &(EXTENSION_UUID)).await;
            enabled = matches!(call, Ok(true));
        }
    }

    // For the usual case — a brand-new install the shell has never scanned — the
    // D-Bus enable is impossible, so record the UUID in `enabled-extensions`
    // ourselves. That is the list the shell reads when it next starts, and
    // without it the extension would come up installed but inactive, leaving
    // clipboard sync just as broken after the log out as before it.
    let enabled_at_next_login = enabled || add_uuid_to_enabled_extensions();

    tracing::info!(
        "Installed GNOME extension {EXTENSION_UUID} to {} \
         (enabled now: {enabled}, enabled at next login: {enabled_at_next_login})",
        dest.display()
    );

    Ok(ExtensionInstallResult {
        installed_to: dest.display().to_string(),
        enabled,
        enabled_at_next_login,
    })
}

/// Add our UUID to `org.gnome.shell enabled-extensions` without disturbing the
/// extensions already listed there, so GNOME Shell activates the extension when
/// it next scans the extension directories.
///
/// Uses `gsettings` (a fixed argv — no shell, no user input) because the
/// D-Bus API cannot do this for an unscanned UUID and GSettings has no D-Bus
/// binding to call directly. Returns false if gsettings is unavailable, e.g. in
/// a sandbox without dconf access; the caller then tells the user to enable the
/// extension by hand rather than claiming success.
#[cfg(target_os = "linux")]
fn add_uuid_to_enabled_extensions() -> bool {
    const SCHEMA: &str = "org.gnome.shell";
    const KEY: &str = "enabled-extensions";

    let current = match std::process::Command::new("gsettings")
        .args(["get", SCHEMA, KEY])
        .output()
    {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Ok(out) => {
            tracing::warn!(
                "gsettings get {SCHEMA} {KEY} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return false;
        }
        Err(e) => {
            tracing::warn!("Could not run gsettings to enable the extension: {e}");
            return false;
        }
    };

    if current.contains(EXTENSION_UUID) {
        return true;
    }

    // `gsettings get` yields e.g. "@as []" or "['dash-to-dock@micxgx.gmail.com']".
    // Reuse the existing text verbatim — no parse/re-quote round trip — and just
    // append ours to the array literal.
    let inner = current
        .trim_start_matches("@as")
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();

    let value = if inner.is_empty() {
        format!("['{EXTENSION_UUID}']")
    } else {
        format!("[{inner}, '{EXTENSION_UUID}']")
    };

    match std::process::Command::new("gsettings")
        .args(["set", SCHEMA, KEY, &value])
        .output()
    {
        Ok(out) if out.status.success() => true,
        Ok(out) => {
            tracing::warn!(
                "gsettings set {SCHEMA} {KEY} failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            false
        }
        Err(e) => {
            tracing::warn!("Could not run gsettings to enable the extension: {e}");
            false
        }
    }
}

#[tauri::command]
pub(crate) fn get_launch_args() -> Vec<String> {
    std::env::args().collect()
}

#[tauri::command]
pub(crate) async fn configure_autostart(app_handle: tauri::AppHandle, enable: bool) -> Result<bool, String> {
    // Check if running in Flatpak
    if cfg!(target_os = "linux") && std::env::var("FLATPAK_ID").is_ok() {
        let conn = zbus::Connection::session().await
            .map_err(|e| format!("Failed to connect to session bus: {}", e))?;

        // Build a proxy for the Background portal
        let proxy: zbus::Proxy<'_> = zbus::proxy::Builder::new(&conn)
            .interface("org.freedesktop.portal.Background").unwrap()
            .path("/org/freedesktop/portal/desktop").unwrap()
            .destination("org.freedesktop.portal.Desktop").unwrap()
            .build()
            .await
            .map_err(|e| format!("Failed to create Background portal proxy: {}", e))?;

        // Compute a predictable handle_token from our unique bus name
        let unique_name = conn.unique_name()
            .ok_or("No unique bus name")?
            .as_str()
            .to_string();
        let sender_part = unique_name
            .trim_start_matches(':')
            .replace('.', "_");
        let handle_token = "clustercut_autostart";
        let request_path = format!(
            "/org/freedesktop/portal/desktop/request/{}/{}",
            sender_part, handle_token
        );

        // Subscribe to the Response signal on the request path BEFORE calling the method
        let response_proxy: zbus::Proxy<'_> = zbus::proxy::Builder::new(&conn)
            .interface("org.freedesktop.portal.Request").unwrap()
            .path(request_path.as_str()).unwrap()
            .destination("org.freedesktop.portal.Desktop").unwrap()
            .build()
            .await
            .map_err(|e| format!("Failed to create request proxy: {}", e))?;

        let mut response_stream: zbus::proxy::SignalStream<'_> = response_proxy
            .receive_signal("Response")
            .await
            .map_err(|e| format!("Failed to subscribe to Response signal: {}", e))?;

        // Build the options dict for RequestBackground
        let mut options = std::collections::HashMap::<&str, zbus::zvariant::Value<'_>>::new();
        options.insert("handle_token", zbus::zvariant::Value::from(handle_token));
        options.insert("reason", zbus::zvariant::Value::from(
            "ClusterCut needs to start at login to sync your clipboard across devices."
        ));
        options.insert("autostart", zbus::zvariant::Value::from(enable));
        if enable {
            let cmd: Vec<String> = vec![
                "clustercut".into(),
                "--minimized".into(),
            ];
            options.insert("commandline", zbus::zvariant::Value::from(cmd));
        }

        // Call RequestBackground (parent_window = "")
        proxy.call_method("RequestBackground", &("", options)).await
            .map_err(|e| format!("RequestBackground call failed: {}", e))?;

        // Wait for the Response signal with a 60s timeout
        use futures::StreamExt;
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            response_stream.next(),
        )
        .await
        .map_err(|_| "Portal request timed out — no response within 60 seconds".to_string())?
        .ok_or("Response signal stream ended unexpectedly")?;

        // Parse the response: (uint32 response, dict results)
        let body: zbus::message::Body = response.body();
        let (response_code, _results): (u32, std::collections::HashMap<String, zbus::zvariant::OwnedValue>) = body
            .deserialize()
            .map_err(|e| format!("Failed to deserialize portal response: {}", e))?;

        if response_code == 0 {
            // Approved — persist the state
            let state = app_handle.state::<AppState>();
            {
                let mut settings = state.settings.lock().unwrap();
                settings.flatpak_autostart = enable;
            }
            storage::save_settings(&app_handle, &state.settings.lock().unwrap());
            tracing::info!("Flatpak autostart {} via Background portal", if enable { "enabled" } else { "disabled" });
            Ok(true)
        } else {
            Err(format!("Autostart request was denied by the user (response code: {})", response_code))
        }
    } else {
        Ok(false) // Not handled — let tauri-plugin-autostart handle it
    }
}

#[tauri::command]
pub(crate) async fn get_autostart_state(app_handle: tauri::AppHandle) -> Result<Option<bool>, String> {
    if cfg!(target_os = "linux") && std::env::var("FLATPAK_ID").is_ok() {
        let state = app_handle.state::<AppState>();
        let settings = state.settings.lock().unwrap();
        Ok(Some(settings.flatpak_autostart))
    } else {
        Ok(None)
    }
}

#[tauri::command]
pub(crate) async fn show_native_notification(_app_handle: tauri::AppHandle, title: String, body: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        use windows::UI::Notifications::{ToastNotificationManager, ToastNotification};
        use windows::Data::Xml::Dom::XmlDocument;
        use windows::core::HSTRING;

        let aumid = "app.clustercut.clustercut";

        // Raw XML for Native Actions
        // activationType="protocol" ensures clicking invokes "clustercut://..." which SingleInstance catches.
        let xml = format!(r#"
<toast activationType="protocol" launch="clustercut://action/show">
    <visual>
        <binding template="ToastGeneric">
            <text>{}</text>
            <text>{}</text>
        </binding>
    </visual>
</toast>
"#, title, body);

        let doc = XmlDocument::new().map_err(|e| e.to_string())?;
        doc.LoadXml(&HSTRING::from(&xml)).map_err(|e| e.to_string())?;

        let toast = ToastNotification::CreateToastNotification(&doc).map_err(|e| e.to_string())?;

        // Create Notifier and Show
        let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(aumid))
            .map_err(|e| e.to_string())?;

        notifier.Show(&toast).map_err(|e| e.to_string())?;
    }

    #[cfg(target_os = "linux")]
    {
        use notify_rust::Notification;
        let _ = Notification::new()
            .summary(&title)
            .body(&body)
            .appname("ClusterCut")
            .timeout(notify_rust::Timeout::Milliseconds(5000))
            .show()
            .map_err(|e| e.to_string());
    }

    #[cfg(target_os = "macos")]
    {
        send_notification(&_app_handle, &title, &body, false, None, "history", NotificationPayload::None);
    }

    Ok(())
}
