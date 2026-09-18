fn main() {
    // `commands/system.rs` embeds the GNOME extension sources with include_str!,
    // and cargo does not track files outside the crate directory on its own —
    // without these the binary would keep serving a stale extension after an
    // edit under gnome-extension/.
    for path in [
        "../gnome-extension/extension.js",
        "../gnome-extension/metadata.json",
        "../gnome-extension/icons/hicolor/symbolic/apps/clustercut-symbolic.svg",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }

    tauri_build::build()
}
