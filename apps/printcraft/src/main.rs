//! PrintCraft desktop app.
//!
//! Usage: `printcraft [options] [files…]`
//!
//! View options (applied after the files open; also the seed of the UI control channel):
//! `--page N  --zoom 150  --layout continuous|two-up|single  --panel comments|bookmarks|pages|fields|layers|attachments|none
//!  --theme light|dark  --mode all|read|edit|convert|sign  --tool <catalogue id>  --left open|closed
//!  --organize on  --fields on  --dialog properties|shortcuts|about  --palette <query>  --home on`
//!
//! `--control <file>` enables the UI control channel (off by default): the app listens on a random
//! loopback port and writes `{"port", "token", "pid"}` to `<file>` (owner-only permissions).
//! The token is 256 bits. Supply it with `--control-token-file` / `PRINTCRAFT_CONTROL_TOKEN_FILE`
//! or `--control-token` / `PRINTCRAFT_CONTROL_TOKEN`; otherwise one is generated and stored only
//! in `<file>`. Agents then drive it with `printcraft-cli ui --control <file> <method> …`.
//! See `SECURITY.md`. Stdio MCP (`printcraft-cli mcp`) does not use this token.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

use printcraft_ui_egui::PrintCraftApp;

mod updates;

/// Freedesktop app id: the `.desktop` file name and the hicolor icon name.
const APP_ID: &str = "ai.storyteller.printcraft";

/// The app icon (assets/app-icon/README.md). macOS gets the version on Apple's icon grid, with a
/// transparent margin; Windows and Linux get the full-bleed tile.
#[cfg(target_os = "macos")]
const APP_ICON_PNG: &[u8] = include_bytes!("../../../assets/app-icon/printcraft-1024.png");
#[cfg(not(target_os = "macos"))]
const APP_ICON_PNG: &[u8] = include_bytes!("../../../assets/app-icon/hicolor/256x256/apps/ai.storyteller.printcraft.png");

fn main() -> eframe::Result {
    // Last-resort guard (AGENTS.md §4): commands, edits, opens and saves catch panics and report
    // them; this hook logs every panic, caught or not, with a backtrace when RUST_BACKTRACE is set.
    std::panic::set_hook(Box::new(|info| {
        eprintln!("printcraft: internal error: {info}");
        let trace = std::backtrace::Backtrace::capture();
        if trace.status() == std::backtrace::BacktraceStatus::Captured {
            eprintln!("{trace}");
        }
    }));
    let mut files = Vec::new();
    let mut options: Vec<(String, String)> = Vec::new();
    let mut control_file: Option<String> = None;
    let mut control_token: Option<String> = None;
    let mut control_token_file: Option<String> = None;
    let mut control_usage_error: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--version" => {
                println!("printcraft {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--control" => match args.next() {
                Some(path) => control_file = Some(path),
                None => control_usage_error = Some("--control needs a file path".into()),
            },
            "--control-token" => match args.next() {
                Some(token) => control_token = Some(token),
                None => control_usage_error = Some("--control-token needs 64 hexadecimal characters".into()),
            },
            "--control-token-file" => match args.next() {
                Some(path) => control_token_file = Some(path),
                None => control_usage_error = Some("--control-token-file needs a path".into()),
            },
            flag if flag.starts_with("--") => {
                let value = args.next().unwrap_or_default();
                options.push((flag.trim_start_matches("--").to_string(), value));
            }
            _ => files.push(a),
        }
    }
    let integrated = cfg!(target_os = "macos");
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("PrintCraft")
        .with_inner_size([1440.0, 920.0])
        .with_min_inner_size([820.0, 520.0])
        .with_drag_and_drop(true)
        // Wayland app id: matches packaging/linux/ai.storyteller.printcraft.desktop.
        .with_app_id(APP_ID);
    // Dock, taskbar, Alt-Tab and launcher icon when running unbundled.
    match eframe::icon_data::from_png_bytes(APP_ICON_PNG) {
        Ok(icon) => viewport = viewport.with_icon(icon),
        Err(e) => eprintln!("printcraft: app icon: {e}"),
    }
    if integrated {
        viewport = viewport.with_fullsize_content_view(true).with_titlebar_shown(false).with_title_shown(false);
    }
    // eframe would otherwise derive the settings folder from the app id: keep it under "PrintCraft".
    let persistence_path = eframe::storage_dir("PrintCraft").map(|d| d.join("app.ron"));
    let mut native = eframe::NativeOptions { viewport, persistence_path, ..Default::default() };
    prefer_integrated_gpu(&mut native);
    eframe::run_native(
        "PrintCraft",
        native,
        Box::new(move |cc| {
            let mut app = PrintCraftApp::new();
            if let Some(json) = cc.storage.and_then(|s| s.get_string("printcraft")) {
                app.restore(&json);
            }
            app.integrated_titlebar = integrated;
            app.update_source = Some(std::sync::Arc::new(updates::latest_release));
            app.keychain_ids = cfg!(target_os = "macos");
            if let Some(msg) = &control_usage_error {
                eprintln!("printcraft: {msg}");
            } else if let Some(file) = &control_file {
                let client = app.attach_control(&cc.egui_ctx);
                match control_endpoint(file, control_token.as_deref(), control_token_file.as_deref(), client) {
                    Ok(port) => eprintln!("printcraft: UI control channel on 127.0.0.1:{port} (connection details in {file})"),
                    Err(e) => eprintln!("printcraft: --control {file}: {e}"),
                }
            } else if control_token.is_some() || control_token_file.is_some() {
                eprintln!("printcraft: control token options apply only with --control FILE");
            }
            // Autosave unsaved changes; offer to recover documents a crashed session left behind.
            if let Some(dir) = printcraft_ui_egui::RecoveryStore::default_dir() {
                app.enable_recovery(printcraft_ui_egui::RecoveryStore::new(dir));
            }
            for f in files {
                app.open_path(&f);
            }
            for (k, v) in options {
                if let Err(e) = app.set_option(&k, &v) {
                    eprintln!("printcraft: --{k} {v}: {e}");
                }
            }
            Ok(Box::new(app))
        }),
    )
}

/// Token from the flag, then the environment. Flags win. Neither means "generate".
fn control_token_sources(flag_token: Option<&str>, flag_file: Option<&str>) -> (Option<String>, Option<String>) {
    let token = flag_token.map(str::to_string).or_else(|| std::env::var("PRINTCRAFT_CONTROL_TOKEN").ok().filter(|s| !s.trim().is_empty()));
    let file = flag_file.map(str::to_string).or_else(|| std::env::var("PRINTCRAFT_CONTROL_TOKEN_FILE").ok().filter(|s| !s.trim().is_empty()));
    (token, file)
}

/// Bind loopback control and write `{port, token, pid}` to `file` (mode 0600). The token is not
/// printed. A generated token lives only in that file, or also in `--control-token-file` when
/// that path did not exist yet.
fn control_endpoint(
    file: &str,
    flag_token: Option<&str>,
    flag_file: Option<&str>,
    client: printcraft_ui_egui::control::ControlClient,
) -> std::io::Result<u16> {
    let (supplied, token_file) = control_token_sources(flag_token, flag_file);
    let token = printcraft_ui_egui::control::resolve_server_token(supplied.as_deref(), token_file.as_deref().map(std::path::Path::new))?;
    let ep = printcraft_ui_egui::control::serve_with_token(client, token)?;
    write_control_file(file, ep.port, &ep.token)?;
    Ok(ep.port)
}

/// Write the control endpoint so that only the current user can read the token.
fn write_control_file(path: &str, port: u16, token: &str) -> std::io::Result<()> {
    let json = serde_json::json!({ "port": port, "token": token, "pid": std::process::id() }).to_string();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(json.as_bytes())
}

/// Draw on the integrated GPU unless `WGPU_POWER_PREF` says otherwise. A PDF viewer has no use
/// for a discrete GPU, and on hybrid-graphics laptops (NVIDIA Optimus) the discrete one can lose
/// or corrupt its memory across suspend and screen lock, leaving the window illegible (issue #8).
/// It also saves battery. Machines with one GPU are unaffected.
fn prefer_integrated_gpu(native: &mut eframe::NativeOptions) {
    if std::env::var_os("WGPU_POWER_PREF").is_some() {
        return;
    }
    if let eframe::egui_wgpu::WgpuSetup::CreateNew(setup) = &mut native.wgpu_options.wgpu_setup {
        setup.power_preference = eframe::wgpu::PowerPreference::LowPower;
    }
}
