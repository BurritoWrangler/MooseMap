// Prevents an extra console window on Windows in release. No effect elsewhere.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sqlx=warn".into()),
        )
        .init();

    if let Err(e) = moosemap_desktop_lib::run() {
        eprintln!("MooseMap failed to start: {e:#}");
        std::process::exit(1);
    }
}
