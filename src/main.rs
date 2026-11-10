#![deny(unsafe_code)]

mod app;
mod auth;
mod config;
mod log;
mod naming;
mod storage;

use config::Config;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

/// Wait for a SIGTERM or Ctrl+C signal, then log and return so the server
/// can drain in-flight requests (and their GCS writes).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    log::info("Shutdown signal received, draining connections", json!({}));
}

fn fail(message: &str) -> ! {
    log::error(message, json!({}));
    std::process::exit(1);
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config =
        Config::from_env().unwrap_or_else(|e| fail(&format!("Invalid configuration: {e}")));

    let store = storage::GcsStore::new(config.bucket.clone(), config.emulator_host.clone())
        .await
        .unwrap_or_else(|e| fail(&e));

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| fail(&format!("Failed to bind to {addr}: {e}")));

    log::info(
        &format!("Listening on {addr}"),
        json!({
            "port": config.port,
            "bucket": config.bucket,
            "path_prefix": if config.path_prefix.is_empty() { "/" } else { &config.path_prefix },
            "methods": config.methods.iter().map(|m| m.as_str()).collect::<Vec<_>>(),
            "auth_mode": config.auth.mode(),
            "emulator": config.emulator_host,
            "version": env!("CARGO_PKG_VERSION"),
        }),
    );

    let state = app::AppState {
        config: Arc::new(config),
        store: Arc::new(store),
    };

    axum::serve(
        listener,
        app::app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap_or_else(|e| fail(&format!("Server error: {e}")));
}
