use std::sync::Arc;

use anyhow::Context;
use gatekeeper::config::Config;
use gatekeeper::detector::Detector;
use gatekeeper::proxy::{ProxyState, router, upstream_client};
use gatekeeper::storage::MappingStore;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = Config::from_env().context("invalid Gatekeeper configuration")?;
    let detector = Arc::new(Detector::default().with_redactions(&config.redactions));
    let mut state = ProxyState::new(
        config.target_url,
        upstream_client().context("failed to build upstream HTTP client")?,
        detector,
        config.max_body_bytes,
        config.upstream_auth,
    );
    if let Some(path) = &config.storage.path {
        let store = MappingStore::open(path).context("failed to open persistent mapping store")?;
        state = state.with_storage(Arc::new(store));
    }
    if let Some(token) = &config.storage.client_token {
        state = state.with_client_token(token);
    }
    let app = router(state);
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.listen_addr))?;

    tracing::info!(address = %config.listen_addr, "gatekeeper listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server failed")
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
