use anyhow::Result;
use axum::{
    routing::{get, post},
    Router,
};
use tokio::task::JoinHandle;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

// Declare external modules (files must exist in src/)
#[path = "state.rs"]
mod state;
#[path = "tls.rs"]
mod tls;
#[path = "types.rs"]
mod types;
#[path = "ui.rs"]
mod ui;
#[path = "db.rs"]
mod db;

fn init_tracing() {
    let env = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(env).init();
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    // Initialize SQLite file db.sqlite in CWD
    let conn = rusqlite::Connection::open("db.sqlite")?;
    db::ensure_db(&conn)?;
    // Keep connection around via a global if needed; for simplicity, reopen per op in this build

    // Auto-load TLS config if certs/ exists
    let _ = tls::try_load_from_certs().await;

    // Spawn TLS server
    let tls_task: JoinHandle<Result<()>> = tokio::spawn(async { tls::spawn_tls_server().await });

    // HTTP API & UI
    let app = Router::new()
        .route("/", get(ui::index))
        .route("/api/config", get(ui::get_config).post(ui::update_config))
    .route("/api/certs", get(ui::get_certs_dir))
        .route("/api/generate", post(ui::generate_certs))
    .route("/api/random-ca", post(ui::set_random_ca))
        .route("/api/sessions", get(ui::get_sessions).delete(ui::delete_sessions))
        .route("/api/test", post(ui::run_test_client));

    let http_addr: std::net::SocketAddr = "0.0.0.0:8080".parse().unwrap();
    info!("Web UI listening on http://{}", http_addr);
    let listener = tokio::net::TcpListener::bind(http_addr).await?;
    let http_task = axum::serve(listener, app);

    tokio::select! {
        res = http_task => {
            if let Err(e) = res {
                error!("HTTP server error: {e:#}");
            }
        }
        res = tls_task => {
            if let Err(join_err) = res {
                error!("TLS task join error: {join_err:#}");
            } else if let Ok(Err(run_err)) = res {
                error!("TLS server error: {run_err:#}");
            }
        }
    }

    Ok(())
}
