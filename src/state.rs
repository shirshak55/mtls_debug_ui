use std::sync::Arc;

use once_cell::sync::Lazy;
use rustls::ServerConfig;
use tokio::sync::RwLock;
use tracing::warn;

use crate::types::{AppConfig, Session};
use crate::db;

/// Capacity for in-memory session logs.
/// Oldest entries are pruned when this capacity is exceeded.
const SESSIONS_CAP: usize = 1000;

/// Shared, mutable application state protected by an async RwLock.
/// This keeps configuration, built TLS server config, and recent TLS sessions.
pub struct SharedState {
    pub config: AppConfig,
    pub server_config: Option<Arc<ServerConfig>>,
    pub sessions: Vec<Session>,
    // Last generated client identity (for /api/test)
    pub generated_client_cert_pem: Option<String>,
    pub generated_client_key_pem: Option<String>,
    pub generated_ca_cert_pem: Option<String>,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            config: AppConfig::default(),
            server_config: None,
            sessions: Vec::with_capacity(256),
            generated_client_cert_pem: None,
            generated_client_key_pem: None,
            generated_ca_cert_pem: None,
        }
    }
}

/// Global state instance.
pub static STATE: Lazy<RwLock<SharedState>> = Lazy::new(|| RwLock::new(SharedState::default()));

/// Append a session log entry and prune to `SESSIONS_CAP`.
pub async fn add_session(s: Session) {
    // Update in-memory log
    let mut st = STATE.write().await;
    st.sessions.push(s.clone());
    if st.sessions.len() > SESSIONS_CAP {
        let overflow = st.sessions.len() - SESSIONS_CAP;
        st.sessions.drain(0..overflow);
    }

    // Also persist top history in SQLite (top 10 kept)
    let to_store = s;
    tokio::spawn(async move {
        if let Err(e) = tokio::task::spawn_blocking(move || {
            let conn = rusqlite::Connection::open("db.sqlite")?;
            db::ensure_db(&conn)?;
            db::insert_session(&conn, &to_store)?;
            db::prune_sessions(&conn, 10)?;
            Ok::<(), rusqlite::Error>(())
        })
    .await
    .unwrap_or(Err(rusqlite::Error::ExecuteReturnedResults))
        {
            warn!("SQLite persist failed: {}", e);
        }
    });
}
