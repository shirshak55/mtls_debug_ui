use rusqlite::{params, Connection};
use crate::types::Session;

pub fn ensure_db(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            peer_addr TEXT,
            tls_version TEXT,
            cipher_suite TEXT,
            alpn TEXT,
            sni TEXT,
            client_cert_present INTEGER NOT NULL,
            status TEXT NOT NULL,
            error TEXT,
            handshake_read_bytes INTEGER,
            handshake_written_bytes INTEGER,
            details TEXT,
            client_certs TEXT
        );",
    )
}

pub fn insert_session(conn: &Connection, s: &Session) -> rusqlite::Result<()> {
    let details_json = s
        .details
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());
    let client_certs_json = s
        .client_certs
        .as_ref()
        .map(|v| serde_json::to_string(v).unwrap_or_default());
    conn.execute(
        "INSERT INTO sessions (
            ts, peer_addr, tls_version, cipher_suite, alpn, sni, client_cert_present,
            status, error, handshake_read_bytes, handshake_written_bytes, details, client_certs
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            s.timestamp.to_rfc3339(),
            s.peer_addr,
            s.tls_version,
            s.cipher_suite,
            s.alpn,
            s.sni,
            if s.client_cert_present { 1 } else { 0 },
            s.status,
            s.error,
            s.handshake_read_bytes.map(|v| v as i64),
            s.handshake_written_bytes.map(|v| v as i64),
            details_json,
            client_certs_json,
        ],
    )?;
    Ok(())
}

pub fn prune_sessions(conn: &Connection, keep: usize) -> rusqlite::Result<()> {
    // Delete rows older than the newest `keep` entries
    conn.execute(
        &format!(
            "DELETE FROM sessions WHERE id NOT IN (SELECT id FROM sessions ORDER BY id DESC LIMIT {})",
            keep
        ),
        [],
    )?;
    Ok(())
}

pub fn fetch_top_sessions(conn: &Connection, limit: usize) -> rusqlite::Result<Vec<Session>> {
    let mut stmt = conn.prepare(
        "SELECT id, ts, peer_addr, tls_version, cipher_suite, alpn, sni,
                client_cert_present, status, error, handshake_read_bytes, handshake_written_bytes,
                details, client_certs
         FROM sessions ORDER BY id DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map(params![limit as i64], |row| {
        let ts: String = row.get(1)?;
        let details_str: Option<String> = row.get(12)?;
        let client_certs_str: Option<String> = row.get(13)?;
        let parsed_details = details_str
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());
        let parsed_client_certs = client_certs_str
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok());
        Ok(Session {
            timestamp: chrono::DateTime::parse_from_rfc3339(&ts)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
            peer_addr: row.get(2)?,
            tls_version: row.get(3)?,
            cipher_suite: row.get(4)?,
            alpn: row.get(5)?,
            sni: row.get(6)?,
            client_cert_present: {
                let v: i64 = row.get(7)?;
                v != 0
            },
            status: row.get(8)?,
            error: row.get(9)?,
            handshake_read_bytes: row.get::<_, Option<i64>>(10)?.map(|v| v as u64),
            handshake_written_bytes: row.get::<_, Option<i64>>(11)?.map(|v| v as u64),
            details: parsed_details,
            client_certs: parsed_client_certs,
        })
    })?;

    let mut out = Vec::new();
    for r in rows {
        if let Ok(s) = r { out.push(s); }
    }
    Ok(out)
}
