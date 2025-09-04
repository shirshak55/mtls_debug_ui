use std::io::{BufReader, Cursor};
use std::sync::Arc;

use anyhow::anyhow;
use axum::{http::StatusCode, response::Html, Json};
use std::fs;
use rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::certs;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tracing::warn;

use crate::state::STATE;
use crate::tls::{
    build_server_config, generate_all, parse_root_store_from_pem, parse_server_cert_key,
};
use crate::types::{
    AppConfig, CertSummary, CertsResponse, ConfigUpdate, GenerateResponse, MtlsMode, PublicConfig, TestResponse, RandomCaResponse,
};

fn summarize_pem_chain(pem: &str) -> Option<CertSummary> {
    let mut reader = BufReader::new(Cursor::new(pem.as_bytes()));
    let der = certs(&mut reader).ok()?;
    if der.is_empty() { return None; }
    let leaf = &der[0];
    let (_, cert) = x509_parser::parse_x509_certificate(leaf).ok()?;
    let subject = cert.subject().iter_common_name().next()
        .and_then(|cn| cn.as_str().ok()).unwrap_or("(unknown)").to_string();
    let issuer = cert.issuer().iter_common_name().next()
        .and_then(|cn| cn.as_str().ok()).unwrap_or("(unknown)").to_string();
    let not_before = cert.validity().not_before
        .to_rfc2822()
        .unwrap_or_else(|_| "(n/a)".to_string());
    let not_after = cert.validity().not_after
        .to_rfc2822()
        .unwrap_or_else(|_| "(n/a)".to_string());
    let sans = cert.extensions().iter().find_map(|ext| {
        use x509_parser::extensions::ParsedExtension;
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => Some(
                san.general_names.iter().map(|gn| gn.to_string()).collect::<Vec<_>>()
            ),
            _ => None,
        }
    }).unwrap_or_default();
    let sha256 = {
        use ring::digest::{digest, SHA256};
        let h = digest(&SHA256, leaf);
        h.as_ref().iter().map(|b| format!("{:02x}", b)).collect::<String>()
    };
    Some(CertSummary { subject, issuer, not_before, not_after, sha256, sans })
}

#[cfg(feature = "embed-ui")]
const EMBED_INDEX_HTML: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/index.html"));

#[cfg(not(feature = "embed-ui"))]
const EMBED_INDEX_HTML: &str = r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>mTLS Debug Server</title>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 2rem; color: #111; }
    .card { border: 1px solid #ddd; padding: 1rem; border-radius: .5rem; margin-bottom: 1rem; }
    pre { background: #f6f8fa; padding: 1rem; overflow: auto; }
  </style>
</head>
<body>
  <h1>mTLS Debug Server</h1>
  <div class="card">
    You are viewing a minimal embedded UI. To use the full UI:
    <ol>
      <li>Create assets/index.html</li>
      <li>Build with the "embed-ui" feature enabled</li>
      <li>Rebuild the project</li>
    </ol>
  </div>
  <div class="card">
    API quick links:
    <ul>
      <li><a href="/api/config">GET /api/config</a></li>
      <li><a href="/api/sessions">GET /api/sessions</a></li>
    </ul>
  </div>
</body>
</html>
"#;

/// GET /
pub async fn index() -> Html<String> {
    // Prefer runtime assets/index.html if present (enables Tailwind UI without embed feature)
    let runtime_path = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/index.html");
    let html = fs::read_to_string(runtime_path).unwrap_or_else(|_| EMBED_INDEX_HTML.to_string());
    Html(html)
}

/// GET /api/config
pub async fn get_config() -> Json<PublicConfig> {
    let st = STATE.read().await;
    let pcfg = PublicConfig {
        mtls_mode: st.config.mtls_mode.as_str(),
        has_server_cert: st
            .config
            .server_cert_pem
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        has_server_key: st
            .config
            .server_key_pem
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        has_client_ca: st
            .config
            .client_ca_pem
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        server_cert_summary: st.config.server_cert_pem.as_ref().and_then(|p| summarize_pem_chain(p)),
        client_ca_summary: st.config.client_ca_pem.as_ref().and_then(|p| summarize_pem_chain(p)),
    };
    Json(pcfg)
}

/// POST /api/config
pub async fn update_config(
    Json(update): Json<ConfigUpdate>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut st = STATE.write().await;

    let mut cfg = st.config.clone();
    if let Some(m) = MtlsMode::from_str(update.mtls_mode.as_str()) {
        cfg.mtls_mode = m;
    }

    if let Some(cert) = update.server_cert_pem {
        if !cert.trim().is_empty() {
            cfg.server_cert_pem = Some(cert);
        }
    }
    if let Some(key) = update.server_key_pem {
        if !key.trim().is_empty() {
            cfg.server_key_pem = Some(key);
        }
    }
    if let Some(ca) = update.client_ca_pem {
        if !ca.trim().is_empty() {
            cfg.client_ca_pem = Some(ca);
        }
    }

    match build_server_config(&cfg) {
        Ok(sc) => {
            st.config = cfg;
            st.server_config = Some(sc);
            (StatusCode::OK, Json(json!({ "status": "ok" })))
        }
        Err(e) => {
            warn!("Config update failed: {e:#}");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "status": "error", "error": format!("{e:#}") })),
            )
        }
    }
}

/// POST /api/generate
pub async fn generate_certs() -> (StatusCode, Json<GenerateResponse>) {
    match generate_all() {
        Ok((ca_pem, srv_cert_pem, srv_key_pem, cli_cert_pem, cli_key_pem)) => {
            // Save to ./certs
            let _ = std::fs::create_dir_all("certs");
            let _ = std::fs::write("certs/ca.pem", &ca_pem);
            let _ = std::fs::write("certs/server.crt", &srv_cert_pem);
            let _ = std::fs::write("certs/server.key", &srv_key_pem);
            let _ = std::fs::write("certs/client.crt", &cli_cert_pem);
            let _ = std::fs::write("certs/client.key", &cli_key_pem);

            // Apply config (mTLS required with generated CA)
            let new_cfg = AppConfig {
                mtls_mode: MtlsMode::Required,
                server_cert_pem: Some(srv_cert_pem.clone()),
                server_key_pem: Some(srv_key_pem.clone()),
                client_ca_pem: Some(ca_pem.clone()),
            };
            let applied = match build_server_config(&new_cfg) {
                Ok(sc) => {
                    let mut st = STATE.write().await;
                    st.config = new_cfg;
                    st.server_config = Some(sc);
                    st.generated_client_cert_pem = Some(cli_cert_pem.clone());
                    st.generated_client_key_pem = Some(cli_key_pem.clone());
                    st.generated_ca_cert_pem = Some(ca_pem.clone());
                    true
                }
                Err(e) => {
                    warn!("Failed to apply generated config: {e:#}");
                    false
                }
            };

            let resp = GenerateResponse {
                ca_cert_pem: ca_pem,
                server_cert_pem: srv_cert_pem,
                server_key_pem: srv_key_pem,
                client_cert_pem: cli_cert_pem,
                client_key_pem: cli_key_pem,
                applied,
            };
            (StatusCode::OK, Json(resp))
        }
        Err(e) => {
            warn!("Generate certs failed: {e:#}");
            let resp = GenerateResponse {
                ca_cert_pem: String::new(),
                server_cert_pem: String::new(),
                server_key_pem: String::new(),
                client_cert_pem: String::new(),
                client_key_pem: String::new(),
                applied: false,
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(resp))
        }
    }
}

/// POST /api/random-ca - generate a random CA and set it as client CA only
pub async fn set_random_ca() -> (StatusCode, Json<RandomCaResponse>) {
    // Reuse rcgen to make a CA cert
    let mut ca_params = rcgen::CertificateParams::new(vec![]);
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Random Debug CA");
    let ca = match rcgen::Certificate::from_params(ca_params) {
        Ok(c) => c,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(RandomCaResponse { ca_cert_pem: String::new() })),
    };
    let ca_pem = ca.serialize_pem().unwrap_or_default();
    let _ = std::fs::create_dir_all("certs");
    let _ = std::fs::write("certs/ca.pem", &ca_pem);
    // Update config with CA only (do not alter existing server cert/key)
    let mut st = STATE.write().await;
    st.config.client_ca_pem = Some(ca_pem.clone());
    // Try to rebuild server config if possible
    if let Ok(sc) = build_server_config(&st.config) {
        st.server_config = Some(sc);
    }
    (StatusCode::OK, Json(RandomCaResponse { ca_cert_pem: ca_pem }))
}

/// GET /api/sessions
pub async fn get_sessions() -> Json<Vec<crate::types::Session>> {
    // Prefer SQLite top 10 if available; fall back to memory
    let rows = tokio::task::spawn_blocking(|| {
        let conn = rusqlite::Connection::open("db.sqlite").ok()?;
        crate::db::ensure_db(&conn).ok()?;
        crate::db::fetch_top_sessions(&conn, 10).ok()
    })
    .await
    .ok()
    .flatten();
    if let Some(list) = rows {
        // rows are already ordered by id DESC (newest first)
        Json(list)
    } else {
        let st = STATE.read().await;
        // ensure newest first from in-memory ring
        let mut v: Vec<_> = st.sessions.clone();
        if v.len() > 10 { v = v.split_off(v.len().saturating_sub(10)); }
        v.reverse();
        Json(v)
    }
}

/// DELETE /api/sessions - clear all stored sessions (DB and memory)
pub async fn delete_sessions() -> (StatusCode, Json<serde_json::Value>) {
    let db_res = tokio::task::spawn_blocking(|| {
        let conn = rusqlite::Connection::open("db.sqlite")?;
        crate::db::ensure_db(&conn)?;
        conn.execute("DELETE FROM sessions", [])?;
        Ok::<(), rusqlite::Error>(())
    }).await;
    // Clear in-memory regardless of DB outcome
    {
        let mut st = STATE.write().await;
        st.sessions.clear();
    }
    match db_res {
        Ok(Ok(())) => (StatusCode::OK, Json(json!({"status":"ok"}))),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"status":"error"}))),
    }
}

/// GET /api/certs - read PEMs from ./certs to prefill UI fields
pub async fn get_certs_dir() -> Json<CertsResponse> {
    let read_file = |p: &str| -> Option<String> {
        std::fs::read_to_string(p).ok().filter(|s| !s.trim().is_empty())
    };
    Json(CertsResponse {
        server_cert_pem: read_file("certs/server.crt").or_else(|| read_file("certs/server.pem")),
        server_key_pem: read_file("certs/server.key"),
        client_ca_pem: read_file("certs/ca.pem").or_else(|| read_file("certs/ca.crt")),
    })
}

/// POST /api/test
pub async fn run_test_client() -> (StatusCode, Json<TestResponse>) {
    // Snapshot current state
    let (st_cfg, mut client_cert_pem, mut client_key_pem) = {
        let st = STATE.read().await;
        (
            st.config.clone(),
            st.generated_client_cert_pem.clone(),
            st.generated_client_key_pem.clone(),
        )
    };

    // If missing in state, try loading from ./certs
    if client_cert_pem.is_none() || client_key_pem.is_none() {
        if let Ok(cc) = std::fs::read_to_string("certs/client.crt") { if !cc.trim().is_empty() { client_cert_pem = Some(cc); } }
        if let Ok(ck) = std::fs::read_to_string("certs/client.key") { if !ck.trim().is_empty() { client_key_pem = Some(ck); } }
    }

    // Build a client config that trusts either the CA (preferred) or the server cert
    let client_work = async {
    let mut root_store = RootCertStore::empty();

        if let Some(ca_pem) = st_cfg.client_ca_pem.as_ref() {
            let store = parse_root_store_from_pem(ca_pem)?;
            root_store = store;
        } else if let Some(srv_cert_pem) = st_cfg.server_cert_pem.as_ref() {
            let mut reader = BufReader::new(Cursor::new(srv_cert_pem.as_bytes()));
            let cert_der = certs(&mut reader)?;
            if cert_der.is_empty() {
                return Err(anyhow!("no server certs available for client trust"));
            }
            let (added, _) = root_store.add_parsable_certificates(&cert_der);
            if added == 0 {
                return Err(anyhow!("failed to add server cert to client root store"));
            }
        } else {
            return Err(anyhow!("no trust anchors available"));
        }

        // Build ClientConfig
        let client_config = if let (Some(cc_pem), Some(ck_pem)) =
            (client_cert_pem.as_ref(), client_key_pem.as_ref())
        {
            // Use client auth if we have generated client identity
            let (chain, key) = parse_server_cert_key(cc_pem, ck_pem)?;
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_client_auth_cert(chain, key)?
        } else {
            ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(client_config));
        let server_name = rustls::ServerName::try_from("localhost")
            .or_else(|_| rustls::ServerName::try_from("127.0.0.1"))?;

        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", 4433)).await?;
        let mut stream = connector.connect(server_name, tcp).await?;

        // Roundtrip
        let msg = b"ping";
        stream.write_all(msg).await?;
        stream.flush().await?;
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?;
        let echoed = String::from_utf8_lossy(&buf).to_string();

        Ok::<(String, serde_json::Value), anyhow::Error>((
            echoed,
            json!({ "note": "TLS details omitted in this build for compatibility." }),
        ))
    }
    .await;

    match client_work {
        Ok((echoed, tls_info)) => (
            StatusCode::OK,
            Json(TestResponse {
                success: true,
                error: None,
                echoed: Some(echoed),
                tls_info: Some(tls_info),
            }),
        ),
        Err(e) => (
            StatusCode::OK,
            Json(TestResponse {
                success: false,
                error: Some(format!("{e:#}")),
                echoed: None,
                tls_info: None,
            }),
        ),
    }
}
