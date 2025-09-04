use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use rcgen::{
    Certificate as RcgenCert, CertificateParams, DistinguishedName, DnType, IsCa, SanType,
};
use rustls::{
    server::{AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient},
    Certificate, PrivateKey, RootCertStore, ServerConfig as RustlsServerConfig,
};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use serde_json::{json, Value, Map as JsonMap};

use crate::state::{add_session, STATE};
use crate::types::{AppConfig, CertSummary, MtlsMode, Session};

// Counting IO wrapper to measure handshake I/O
struct CountingState {
    read: AtomicU64,
    written: AtomicU64,
    enabled: AtomicBool,
}

impl CountingState {
    fn new() -> Arc<Self> {
        Arc::new(Self { read: AtomicU64::new(0), written: AtomicU64::new(0), enabled: AtomicBool::new(true) })
    }
}

struct CountingIo<S> {
    inner: S,
    state: Arc<CountingState>,
}

impl<S> CountingIo<S> {
    fn new(inner: S, state: Arc<CountingState>) -> Self { Self { inner, state } }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for CountingIo<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let p = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &p {
            let after = buf.filled().len();
            let n = (after - before) as u64;
            if self.state.enabled.load(Ordering::Relaxed) && n > 0 {
                self.state.read.fetch_add(n, Ordering::Relaxed);
            }
        }
        p
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for CountingIo<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let p = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &p {
            if self.state.enabled.load(Ordering::Relaxed) && *n > 0 {
                self.state.written.fetch_add(*n as u64, Ordering::Relaxed);
            }
        }
        p
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Parse a server certificate chain and private key from PEM strings.
/// Supports PKCS#8 and RSA private keys.
pub fn parse_server_cert_key(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<Certificate>, PrivateKey)> {
    let mut cert_reader = BufReader::new(Cursor::new(cert_pem.as_bytes()));
    let cert_der = certs(&mut cert_reader).context("parse server certs pem")?;
    if cert_der.is_empty() {
        return Err(anyhow!("no certificates found in server cert pem"));
    }
    let cert_chain: Vec<Certificate> = cert_der.into_iter().map(Certificate).collect();

    // Try PKCS#8, then fall back to RSA.
    let mut key_reader = BufReader::new(Cursor::new(key_pem.as_bytes()));
    let mut keys = pkcs8_private_keys(&mut key_reader).context("parse pkcs8 private key")?;
    let key = if !keys.is_empty() {
        PrivateKey(keys.remove(0))
    } else {
        let mut key_reader = BufReader::new(Cursor::new(key_pem.as_bytes()));
        let mut rsa_keys = rsa_private_keys(&mut key_reader).context("parse rsa private key")?;
        if rsa_keys.is_empty() {
            return Err(anyhow!("no private keys found in server key pem"));
        }
        PrivateKey(rsa_keys.remove(0))
    };

    Ok((cert_chain, key))
}

/// Build a rustls RootCertStore from a PEM bundle.
pub fn parse_root_store_from_pem(ca_pem: &str) -> Result<RootCertStore> {
    let mut reader = BufReader::new(Cursor::new(ca_pem.as_bytes()));
    let ca_der = certs(&mut reader).context("parse CA pem")?;
    if ca_der.is_empty() {
        return Err(anyhow!("no certificates found in CA bundle"));
    }
    let mut store = RootCertStore::empty();
    let (added, _skipped) = store.add_parsable_certificates(&ca_der);
    if added == 0 {
        return Err(anyhow!("failed adding any CA certificates to root store"));
    }
    Ok(store)
}

/// Build a ServerConfig from the provided AppConfig, including mTLS mode.
pub fn build_server_config(cfg: &AppConfig) -> Result<Arc<RustlsServerConfig>> {
    let server_cert_pem = cfg
        .server_cert_pem
        .as_ref()
        .ok_or_else(|| anyhow!("server certificate pem not set"))?;
    let server_key_pem = cfg
        .server_key_pem
        .as_ref()
        .ok_or_else(|| anyhow!("server private key pem not set"))?;

    let (cert_chain, key) = parse_server_cert_key(server_cert_pem, server_key_pem)?;

    let builder = rustls::ServerConfig::builder().with_safe_defaults();

    let mut server_config = match cfg.mtls_mode {
        MtlsMode::Off => builder
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)?,
        MtlsMode::Optional => {
            let ca_pem = cfg
                .client_ca_pem
                .as_ref()
                .ok_or_else(|| anyhow!("client CA pem required for optional mTLS"))?;
            let roots = parse_root_store_from_pem(ca_pem)?;
            let verifier = AllowAnyAnonymousOrAuthenticatedClient::new(roots);
            builder
                .with_client_cert_verifier(Arc::new(verifier))
                .with_single_cert(cert_chain, key)?
        }
        MtlsMode::Required => {
            let ca_pem = cfg
                .client_ca_pem
                .as_ref()
                .ok_or_else(|| anyhow!("client CA pem required for required mTLS"))?;
            let roots = parse_root_store_from_pem(ca_pem)?;
            let verifier = AllowAnyAuthenticatedClient::new(roots);
            builder
                .with_client_cert_verifier(Arc::new(verifier))
                .with_single_cert(cert_chain, key)?
        }
    };

    // Advertise ALPN (for diagnostics; echo server itself is raw TCP).
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(server_config))
}

/// Spawn the TLS echo server on 0.0.0.0:4433 (runs indefinitely).
/// It reads the current TLS server configuration from global state and
/// logs sessions in memory.
pub async fn spawn_tls_server() -> Result<()> {
    let addr: SocketAddr = "0.0.0.0:4433".parse().unwrap();
    let listener = TcpListener::bind(addr).await?;
    info!("TLS echo server listening on {}", addr);

    loop {
    let (tcp, peer) = listener.accept().await?;
        let state_snapshot = {
            let st = STATE.read().await;
            st.server_config.clone()
        };

        let Some(server_config) = state_snapshot else {
            let err = "No server TLS config set. Use /api/generate or /api/config to configure certificates.";
            warn!("{}", err);
            add_session(Session {
                timestamp: Utc::now(),
                peer_addr: Some(peer.to_string()),
                tls_version: None,
                cipher_suite: None,
                alpn: None,
                sni: None,
                client_cert_present: false,
                status: "handshake_error".to_string(),
                error: Some(err.to_string()),
                handshake_read_bytes: None,
                handshake_written_bytes: None,
                details: None,
                client_certs: None,
            })
            .await;
            continue;
        };

        let acceptor = TlsAcceptor::from(server_config);

        tokio::spawn(async move {
            // Wrap stream for handshake counting
            let counters = CountingState::new();
            // Peek ClientHello bytes before wrapping
            let tcp = tcp;
            let mut peek_buf = vec![0u8; 16 * 1024];
            let mut details_map: JsonMap<String, Value> = JsonMap::new();
            let mut non_tls_reported = false;
            match tcp.peek(&mut peek_buf).await {
                Ok(n) if n > 0 => {
                    let sl = &peek_buf[..n];
                    if sl.get(0) != Some(&0x16) { // Not a TLS Handshake record
                        let reason = classify_non_tls(sl);
                        let hex = sl.iter().take(64).map(|b| format!("{:02x}", b)).collect::<String>();
                        details_map.insert("raw_initial_len".to_string(), json!(n));
                        details_map.insert("raw_initial_bytes_hex".to_string(), json!(hex));
                        details_map.insert("non_tls_reason".to_string(), json!(reason));
                        // Record immediately and skip TLS accept
                        add_session(Session {
                            timestamp: Utc::now(),
                            peer_addr: Some(peer.to_string()),
                            tls_version: None,
                            cipher_suite: None,
                            alpn: None,
                            sni: None,
                            client_cert_present: false,
                            client_certs: None,
                            status: "handshake_error".to_string(),
                            error: Some(format!("Non‑TLS traffic on TLS port: {reason}")),
                            handshake_read_bytes: Some(counters.read.load(Ordering::Relaxed)),
                            handshake_written_bytes: Some(counters.written.load(Ordering::Relaxed)),
                            details: Some(Value::Object(details_map.clone())),
                        }).await;
                        non_tls_reported = true;
                    } else if let Ok(ch) = parse_client_hello(sl) {
                        // ch is { client_hello: {...} }
                        if let Some(obj) = ch.as_object() {
                            for (k, v) in obj { details_map.insert(k.clone(), v.clone()); }
                        }
                    }
                    // Always record the raw initial bytes (hex) for diagnostics
                    let hex = sl.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                    details_map.insert("raw_initial_len".to_string(), json!(n));
                    details_map.insert("raw_initial_bytes_hex".to_string(), json!(hex));
                }
                _ => {}
            }
            if non_tls_reported { return; }
            let stream = CountingIo::new(tcp, counters.clone());

            // Perform handshake
            match acceptor.accept(stream).await {
                Ok(mut tls_stream) => {
                    // Stop counting now that handshake finished
                    counters.enabled.store(false, Ordering::Relaxed);

                    // Extract negotiated details
                    let (tls_version, cipher_suite, alpn, sni, client_cert_present, client_certs) = {
                        // For server-side stream, get_ref returns (&IO, &ServerConnection)
                        let (_io, conn) = tls_stream.get_ref();

                        let ver = conn
                            .protocol_version()
                            .map(|v| format!("{:?}", v));
                        let cipher = conn
                            .negotiated_cipher_suite()
                            .map(|cs| format!("{:?}", cs.suite()));
                        let alpn = conn
                            .alpn_protocol()
                            .map(|p| String::from_utf8_lossy(p).to_string());
                        let sni = conn
                            .server_name()
                            .map(|sn| sn.to_string());
                        let peer_chain = conn.peer_certificates().map(|v| v.to_vec()).unwrap_or_default();
                        let has_client = !peer_chain.is_empty();
                        let summaries: Option<Vec<CertSummary>> = if has_client {
                            Some(peer_chain.iter().filter_map(|c| summarize_der_cert(c.0.as_slice()).ok()).collect())
                        } else { None };
                        (ver, cipher, alpn, sni, has_client, summaries)
                    };

                    // Echo loop, and capture plaintext application data (post-handshake)
                    let mut app_total: u64 = 0;
                    let mut app_cap: Vec<u8> = Vec::with_capacity(16 * 1024);
                    let cap_limit: usize = 64 * 1024; // limit capture size to 64KB
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        match tls_stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                app_total += n as u64;
                                // capture up to cap_limit bytes
                                let remaining = cap_limit.saturating_sub(app_cap.len());
                                let take = remaining.min(n);
                                if take > 0 { app_cap.extend_from_slice(&buf[..take]); }
                                if let Err(e) = tls_stream.write_all(&buf[..n]).await {
                                    warn!("Echo write error: {e}");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!("Echo read error: {e}");
                                break;
                            }
                        }
                    }
                    let _ = tls_stream.shutdown().await;

                    // Populate capture details
                    details_map.insert("app_data_total_bytes".to_string(), json!(app_total));
                    if !app_cap.is_empty() {
                        let hex = app_cap.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                        details_map.insert("app_data_preview_hex".to_string(), json!(hex));
                        details_map.insert("app_data_truncated".to_string(), json!(app_cap.len() < app_total as usize));
                    }

                    add_session(Session {
                        timestamp: Utc::now(),
                        peer_addr: Some(peer.to_string()),
                        tls_version,
                        cipher_suite,
                        alpn,
                        sni,
                        client_cert_present,
                        client_certs: client_certs,
                        status: "ok".to_string(),
                        error: None,
                        handshake_read_bytes: Some(counters.read.load(Ordering::Relaxed)),
                        handshake_written_bytes: Some(counters.written.load(Ordering::Relaxed)),
                        details: Some(Value::Object(details_map)),
                    })
                    .await;
                }
                Err(e) => {
                    // Stop counting, log what we observed
                    counters.enabled.store(false, Ordering::Relaxed);
                    add_session(Session {
                        timestamp: Utc::now(),
                        peer_addr: Some(peer.to_string()),
                        tls_version: None,
                        cipher_suite: None,
                        alpn: None,
                        sni: None,
                        client_cert_present: false,
                        client_certs: None,
                        status: "handshake_error".to_string(),
                        error: Some(format!(
                            "{}\nSSL handshake has read {} bytes and written {} bytes",
                            format!("{e:#}"),
                            counters.read.load(Ordering::Relaxed),
                            counters.written.load(Ordering::Relaxed)
                        )),
                        handshake_read_bytes: Some(counters.read.load(Ordering::Relaxed)),
                        handshake_written_bytes: Some(counters.written.load(Ordering::Relaxed)),
                        details: Some(Value::Object(details_map)),
                    })
                    .await;
                }
            }
        });
    }
}

/// Parse ClientHello from raw TLS records using tls-parser to surface offered params
fn parse_client_hello(buf: &[u8]) -> Result<serde_json::Value> {
    fn name_group(id: u16) -> Option<&'static str> {
        match id {
            0x001d => Some("x25519"),
            0x0017 => Some("secp256r1 (P-256)"),
            0x0018 => Some("secp384r1 (P-384)"),
            0x0019 => Some("secp521r1 (P-521)"),
            0x001e => Some("x448"),
            0x0001 => Some("sect163k1"),
            0x0002 => Some("sect163r1"),
            0x0003 => Some("sect163r2"),
            0x0004 => Some("sect193r1"),
            0x0005 => Some("sect193r2"),
            0x0006 => Some("sect233k1"),
            0x0007 => Some("sect233r1"),
            0x0008 => Some("sect239k1"),
            0x0009 => Some("sect283k1"),
            0x000a => Some("sect283r1"),
            0x000b => Some("sect409k1"),
            0x000c => Some("sect409r1"),
            0x000d => Some("sect571k1"),
            0x000e => Some("sect571r1"),
            0x0015 => Some("secp160k1"),
            0x0016 => Some("secp160r1"),
            0x001a => Some("brainpoolP256r1"),
            0x001b => Some("brainpoolP384r1"),
            0x001c => Some("brainpoolP512r1"),
            _ => None,
        }
    }
    fn name_cipher(id: u16) -> Option<&'static str> {
        match id {
            0x1301 => Some("TLS_AES_128_GCM_SHA256 (TLS 1.3)"),
            0x1302 => Some("TLS_AES_256_GCM_SHA384 (TLS 1.3)"),
            0x1303 => Some("TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)"),
            0xC02B => Some("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
            0xC02C => Some("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
            0xC02F => Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            0xC030 => Some("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
            0xCCA8 => Some("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
            0xCCA9 => Some("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
            0x00FF => Some("TLS_EMPTY_RENEGOTIATION_INFO_SCSV"),
            _ => None,
        }
    }
    fn name_sig(id: u16) -> Option<&'static str> {
        match id {
            0x0403 => Some("ecdsa_secp256r1_sha256"),
            0x0503 => Some("ecdsa_secp384r1_sha384"),
            0x0603 => Some("ecdsa_secp521r1_sha512"),
            0x0804 => Some("rsa_pss_rsae_sha256"),
            0x0805 => Some("rsa_pss_rsae_sha384"),
            0x0806 => Some("rsa_pss_rsae_sha512"),
            0x0807 => Some("ed25519"),
            0x0808 => Some("ed448"),
            0x0401 => Some("rsa_pkcs1_sha256"),
            0x0501 => Some("rsa_pkcs1_sha384"),
            0x0601 => Some("rsa_pkcs1_sha512"),
            _ => None,
        }
    }
    fn be16(b: &[u8]) -> Option<u16> { if b.len() >= 2 { Some(u16::from_be_bytes([b[0], b[1]])) } else { None } }
    let mut offered_versions: Vec<String> = vec![];
    let mut ciphers: Vec<String> = vec![];
    let mut alpn: Vec<String> = vec![];
    let mut sni: Option<String> = None;
    let mut sig_algs: Vec<String> = vec![];
    let mut groups: Vec<String> = vec![];

    if buf.len() < 5 || buf[0] != 0x16 { // Handshake record
        return Err(anyhow!("not a TLS handshake record"));
    }
    let rec_len = be16(&buf[3..5]).unwrap_or(0) as usize;
    let mut i = 5;
    let end = std::cmp::min(buf.len(), 5 + rec_len);
    if i + 4 > end { return Err(anyhow!("short handshake")); }
    let hs_typ = buf[i]; i += 1; // 0x01 ClientHello
    if hs_typ != 0x01 { return Err(anyhow!("not a ClientHello")); }
    let hs_len = ((buf[i] as usize) << 16) | ((buf[i+1] as usize) << 8) | (buf[i+2] as usize); i += 3;
    let hs_end = std::cmp::min(end, i + hs_len);
    if i + 2 + 32 + 1 > hs_end { return Err(anyhow!("short ClientHello")); }
    let _legacy_ver = be16(&buf[i..i+2]).unwrap_or(0); i += 2;
    i += 32; // random
    // session id
    let sid_len = buf[i] as usize; i += 1; if i + sid_len > hs_end { return Err(anyhow!("bad session id")); } i += sid_len;
    // cipher suites
    if i + 2 > hs_end { return Err(anyhow!("no cipher suites")); }
    let cs_len = be16(&buf[i..i+2]).unwrap_or(0) as usize; i += 2;
    if i + cs_len > hs_end { return Err(anyhow!("bad cipher suites")); }
    let mut j = 0; while j + 1 < cs_len { let v = be16(&buf[i+j..i+j+2]).unwrap(); if let Some(n) = name_cipher(v) { ciphers.push(n.to_string()); } else { ciphers.push(format!("0x{:04x}", v)); } j += 2; }
    i += cs_len;
    // compression methods
    if i + 1 > hs_end { return Err(anyhow!("no compression methods")); }
    let comp_len = buf[i] as usize; i += 1; if i + comp_len > hs_end { return Err(anyhow!("bad compression methods")); } i += comp_len;
    // extensions
    if i + 2 > hs_end { // no extensions
        return Ok(serde_json::json!({ "client_hello": {"cipher_suites": ciphers} }));
    }
    let ext_total = be16(&buf[i..i+2]).unwrap_or(0) as usize; i += 2;
    if i + ext_total > hs_end { return Err(anyhow!("bad extensions length")); }
    let ext_end = i + ext_total;
    while i + 4 <= ext_end {
        let ext_typ = be16(&buf[i..i+2]).unwrap_or(0); i += 2;
        let ext_len = be16(&buf[i..i+2]).unwrap_or(0) as usize; i += 2;
        if i + ext_len > ext_end { break; }
        let data = &buf[i..i+ext_len];
        match ext_typ {
            0 => { // SNI
                if data.len() >= 2 {
                    let list_len = be16(&data[0..2]).unwrap_or(0) as usize;
                    let mut k = 2;
                    while k + 3 <= data.len() && k < 2 + list_len {
                        let name_typ = data[k]; k += 1;
                        let name_len = be16(&data[k..k+2]).unwrap_or(0) as usize; k += 2;
                        if name_typ == 0 && k + name_len <= data.len() {
                            sni = Some(String::from_utf8_lossy(&data[k..k+name_len]).to_string());
                            break;
                        }
                        k += name_len;
                    }
                }
            }
            16 => { // ALPN
                let mut k = 0;
                // Try to skip 2-byte list length if present
                if data.len() >= 2 { let list_len = be16(&data[0..2]).unwrap_or(0) as usize; if 2 + list_len <= data.len() { k = 2; } }
                while k < data.len() {
                    if k + 1 > data.len() { break; }
                    let l = data[k] as usize; k += 1;
                    if k + l > data.len() { break; }
                    alpn.push(String::from_utf8_lossy(&data[k..k+l]).to_string());
                    k += l;
                }
            }
            43 => { // supported_versions
                if !data.is_empty() {
                    let mut k = 0; let l = data[0] as usize; k += 1;
                    let stop = std::cmp::min(data.len(), 1 + l);
                    while k + 1 < stop {
                        let v = be16(&data[k..k+2]).unwrap(); k += 2;
                        let txt = match v { 0x0301 => "TLS1.0", 0x0302 => "TLS1.1", 0x0303 => "TLS1.2", 0x0304 => "TLS1.3", _ => "unknown" };
                        if txt == "unknown" { offered_versions.push(format!("0x{:04x}", v)); } else { offered_versions.push(txt.to_string()); }
                    }
                }
            }
            13 => { // signature_algorithms
                if data.len() >= 2 { let l = be16(&data[0..2]).unwrap_or(0) as usize; let mut k = 2; let stop = std::cmp::min(data.len(), 2 + l);
                    while k + 1 < stop { let v = be16(&data[k..k+2]).unwrap(); if let Some(n) = name_sig(v) { sig_algs.push(n.to_string()); } else { sig_algs.push(format!("0x{:04x}", v)); } k += 2; }
                }
            }
            10 => { // supported_groups
                if data.len() >= 2 { let l = be16(&data[0..2]).unwrap_or(0) as usize; let mut k = 2; let stop = std::cmp::min(data.len(), 2 + l);
                    while k + 1 < stop { let v = be16(&data[k..k+2]).unwrap(); if let Some(n) = name_group(v) { groups.push(n.to_string()); } else { groups.push(format!("0x{:04x}", v)); } k += 2; }
                }
            }
            51 => { // key_share (collect only group IDs)
                if data.len() >= 2 { let total = be16(&data[0..2]).unwrap_or(0) as usize; let mut k = 2; let stop = std::cmp::min(data.len(), 2 + total);
                    while k + 3 < stop { let grp = be16(&data[k..k+2]).unwrap(); k += 2; let l = be16(&data[k..k+2]).unwrap_or(0) as usize; k += 2; if let Some(n) = name_group(grp) { groups.push(n.to_string()); } else { groups.push(format!("0x{:04x}", grp)); } k = std::cmp::min(stop, k + l); }
                }
            }
            _ => {}
        }
        i += ext_len;
    }

    // Deduplicate groups for readability
    groups.sort();
    groups.dedup();

    Ok(serde_json::json!({
        "client_hello": {
            "offered_versions": offered_versions,
            "cipher_suites": ciphers,
            "alpn": alpn,
            "sni": sni,
            "signature_algorithms": sig_algs,
            "supported_groups": groups,
        }
    }))
}

fn classify_non_tls(bytes: &[u8]) -> &'static str {
    // Simple heuristics for common plaintext protocols
    let prefix = &bytes[..bytes.len().min(8)];
    let is_ascii = prefix.iter().all(|b| b.is_ascii_graphic() || *b == b' ');
    if is_ascii {
        let s = String::from_utf8_lossy(prefix).to_ascii_uppercase();
        if s.starts_with("GET") || s.starts_with("POST") || s.starts_with("HEAD") || s.starts_with("PUT") || s.starts_with("DELETE") || s.starts_with("CONNECT") || s.starts_with("OPTIONS") || s.starts_with("TRACE") || s.starts_with("PRI ") {
            return "looks like HTTP";
        }
        if s.starts_with("SSH-") { return "looks like SSH"; }
        if s.starts_with("SMTP") || s.starts_with("HELO") || s.starts_with("EHLO") { return "looks like SMTP"; }
    }
    "unknown non-TLS"
}

/// Generate a full set of test certificates:
/// - CA certificate (self-signed).
/// - Server certificate/key for CN=localhost (signed by the CA).
/// - Client certificate/key for CN=client (signed by the CA).
/// Returns (ca_pem, server_cert_pem, server_key_pem, client_cert_pem, client_key_pem).
pub fn generate_all() -> Result<(String, String, String, String, String)> {
    // CA
    let mut ca_params = CertificateParams::new(vec![]);
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "mTLS Debug CA");
        dn
    };
    let ca_cert = RcgenCert::from_params(ca_params)?;
    let ca_pem = ca_cert.serialize_pem()?;

    // Server (CN=localhost)
    let mut srv_params = CertificateParams::new(vec!["localhost".into()]);
    srv_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    srv_params
        .subject_alt_names
        .push(SanType::DnsName("localhost".into()));
    srv_params.is_ca = IsCa::NoCa;
    let srv_cert = RcgenCert::from_params(srv_params)?;
    let srv_cert_pem = srv_cert.serialize_pem_with_signer(&ca_cert)?;
    let srv_key_pem = srv_cert.serialize_private_key_pem();

    // Client (CN=client)
    let mut cli_params = CertificateParams::new(vec!["client".into()]);
    cli_params
        .distinguished_name
        .push(DnType::CommonName, "client");
    cli_params.is_ca = IsCa::NoCa;
    let cli_cert = RcgenCert::from_params(cli_params)?;
    let cli_cert_pem = cli_cert.serialize_pem_with_signer(&ca_cert)?;
    let cli_key_pem = cli_cert.serialize_private_key_pem();

    Ok((ca_pem, srv_cert_pem, srv_key_pem, cli_cert_pem, cli_key_pem))
}

fn summarize_der_cert(der: &[u8]) -> Result<CertSummary> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)?;
    let subject = cert.subject().iter_common_name().next()
        .and_then(|cn| cn.as_str().ok()).unwrap_or("(unknown)").to_string();
    let issuer = cert.issuer().iter_common_name().next()
        .and_then(|cn| cn.as_str().ok()).unwrap_or("(unknown)").to_string();
    let not_before = cert.validity().not_before.to_rfc2822().unwrap_or_else(|_| "(n/a)".to_string());
    let not_after = cert.validity().not_after.to_rfc2822().unwrap_or_else(|_| "(n/a)".to_string());
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
        let h = digest(&SHA256, der);
        h.as_ref().iter().map(|b| format!("{:02x}", b)).collect::<String>()
    };
    Ok(CertSummary { subject, issuer, not_before, not_after, sha256, sans })
}

/// On startup, try loading TLS config from ./certs folder.
/// Files checked:
/// - certs/server.crt or certs/server.pem
/// - certs/server.key
/// - optional: certs/ca.pem (if present -> mTLS Required else Off)
pub async fn try_load_from_certs() -> Result<bool> {
    use tokio::fs;
    let server_cert = match fs::read_to_string("certs/server.crt").await {
        Ok(s) => Some(s),
        Err(_) => fs::read_to_string("certs/server.pem").await.ok(),
    };
    let server_key = fs::read_to_string("certs/server.key").await.ok();
    let client_ca = match fs::read_to_string("certs/ca.pem").await {
        Ok(s) => Some(s),
        Err(_) => fs::read_to_string("certs/ca.crt").await.ok(),
    };
    if let (Some(cert), Some(key)) = (server_cert, server_key) {
        let mtls_mode = if client_ca.is_some() { MtlsMode::Required } else { MtlsMode::Off };
        let cfg = AppConfig { mtls_mode, server_cert_pem: Some(cert), server_key_pem: Some(key), client_ca_pem: client_ca.clone() };
        match build_server_config(&cfg) {
            Ok(sc) => {
                let mut st = STATE.write().await;
                st.config = cfg;
                st.server_config = Some(sc);
                // Also try to load previously generated client identity for test client
                if let Ok(cli_cert) = fs::read_to_string("certs/client.crt").await {
                    st.generated_client_cert_pem = Some(cli_cert);
                }
                if let Ok(cli_key) = fs::read_to_string("certs/client.key").await {
                    st.generated_client_key_pem = Some(cli_key);
                }
                if let Some(ca) = client_ca {
                    st.generated_ca_cert_pem = Some(ca);
                }
                Ok(true)
            }
            Err(e) => {
                warn!("Auto-load TLS config from certs failed: {e:#}");
                Ok(false)
            }
        }
    } else {
        Ok(false)
    }
}
