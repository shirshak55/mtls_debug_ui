use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// mTLS mode for the server.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MtlsMode {
    Off,
    Optional,
    Required,
}

impl Default for MtlsMode {
    fn default() -> Self {
        MtlsMode::Off
    }
}

impl MtlsMode {
    /// Parse from a string: "off" | "optional" | "required"
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "off" => Some(Self::Off),
            "optional" => Some(Self::Optional),
            "required" => Some(Self::Required),
            _ => None,
        }
    }

    /// Convert to a lowercase string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            MtlsMode::Off => "off",
            MtlsMode::Optional => "optional",
            MtlsMode::Required => "required",
        }
    }
}

/// Complete application configuration (includes sensitive PEMs).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    pub mtls_mode: MtlsMode,
    pub server_cert_pem: Option<String>,
    pub server_key_pem: Option<String>,
    pub client_ca_pem: Option<String>,
}

/// Public configuration view (safe for UI/logs).
#[derive(Debug, Clone, Serialize)]
pub struct PublicConfig {
    pub mtls_mode: &'static str,
    pub has_server_cert: bool,
    pub has_server_key: bool,
    pub has_client_ca: bool,
    // Optional summaries of current certs for UI display
    pub server_cert_summary: Option<CertSummary>,
    pub client_ca_summary: Option<CertSummary>,
}

/// TLS session entry for UI/logs.
#[derive(Debug, Clone, Serialize)]
pub struct Session {
    pub timestamp: DateTime<Utc>,
    pub peer_addr: Option<String>,
    pub tls_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub alpn: Option<String>,
    pub sni: Option<String>,
    pub client_cert_present: bool,
    pub status: String, // "ok" | "handshake_error"
    pub error: Option<String>,
    // Handshake I/O counters
    pub handshake_read_bytes: Option<u64>,
    pub handshake_written_bytes: Option<u64>,
    // Parsed ClientHello and negotiated details
    pub details: Option<serde_json::Value>,
    // Client certificate chain summaries (if presented)
    pub client_certs: Option<Vec<CertSummary>>,
}

/// Payload to update configuration via API.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigUpdate {
    #[serde(default)]
    pub mtls_mode: String,
    #[serde(default)]
    pub server_cert_pem: Option<String>,
    #[serde(default)]
    pub server_key_pem: Option<String>,
    #[serde(default)]
    pub client_ca_pem: Option<String>,
}

/// Response payload for certificate generation API.
#[derive(Debug, Serialize)]
pub struct GenerateResponse {
    pub ca_cert_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub applied: bool,
}

/// Response payload for built-in test client API.
#[derive(Debug, Serialize)]
pub struct TestResponse {
    pub success: bool,
    pub error: Option<String>,
    pub echoed: Option<String>,
    pub tls_info: Option<serde_json::Value>,
}

/// Minimal certificate summary for UI/config inspection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub sha256: String,
    pub sans: Vec<String>,
}

/// Response for GET /api/certs to prefill UI fields from ./certs
#[derive(Debug, Clone, Serialize)]
pub struct CertsResponse {
    pub server_cert_pem: Option<String>,
    pub server_key_pem: Option<String>,
    pub client_ca_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RandomCaResponse {
    pub ca_cert_pem: String,
}
