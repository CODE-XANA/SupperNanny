use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityLogEntry {
    pub username: Option<String>,
    pub ip_address: Option<String>,
    pub action: String,
    pub detail: Option<String>,
    pub severity: String, // "info", "warning", "critical"
}
