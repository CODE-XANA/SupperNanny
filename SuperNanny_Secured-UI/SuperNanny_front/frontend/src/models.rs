use serde::{Serialize, Deserialize};

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct AppPolicy {
    pub app_name: String,
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SandboxEvent {
    pub event_id: i32,
    pub timestamp: String,
    pub hostname: String,
    pub app_name: String,
    pub denied_path: Option<String>,
    pub operation: String,
    pub result: String,
}