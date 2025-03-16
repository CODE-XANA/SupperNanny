use serde::Deserialize;

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct AppPolicy {
    pub app_name: String,
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
    pub updated_at: String, // Adapter le type si nécessaire (ex: chrono::NaiveDateTime ou String)
}
