use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthResponse {
    pub token: String,
}

#[derive(Serialize)]
pub struct RoleInfo {
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct LogEventRequest {
    pub hostname: String,
    pub app_name: String,
    pub denied_path: Option<String>,
    pub operation: String,
    pub result: String,
    pub remote_ip: Option<String>,
    pub domain: Option<String>,
}
