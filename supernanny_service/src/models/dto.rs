use serde::{Serialize, Deserialize};
use validator::Validate;

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

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct LogEventRequest {
    #[validate(length(min = 1, message = "hostname cannot be empty"))]
    pub hostname: String,

    #[validate(length(min = 1, message = "app_name cannot be empty"))]
    pub app_name: String,

    pub denied_path: Option<String>,

    #[validate(length(min = 1, message = "operation cannot be empty"))]
    pub operation: String,

    #[validate(length(min = 1, message = "result cannot be empty"))]
    pub result: String,

    pub remote_ip: Option<String>,

    pub domain: Option<String>,
}

