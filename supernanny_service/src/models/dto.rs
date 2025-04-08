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
