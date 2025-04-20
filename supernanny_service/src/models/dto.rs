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

#[derive(Debug, Deserialize)]
pub struct AppPolicyCreateRequest {
    pub app_name: String,
    pub role_id: i32,
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
    pub allowed_ips: String,
    pub allowed_domains: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PolicyChangeRequest {
    pub app_name: String,
    pub role_id: i32,
    pub default_ro: String,       
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
    pub allowed_ips: String,      
    pub allowed_domains: String,  
    pub allowed_ro_paths: Vec<String>,     
    pub allowed_rw_paths: Vec<String>,     
    pub change_justification: String,
}



#[derive(Serialize, Deserialize)]
pub struct PolicyRequestDetail {
    pub request_id: i32,
    pub app_name: String,
    pub role_id: i32,
    pub role_name: String,
    pub requested_by: String,
    pub requested_at: String,
    pub status: String,
    pub default_ro: bool,
    pub default_rw: bool,
    pub tcp_bind: bool,
    pub tcp_connect: bool,
    pub allowed_ips: Vec<String>,         
    pub allowed_domains: Vec<String>,     
    pub change_justification: String,
}


#[derive(Deserialize)]
pub struct PolicyRequestDecision {
    pub approve: bool,
    pub reason: Option<String>,
}