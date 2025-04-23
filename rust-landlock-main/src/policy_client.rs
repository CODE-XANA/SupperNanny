use anyhow::{Context, Result};
use reqwest::blocking::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize)]
pub struct RuleSetRaw {
    #[serde(default)]
    pub default_ro: String,
    #[serde(default)]
    pub default_rw: String,
    #[serde(default)]
    pub tcp_bind: String,
    #[serde(default)]
    pub tcp_connect: String,
    #[serde(default)]
    pub allowed_ips: String,
    #[serde(default)]
    pub allowed_domains: String,
}

#[derive(Debug)]
pub struct RuleSet {
    pub ro_paths: HashSet<PathBuf>,
    pub rw_paths: HashSet<PathBuf>,
    pub tcp_bind: HashSet<u16>,
    pub tcp_connect: HashSet<u16>,
    pub allowed_ips: HashSet<String>,
    pub allowed_domains: HashSet<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginResponse {
    pub token: String,
}


#[derive(Debug, Serialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
pub struct User {
    pub username: String,
    pub permissions: Vec<String>,
}

impl User {
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }
}

// Helper function to create a consistent HTTPS client
fn create_https_client() -> Result<Client> {
    ClientBuilder::new()
        .danger_accept_invalid_certs(true) // Remove in production with valid certs
        .build()
        .context("Failed to build HTTPS client")
}

impl RuleSet {
    pub fn fetch_for_app(app: &str, token: &str) -> Result<Self> {
        let base_url = env::var("SERVER_URL")
            .unwrap_or_else(|_| "https://127.0.0.1:8443".to_string());
        let url = format!("{}/auth/ruleset?app_name={}", base_url, app);

        let client = create_https_client()?;
        let res = client
            .get(&url)
            .bearer_auth(token)
            .send()
            .context("Failed to GET app ruleset")?;

        if !res.status().is_success() {
            return Err(anyhow::anyhow!("Error fetching app ruleset: {}", res.status()));
        }

        let body = res.text().context("Failed to get response body")?;
        let json_value: serde_json::Value = serde_json::from_str(&body)
            .context("Failed to parse response as JSON")?;
        
        // Look for app-specific policy in app_policies array
        if let Some(app_policies) = json_value.get("app_policies") {
            if let Some(policies) = app_policies.as_array() {
                for policy in policies {
                    if let (Some(policy_app_name), Some(policy_data)) = (
                        policy.get("app_name").and_then(|v| v.as_str()),
                        policy.get("policy")
                    ) {
                        if policy_app_name == app {
                            println!("Found specific policy for app: {}", app);
                            return Self::parse_policy_object(policy_data);
                        }
                    }
                }
            }
        }
        
        // If no app-specific policy found, use the first default policy
        if let Some(default_policies) = json_value.get("default_policies") {
            if let Some(policies) = default_policies.as_array() {
                if !policies.is_empty() {
                    println!("Using default policy for app: {}", app);
                    return Self::parse_policy_object(&policies[0]);
                }
            }
        }
        
        // If no policy found at all, return empty ruleset
        println!("No policy found for app: {}, using empty policy", app);
        Ok(Self::default())
    }

    fn parse_policy_object(policy_obj: &serde_json::Value) -> Result<Self> {
        let mut ruleset = Self::default();
        
        if let Some(paths) = policy_obj.get("default_ro").and_then(|v| v.as_str()) {
            ruleset.ro_paths = split_paths(paths);
        }
        
        if let Some(paths) = policy_obj.get("default_rw").and_then(|v| v.as_str()) {
            ruleset.rw_paths = split_paths(paths);
        }
        
        if let Some(ports) = policy_obj.get("tcp_bind").and_then(|v| v.as_str()) {
            ruleset.tcp_bind = split_ports(ports);
        }
        
        if let Some(ports) = policy_obj.get("tcp_connect").and_then(|v| v.as_str()) {
            ruleset.tcp_connect = split_ports(ports);
        }
        
        if let Some(ips) = policy_obj.get("allowed_ips").and_then(|v| v.as_str()) {
            ruleset.allowed_ips = split_list(ips);
        }
        
        if let Some(domains) = policy_obj.get("allowed_domains").and_then(|v| v.as_str()) {
            ruleset.allowed_domains = split_list(domains);
        }
        
        Ok(ruleset)
    }

    pub fn upload(app: &str, ruleset_raw: &RuleSetRaw, token: &str) -> Result<()> {
        let base_url = env::var("SERVER_URL")
            .unwrap_or_else(|_| "https://127.0.0.1:8443".to_string());
        let url = format!("{}/auth/ruleset?app_name={}", base_url, app);

        let client = create_https_client()?;
        let res = client
            .post(&url)
            .bearer_auth(token)
            .json(ruleset_raw)
            .send()
            .context("Failed to POST ruleset update")?;

        if !res.status().is_success() {
            return Err(anyhow::anyhow!("Error uploading ruleset: {}", res.status()));
        }

        Ok(())
    }

    pub fn login(username: &str, password: &str) -> Result<(String, User)> {
        let base_url = env::var("SERVER_URL")
            .unwrap_or_else(|_| "https://127.0.0.1:8443".to_string());
        let login_url = format!("{}/auth/login", base_url);
    
        let client = create_https_client()?;
        let login_request = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        };
    
        let res = client
            .post(&login_url)
            .json(&login_request)
            .send()
            .context("Failed to authenticate with server")?;
    
        if !res.status().is_success() {
            return Err(anyhow::anyhow!("Authentication failed: {}", res.status()));
        }
    
        let login_response: LoginResponse = res.json()
            .context("Failed to parse authentication response")?;
        
        // Now fetch user roles and permissions
        let roles_url = format!("{}/auth/roles", base_url);
        let roles_res = client
            .get(&roles_url)
            .bearer_auth(&login_response.token)
            .send()
            .context("Failed to fetch user roles")?;
            
        if !roles_res.status().is_success() {
            return Err(anyhow::anyhow!("Failed to get user roles: {}", roles_res.status()));
        }
        
        let roles_data: serde_json::Value = roles_res.json()
            .context("Failed to parse roles response")?;
        
        let permissions = if let Some(perms) = roles_data.get("permissions").and_then(|p| p.as_array()) {
            perms.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else {
            Vec::new()
        };
        
        let user = User {
            username: username.to_string(),
            permissions,
        };
    
        Ok((login_response.token, user))
    }
    
}

impl Default for RuleSet {
    fn default() -> Self {
        Self {
            ro_paths: HashSet::new(),
            rw_paths: HashSet::new(),
            tcp_bind: HashSet::new(),
            tcp_connect: HashSet::new(),
            allowed_ips: HashSet::new(),
            allowed_domains: HashSet::new(),
        }
    }
}

// Helpers
fn split_paths(s: &str) -> HashSet<PathBuf> {
    s.split(':').filter(|s| !s.is_empty()).map(PathBuf::from).collect()
}

fn split_ports(s: &str) -> HashSet<u16> {
    s.split(':').filter_map(|s| s.parse().ok()).collect()
}

fn split_list(s: &str) -> HashSet<String> {
    s.split(':').filter(|s| !s.is_empty()).map(str::to_string).collect()
}

pub fn log_denial_event(
    app_name: &str,
    denied_path: &str,
    operation: &str,
    token: &str,
) -> Result<()> {
    let base_url = env::var("SERVER_URL")
        .unwrap_or_else(|_| "https://127.0.0.1:8443".to_string());
    let url = format!("{}/events/log", base_url);

    let hostname = hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let client = create_https_client()?;
    let event = serde_json::json!({
        "hostname": hostname,
        "app_name": app_name,
        "denied_path": denied_path,
        "operation": operation,
        "result": "denied",
        "remote_ip": "127.0.0.1",
        "domain": "localhost"             
    });

    let res = client
        .post(&url)
        .bearer_auth(token)
        .json(&event)
        .send()
        .context("Failed to send denial event")?;

    if !res.status().is_success() {
        eprintln!("Warning: Failed to log denial event: {}", res.status());
    }

    Ok(())
}