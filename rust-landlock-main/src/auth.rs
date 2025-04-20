use anyhow::{Context, Result};
use dialoguer::{Input, Password};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct Role {
    pub role_id: i32,
    pub role_name: String,
}

#[derive(Debug, Deserialize)]
pub struct Policy {
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
    pub allowed_ips: String,
    pub allowed_domains: String,
}

pub struct AuthSession {
    pub jwt: String,
    pub roles: Vec<Role>,
    pub client: Client,
    pub server_url: String,
}

impl AuthSession {
    pub fn login_and_fetch_roles() -> Result<Self> {
        let server_url = std::env::var("SERVER_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:3005".into());

        let username: String = Input::new()
            .with_prompt("Username")
            .interact()
            .context("Failed to read username")?;

        let password: String = Password::new()
            .with_prompt("Password")
            .interact()
            .context("Failed to read password")?;

        let client = Client::new();

        // Step 1: POST /auth/login
        let res = client
            .post(format!("{}/auth/login", server_url))
            .json(&serde_json::json!({ "username": username, "password": password }))
            .send()
            .context("Failed to send login request")?;

        if !res.status().is_success() {
            return Err(anyhow::anyhow!("Authentication failed: {}", res.status()));
        }

        let AuthResponse { token } = res.json().context("Failed to parse auth response")?;

        // Step 2: GET /auth/roles
        let res = client
            .get(format!("{}/auth/roles", server_url))
            .bearer_auth(&token)
            .send()
            .context("Failed to request user roles")?;

        if !res.status().is_success() {
            return Err(anyhow::anyhow!("Role fetch failed: {}", res.status()));
        }

        let roles: Vec<Role> = res.json().context("Failed to parse roles")?;

        Ok(Self {
            jwt: token,
            roles,
            client,
            server_url,
        })
    }

    pub fn fetch_default_policy(&self, role_id: i32) -> Result<Policy> {
        let res = self
            .client
            .get(format!("{}/auth/ruleset?role_id={}", self.server_url, role_id))
            .bearer_auth(&self.jwt)
            .send()
            .context("Failed to request default policy")?;

        if !res.status().is_success() {
            return Err(anyhow::anyhow!(
                "Default policy fetch failed: {}",
                res.status()
            ));
        }

        res.json::<Policy>()
            .context("Failed to parse default policy response")
    }

    pub fn fetch_app_policy(&self, role_id: i32, app_name: &str) -> Result<Policy> {
        let res = self
            .client
            .get(format!(
                "{}/auth/ruleset?role_id={}&app_name={}",
                self.server_url, role_id, app_name
            ))
            .bearer_auth(&self.jwt)
            .send()
            .context("Failed to request app policy")?;

        if !res.status().is_success() {
            return Err(anyhow::anyhow!(
                "App policy fetch failed: {}",
                res.status()
            ));
        }

        res.json::<Policy>()
            .context("Failed to parse app policy response")
    }
}
