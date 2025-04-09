use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde::Serialize;
use std::{env, path::Path};

#[derive(Debug, Serialize)]
pub struct SandboxLogEntry {
    pub app_name: String,
    pub denied_path: String,
    pub operation: String,
    pub result: String,
}

pub fn log_event(
    jwt: &str,
    user_id: i32,
    app_name: &str,
    path: &Path,
    operation: &str,
    result: &str,
) -> Result<()> {
    let log = SandboxLogEntry {
        app_name: app_name.into(),
        denied_path: path.to_string_lossy().into_owned(),
        operation: operation.into(),
        result: result.into(),
    };

    let base_url = env::var("SERVER_URL").unwrap_or_else(|_| "http://127.0.0.1:3005".into());

    let client = Client::new();
    let response = client
        .post(&format!("{}/events/log", base_url))
        .bearer_auth(jwt)
        .json(&log)
        .send()
        .context("Failed to send log to server")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!("Failed to log event: {}", response.status()));
    }

    Ok(())
}
