use axum::{
    extract::{Extension, Json, ConnectInfo},
    http::StatusCode,
};
use bcrypt::verify;
use jsonwebtoken::{encode, EncodingKey, Header};
use std::{
    env,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::task::spawn_blocking;

use crate::{
    auth::jwt::{AuthUser, Claims},
    models::dto::{AuthResponse, LoginRequest},
    models::security_log::SecurityLogEntry,
    state::AppState,
    utils::logger::log_security_event,
};

#[axum::debug_handler]
pub async fn login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    let username = payload.username.clone();
    let password = payload.password.clone();
    let client_ip = Some(addr.ip().to_string());

    let state_clone = state.clone();

    // Spawn blocking verification logic
    let result = spawn_blocking(move || {
        let mut conn = state_clone
            .db_pool
            .get()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB pool error: {e}")))?;

        // Check if user exists
        let row = conn
            .query_opt("SELECT password_hash FROM users WHERE username = $1", &[&username])
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database query error: {e}")))?;

        let password_hash: String = match row {
            Some(row) => row.get(0),
            None => return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string())),
        };

        // Check password
        let valid = verify(&password, &password_hash)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("bcrypt error: {e}")))?;

        if !valid {
            return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()));
        }

        // Create token
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::new(0, 0))
            .as_secs();
        let exp = now + 3600;

        let claims = Claims {
            sub: username.clone(),
            exp: exp as usize,
        };

        let secret =
            env::var("JWT_SECRET").unwrap_or_else(|_| "my_very_secret_key".to_string());

        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Token generation error: {e}"),
                )
            })?;

        Ok::<(String, String), (StatusCode, String)>((username, token))
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Join error: {e}"),
        )
    })?;

    match result {
        Ok((username, token)) => {
            let _ = log_security_event(
                Arc::new(state.clone()),
                SecurityLogEntry {
                    username: Some(username),
                    ip_address: client_ip,
                    action: "successful_login".into(),
                    detail: Some("User logged in".into()),
                    severity: "info".into(),
                },
            )
            .await;

            Ok(Json(AuthResponse { token }))
        }

        Err((status, message)) => {
            let _ = log_security_event(
                Arc::new(state.clone()),
                SecurityLogEntry {
                    username: Some(payload.username.clone()),
                    ip_address: client_ip,
                    action: "failed_login".into(),
                    detail: Some(message.clone()),
                    severity: "warning".into(),
                },
            )
            .await;

            Err((status, message))
        }
    }
}

pub async fn who_am_i(AuthUser { claims }: AuthUser) -> String {
    format!("You are authenticated as: {}", claims.sub)
}
