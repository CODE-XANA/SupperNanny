use axum::{extract::{Extension, Json}, http::StatusCode};
use bcrypt::verify;
use jsonwebtoken::{encode, EncodingKey, Header};
use std::{env, time::{SystemTime, UNIX_EPOCH, Duration}};
use tokio::task::spawn_blocking;

use crate::{
    state::AppState,
    auth::jwt::{Claims, AuthUser},
    models::dto::{LoginRequest, AuthResponse},
};

#[axum::debug_handler]
pub async fn login(
    Extension(state): Extension<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    let username = payload.username.clone();
    let password = payload.password.clone();
    let state = state.clone();

    let token_result = spawn_blocking(move || {
        let mut conn = state.db_pool.get()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB pool error: {e}")))?;

        let row = conn.query_opt("SELECT password_hash FROM users WHERE username = $1", &[&username])
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Database query error: {e}")))?;

        let password_hash: String = match row {
            Some(row) => row.get(0),
            None => return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string())),
        };

        let valid = verify(&password, &password_hash)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("bcrypt error: {e}")))?;
        if !valid {
            return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::new(0, 0))
            .as_secs();
        let exp = now + 3600;

        let claims = Claims { sub: username, exp: exp as usize };
        let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "my_very_secret_key".to_string());

        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Token generation error: {e}")))?;

        Ok(token)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Join error: {e}")))??;

    Ok(Json(AuthResponse { token: token_result }))
}

pub async fn who_am_i(AuthUser { claims }: AuthUser) -> String {
    format!("You are authenticated as: {}", claims.sub)
}
