use axum::{
    extract::{Extension, Json},
    http::StatusCode,
};
use crate::{
    auth::jwt::AuthUser,
    models::dto::LogEventRequest,
    state::AppState,
};

use validator::Validate;

pub async fn log_event(
    AuthUser { claims }: AuthUser,
    Extension(state): Extension<AppState>,
    Json(payload): Json<LogEventRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if let Err(validation_errors) = payload.validate() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Validation failed: {validation_errors}"),
        ));
    }

    let username = claims.sub;
    let state = state.clone();

    tokio::task::spawn_blocking(move || {
        let mut conn = state.db_pool.get()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB pool error: {e}")))?;

        let user_id: Option<i32> = conn.query_opt(
            "SELECT user_id FROM users WHERE username = $1",
            &[&username],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("User ID lookup failed: {e}")))?
        .map(|row| row.get(0));

        conn.execute(
            "
            INSERT INTO sandbox_events (
                hostname, app_name, denied_path, operation, result,
                user_id, remote_ip, domain, timestamp
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            ",
            &[
                &payload.hostname,
                &payload.app_name,
                &payload.denied_path,
                &payload.operation,
                &payload.result,
                &user_id,
                &payload.remote_ip,
                &payload.domain,
            ],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Insert failed: {e}")))?;

        Ok(())
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Join error".to_string()))??;

    Ok(StatusCode::CREATED)
}
