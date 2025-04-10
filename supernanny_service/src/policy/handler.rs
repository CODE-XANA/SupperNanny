use axum::{
    extract::{Extension, Json},
    http::StatusCode,
};
use std::sync::Arc;

use crate::{
    auth::jwt::AuthUser,
    models::dto::AppPolicyCreateRequest,
    state::AppState,
    utils::permissions::has_permission,
};
use tokio::task::spawn_blocking;

pub async fn add_app_policy(
    AuthUser { claims }: AuthUser,
    Extension(state): Extension<AppState>,
    Json(body): Json<AppPolicyCreateRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    if !has_permission(Arc::new(state.clone()), claims.user_id, "manage_policies").await? {
        return Err((StatusCode::FORBIDDEN, "Permission denied".to_string()));
    }

    let state = state.clone();
    spawn_blocking(move || {
        let mut conn = state.db_pool.get()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        conn.execute(
            "
            INSERT INTO app_policy (
                app_name, role_id, default_ro, default_rw, tcp_bind, tcp_connect,
                allowed_ips, allowed_domains, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            ON CONFLICT (app_name, role_id)
            DO UPDATE SET
                default_ro = EXCLUDED.default_ro,
                default_rw = EXCLUDED.default_rw,
                tcp_bind = EXCLUDED.tcp_bind,
                tcp_connect = EXCLUDED.tcp_connect,
                allowed_ips = EXCLUDED.allowed_ips,
                allowed_domains = EXCLUDED.allowed_domains,
                updated_at = NOW()
            ",
            &[
                &body.app_name,
                &body.role_id,
                &body.default_ro,
                &body.default_rw,
                &body.tcp_bind,
                &body.tcp_connect,
                &body.allowed_ips,
                &body.allowed_domains,
            ],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Insert error: {e}")))?;

        Ok(())
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Join error".to_string()))??;

    Ok(StatusCode::CREATED)
}
