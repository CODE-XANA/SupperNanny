use crate::state::AppState;
use axum::http::StatusCode;
use std::sync::Arc;
use tokio::task::spawn_blocking;

pub async fn has_permission(
    state: Arc<AppState>,
    user_id: i32,
    permission: &str,
) -> Result<bool, (StatusCode, String)> {
    let state = state.clone();
    let permission = permission.to_string();

    let result = spawn_blocking(move || {
        let mut conn = state.db_pool.get()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB pool error: {e}")))?;

        let row = conn.query_opt(
            r#"
            SELECT 1
            FROM user_roles ur
            JOIN role_permissions rp ON ur.role_id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.permission_id
            WHERE ur.user_id = $1 AND p.permission_name = $2
            "#,
            &[&user_id, &permission],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Query failed: {e}")))?;

        Ok(row.is_some())
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Join error".to_string()))??;

    Ok(result)
}
