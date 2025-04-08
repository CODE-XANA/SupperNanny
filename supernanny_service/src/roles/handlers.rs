use axum::{extract::Extension, Json, http::StatusCode};
use crate::{
    auth::jwt::AuthUser,
    state::AppState,
    models::dto::RoleInfo,
};
use tokio::task::spawn_blocking;

pub async fn get_roles(
    AuthUser { claims }: AuthUser,
    Extension(state): Extension<AppState>,
) -> Result<Json<RoleInfo>, (StatusCode, String)> {
    let username = claims.sub;
    let state = state.clone();

    let result = spawn_blocking(move || {
        let mut conn = state.db_pool.get()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB pool error: {e}")))?;

        let rows = conn.query(
            "
            SELECT r.role_name, p.permission_name
            FROM users u
            JOIN user_roles ur ON u.user_id = ur.user_id
            JOIN roles r ON ur.role_id = r.role_id
            JOIN role_permissions rp ON r.role_id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.permission_id
            WHERE u.username = $1
            ",
            &[&username],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Query error: {e}")))?;

        let mut roles = Vec::new();
        let mut permissions = Vec::new();

        for row in rows {
            let role: String = row.get(0);
            let permission: String = row.get(1);
            if !roles.contains(&role) { roles.push(role); }
            if !permissions.contains(&permission) { permissions.push(permission); }
        }

        Ok(RoleInfo { roles, permissions })
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Blocking task failed".to_string()))??;

    Ok(Json(result))
}
