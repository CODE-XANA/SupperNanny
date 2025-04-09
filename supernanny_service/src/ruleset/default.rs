use axum::{extract:: Extension, http::StatusCode, Json};
use crate::{models::policy::Policy, state::AppState};
use tokio::task::spawn_blocking;

/// Get default policies for a given role_id
pub async fn get_default_rules(
    Extension(state): Extension<AppState>,
    role_id: i32,
) -> Result<Json<Vec<Policy>>, (StatusCode, String)> {
    let state = state.clone();

    let result = spawn_blocking(move || {
        let mut conn = state
            .db_pool
            .get()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB pool error: {e}")))?;

        let rows = conn
            .query(
                "
                SELECT default_ro, default_rw, tcp_bind, tcp_connect, allowed_ips, allowed_domains
                FROM default_policies
                WHERE role_id = $1
                ",
                &[&role_id],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Query error: {e}")))?;

        let policies = rows
            .into_iter()
            .map(|row| Policy {
                default_ro: row.get(0),
                default_rw: row.get(1),
                tcp_bind: row.get(2),
                tcp_connect: row.get(3),
                allowed_ips: row.get(4),
                allowed_domains: row.get(5),
            })
            .collect();

        Ok(policies)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Join error: {e}")))??;

    Ok(Json(result))
}
