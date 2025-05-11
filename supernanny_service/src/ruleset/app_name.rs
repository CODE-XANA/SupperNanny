use axum::{extract:: Extension, http::StatusCode, Json};
use crate::{models::policy::{Policy, AppRuleSet}, state::AppState};
use tokio::task::spawn_blocking;

/// Get app policies for a given role_id
pub async fn get_app_rules(
    Extension(state): Extension<AppState>,
    role_id: i32,
) -> Result<Json<Vec<AppRuleSet>>, (StatusCode, String)> {
    let state = state.clone();

    let result = spawn_blocking(move || {
        let mut conn = state
            .db_pool
            .get()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB pool error: {e}")))?;

        let rows = conn
            .query(
                "
                SELECT app_name, default_ro, default_rw, tcp_bind, tcp_connect, allowed_ips, allowed_domains
                FROM app_policy
                WHERE role_id = $1
                ",
                &[&role_id],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Query error: {e}")))?;

        let apps = rows
            .into_iter()
            .map(|row| AppRuleSet {
                app_name: row.get(0),
                policy: Policy {
                    default_ro: row.get(1),
                    default_rw: row.get(2),
                    tcp_bind: row.get(3),
                    tcp_connect: row.get(4),
                    allowed_ips: row.get(5),
                    allowed_domains: row.get(6),
                },
            })
            .collect();

        Ok(apps)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Join error: {e}")))??;

    Ok(Json(result))
}
