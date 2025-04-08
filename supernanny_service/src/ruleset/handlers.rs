use axum::{extract::Extension, Json, http::StatusCode};
use crate::{
    auth::jwt::AuthUser,
    state::AppState,
    models::policy::{Policy, AppRuleSet, RuleSetResponse},
};
use tokio::task::spawn_blocking;

pub async fn get_ruleset(
    AuthUser { claims }: AuthUser,
    Extension(state): Extension<AppState>,
) -> Result<Json<RuleSetResponse>, (StatusCode, String)> {
    let username = claims.sub;
    let state = state.clone();

    let result = spawn_blocking(move || {
        let mut conn = state.db_pool.get()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB pool error: {e}")))?;

        let role_rows = conn.query(
            "
            SELECT r.role_id
            FROM users u
            JOIN user_roles ur ON u.user_id = ur.user_id
            JOIN roles r ON ur.role_id = r.role_id
            WHERE u.username = $1
            ",
            &[&username],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Role query error: {e}")))?;

        let role_ids: Vec<i32> = role_rows.iter().map(|row| row.get(0)).collect();

        let mut default_policies = Vec::new();
        for role_id in &role_ids {
            let rows = conn.query(
                "
                SELECT default_ro, default_rw, tcp_bind, tcp_connect, allowed_ips, allowed_domains
                FROM default_policies
                WHERE role_id = $1
                ",
                &[role_id],
            ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Default policy query error: {e}")))?;

            for row in rows {
                default_policies.push(Policy {
                    default_ro: row.get(0),
                    default_rw: row.get(1),
                    tcp_bind: row.get(2),
                    tcp_connect: row.get(3),
                    allowed_ips: row.get(4),
                    allowed_domains: row.get(5),
                });
            }
        }

        let mut app_policies = Vec::new();
        for role_id in &role_ids {
            let rows = conn.query(
                "
                SELECT app_name, default_ro, default_rw, tcp_bind, tcp_connect, allowed_ips, allowed_domains
                FROM app_policy
                WHERE role_id = $1
                ",
                &[role_id],
            ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("App policy query error: {e}")))?;

            for row in rows {
                app_policies.push(AppRuleSet {
                    app_name: row.get(0),
                    policy: Policy {
                        default_ro: row.get(1),
                        default_rw: row.get(2),
                        tcp_bind: row.get(3),
                        tcp_connect: row.get(4),
                        allowed_ips: row.get(5),
                        allowed_domains: row.get(6),
                    },
                });
            }
        }

        Ok(RuleSetResponse {
            default_policies,
            app_policies,
        })
    })
    .await
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Join error".to_string()))??;

    Ok(Json(result))
}
