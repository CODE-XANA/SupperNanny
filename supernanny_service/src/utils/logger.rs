use crate::models::security_log::SecurityLogEntry;
use crate::state::AppState;
use std::sync::Arc;
use tokio::task::spawn_blocking;
use axum::http::StatusCode;

pub async fn log_security_event(
    state: Arc<AppState>,
    log: SecurityLogEntry,
) -> Result<(), (StatusCode, String)> {
    spawn_blocking(move || {
        let mut conn = state.db_pool.get()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB pool error: {e}")))?;

        conn.execute(
            "
            INSERT INTO security_logs (username, ip_address, action, detail, severity)
            VALUES ($1, $2, $3, $4, $5)
            ",
            &[
                &log.username,
                &log.ip_address,
                &log.action,
                &log.detail,
                &log.severity,
            ],
        ).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Insert error: {e}")))?;

        Ok(())
    }).await.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Join error".into()))?
}
