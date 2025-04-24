use actix_web::{post, web, HttpResponse};
use notify_rust::Notification;
use serde_json::Value;

use crate::{
    admin::{Needs, jwt::MANAGE_ROLES},
    state::AppState,
};
use crate::services::logs::db;

#[post("/alert")]
pub async fn alert(_state: web::Data<AppState>, payload: web::Json<Value>) -> HttpResponse {
    let summary = payload.get("annotations")
        .and_then(|a| a.get("summary"))
        .and_then(|v| v.as_str())
        .unwrap_or("Trop de logs 'denied' détectés dans la dernière minute !");

    if let Err(e) = Notification::new()
        .summary("Alerte Grafana")
        .body(summary)
        .icon("dialog-warning")
        .show()
    {
        return HttpResponse::InternalServerError().body(e.to_string());
    }

    // optional persistence
    #[cfg(feature = "persist_logs")]
    {
        let _ = crate::services::logs::db::insert(&state.db,
            crate::services::logs::db::NewLogEntry { level: "WARN", message: summary });
    }

    HttpResponse::Ok().finish()
}

// ---------------------------------------------------------------------------

pub fn config(cfg: &mut web::ServiceConfig) { cfg.service(alert); }
