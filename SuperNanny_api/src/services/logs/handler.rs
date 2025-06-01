use actix_web::{get, web, HttpResponse};
use crate::{state::AppState, services::logs::db};
use crate::admin::{Needs, jwt::VIEW_EVENTS};
use crate::admin::csrf::Csrf;

#[get("/security")]
async fn security_logs(state: web::Data<AppState>) -> HttpResponse {
    match db::last_10(&state.db) {
        Ok(rows) => HttpResponse::Ok().json(rows),
        Err(e)   => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/logs")
            .wrap(Csrf)
            .wrap(Needs(VIEW_EVENTS))
            .service(security_logs)
    );
}
