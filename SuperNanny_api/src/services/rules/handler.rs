use actix_web::{delete, get, post, put, web, HttpResponse};

use crate::state::AppState;
use super::db;
use serde::Deserialize;
use crate::admin::Needs;
use crate::admin::jwt::MANAGE_RULES;
use crate::admin::csrf::Csrf;

// ---------------- app_policy -----------------------------------

#[get("/envs")]
async fn envs(state: web::Data<AppState>) -> HttpResponse {
    match db::list_envs(&state.db) {
        Ok(v)  => HttpResponse::Ok().json(v),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/env/{name}")]
async fn env_by_name(state: web::Data<AppState>, name: web::Path<String>) -> HttpResponse {
    match db::by_name(&state.db, &name) {
        Ok(Some(p)) => HttpResponse::Ok().json(p),
        Ok(None)    => HttpResponse::NotFound().finish(),
        Err(e)      => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/env_id/{pid}")]
async fn env_by_id(state: web::Data<AppState>, pid: web::Path<i32>) -> HttpResponse {
    match db::by_id(&state.db, pid.into_inner()) {
        Ok(Some(p)) => HttpResponse::Ok().json(p),
        Ok(None)    => HttpResponse::NotFound().finish(),
        Err(e)      => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[derive(serde::Deserialize)]
struct EnvBody {
    app_name: String, role_id: i32,
    default_ro: String, default_rw: String,
    tcp_bind: String, tcp_connect: String,
    allowed_ips: String, allowed_domains: String,
}

#[post("/env")]
async fn create_env(state: web::Data<AppState>, body: web::Json<EnvBody>) -> HttpResponse {
    let p = db::NewAppPolicy {
        app_name: &body.app_name,
        role_id: body.role_id,
        default_ro: &body.default_ro,
        default_rw: &body.default_rw,
        tcp_bind: &body.tcp_bind,
        tcp_connect: &body.tcp_connect,
        allowed_ips: &body.allowed_ips,
        allowed_domains: &body.allowed_domains,
    };
    match db::insert_env(&state.db, p) {
        Ok(_)  => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[derive(Deserialize)]
pub struct EnvPatch {
    #[serde(default)]
    pub ll_fs_ro:      Vec<String>,
    #[serde(default)]
    pub ll_fs_rw:      Vec<String>,
    #[serde(default)]
    pub ll_tcp_bind:   Option<String>,
    #[serde(default)]
    pub ll_tcp_connect:Option<String>,
    #[serde(default)]
    pub allowed_ips:   Option<String>,
    #[serde(default)]
    pub allowed_domains:Option<String>,
}


#[put("/env_id/{pid}")]
async fn update_env(state: web::Data<AppState>, pid: web::Path<i32>, body: web::Json<EnvPatch>) -> HttpResponse {
    let ro  = body.ll_fs_ro.join(":");
    let rw  = body.ll_fs_rw.join(":");
    let tcp_b = body.ll_tcp_bind.clone().unwrap_or_else(|| "9418".into());
    let tcp_c = body.ll_tcp_connect.clone().unwrap_or_else(|| "80:443".into());
    let ips = body.allowed_ips.clone().unwrap_or_default();
    let dom = body.allowed_domains.clone().unwrap_or_default();

    match db::update_env(&state.db, pid.into_inner(), &ro, &rw, &tcp_b, &tcp_c, &ips, &dom) {
        Ok(_)  => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/env_id/{pid}")]
async fn delete_env(state: web::Data<AppState>, pid: web::Path<i32>) -> HttpResponse {
    match db::delete_env(&state.db, pid.into_inner()) {
        Ok(true)  => HttpResponse::Ok().body("Supprimé"),
        Ok(false) => HttpResponse::NotFound().finish(),
        Err(e)    => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// ---------------------------------------------------------------------------

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/rules")
        .wrap(Csrf)
        .wrap(Needs(MANAGE_RULES))
        .service(envs)
        .service(env_by_name)
        .service(env_by_id)
        .service(create_env)
        .service(update_env)
        .service(delete_env)
    );
}
