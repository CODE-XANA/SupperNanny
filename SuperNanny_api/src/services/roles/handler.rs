//! End-points /roles (AdminRole).

use actix_web::{delete, get, post, put, web, HttpResponse};
use serde::Deserialize;
use crate::{
    admin::{jwt::MANAGE_ROLES, Needs}, admin::csrf::Csrf, services::{roles::db as roles_db, users::db as users_db}, state::AppState
};

/* -------------------------------------------------------------------------- */
/*                                   CRUD                                     */
/* -------------------------------------------------------------------------- */

#[get("")]
async fn list(state: web::Data<AppState>) -> HttpResponse {
    match roles_db::list(&state.db) {
        Ok(v)  => HttpResponse::Ok().json(v),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[derive(Deserialize)]
struct NewRoleForm { role_name: String }

#[post("")]
async fn create(state: web::Data<AppState>, body: web::Json<NewRoleForm>) -> HttpResponse {
    match roles_db::insert(&state.db, roles_db::NewRole { role_name: &body.role_name }) {
        Ok(id) => HttpResponse::Ok().json(serde_json::json!({ "role_id": id })),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/{rid}")]
async fn remove(state: web::Data<AppState>, rid: web::Path<i32>) -> HttpResponse {
    match roles_db::delete(&state.db, rid.into_inner()) {
        Ok(_)  => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/* -------------------- rôles d’un user ------------------------------------- */

#[get("/user/{uid}")]
async fn list_user_roles(state: web::Data<AppState>, uid: web::Path<i32>) -> HttpResponse {
    match users_db::roles_of_user(&state.db, uid.into_inner()) {
        Ok(v)  => HttpResponse::Ok().json(v),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/* -------------------- default policies ------------------------------------ */

#[get("/default_policies/{rid}")]
async fn get_default(state: web::Data<AppState>, rid: web::Path<i32>) -> HttpResponse {
    match roles_db::get_default_policy(&state.db, rid.into_inner()) {
        Ok(Some(p)) => HttpResponse::Ok().json(p),
        Ok(None)    => HttpResponse::NotFound().finish(),
        Err(e)      => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("/default_policies")]
async fn create_default(
    state: web::Data<AppState>,
    body: web::Json<roles_db::NewDefaultPolicy>,
) -> HttpResponse {
    match roles_db::create_default_policy(&state.db, body.into_inner()) {
        Ok(_)  => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[put("/default_policies/{rid}")]
async fn update_default(
    state: web::Data<AppState>,
    rid: web::Path<i32>,
    body: web::Json<roles_db::DefaultPolicyPatch>,
) -> HttpResponse {
    match roles_db::update_default_policy(&state.db, rid.into_inner(), body.into_inner()) {
        Ok(_)  => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/* ---- création rôle + policies en une fois -------------------------------- */

#[derive(Deserialize)]
struct RoleWithPolicy {
    role_name:       String,
    default_ro:      String,
    default_rw:      String,
    tcp_bind:        String,
    tcp_connect:     String,
    allowed_ips:     String,
    allowed_domains: String,
}

#[post("/create_with_default")]
async fn create_with_default(
    state: web::Data<AppState>,
    body: web::Json<RoleWithPolicy>,
) -> HttpResponse {
    let dto = body.into_inner();

    let rid = match roles_db::insert(&state.db, roles_db::NewRole { role_name: &dto.role_name }) {
        Ok(id) => id,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let np = roles_db::NewDefaultPolicy {
        role_id:        rid,
        default_ro:     dto.default_ro,
        default_rw:     dto.default_rw,
        tcp_bind:       dto.tcp_bind,
        tcp_connect:    dto.tcp_connect,
        allowed_ips:    dto.allowed_ips,
        allowed_domains:dto.allowed_domains,
    };

    if let Err(e) = roles_db::create_default_policy(&state.db, np) {
        return HttpResponse::InternalServerError()
            .body(format!("role created but policies failed: {e}"));
    }

    HttpResponse::Ok().json(serde_json::json!({ "role_id": rid }))
}

/* -------------------------------------------------------------------------- */
/*                                    scope                                   */
/* -------------------------------------------------------------------------- */

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/roles")
            .wrap(Csrf)
            .wrap(Needs(MANAGE_ROLES))
            .service(list)
            .service(create)
            .service(remove)
            .service(list_user_roles)
            // default policies
            .service(get_default)
            .service(create_default)
            .service(update_default)
            // one-shot rôle + policies
            .service(create_with_default),
    );
}
