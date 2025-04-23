use actix_web::{delete, get, post, web, HttpResponse};

use crate::state::AppState;
use super::db;

#[derive(serde::Deserialize)]
struct RoleBody { role_name: String }

#[get("")]
async fn list(state: web::Data<AppState>) -> HttpResponse {
    match db::list(&state.db) {
        Ok(v)  => HttpResponse::Ok().json(v),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[post("")]
async fn create(state: web::Data<AppState>, body: web::Json<RoleBody>) -> HttpResponse {
    let role = db::NewRole { role_name: &body.role_name };
    match db::insert(&state.db, role) {
        Ok(_)  => HttpResponse::Ok().body("Rôle créé"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/{id}")]
async fn remove(state: web::Data<AppState>, path: web::Path<i32>) -> HttpResponse {
    match db::delete(&state.db, path.into_inner()) {
        Ok(_)  => HttpResponse::Ok().body("Rôle supprimé"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// ---------------------- user <-> role ----------------------------------------

#[derive(serde::Deserialize)]
struct AssignRoleBody { user_id: i32, role_id: i32 }

#[post("/assign")]
async fn assign(state: web::Data<AppState>, body: web::Json<AssignRoleBody>) -> HttpResponse {
    match db::assign_role(&state.db, body.user_id, body.role_id) {
        Ok(_)  => HttpResponse::Ok().body("Rôle attribué"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/user/{uid}")]
async fn list_user_roles(state: web::Data<AppState>, path: web::Path<i32>) -> HttpResponse {
    match db::roles_of_user(&state.db, path.into_inner()) {
        Ok(r)  => HttpResponse::Ok().json(r),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/{uid}/{rid}")]
async fn unassign(state: web::Data<AppState>, path: web::Path<(i32, i32)>) -> HttpResponse {
    let (uid, rid) = path.into_inner();
    match db::remove_role(&state.db, uid, rid) {
        Ok(_)  => HttpResponse::Ok().body("Rôle retiré"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// ---------------------- role <-> permission ----------------------------------

#[derive(serde::Deserialize)]
struct PermBody { role_id: i32, permission_id: i32 }

#[post("/perm")]
async fn add_perm(state: web::Data<AppState>, body: web::Json<PermBody>) -> HttpResponse {
    match db::assign_permission(&state.db, body.role_id, body.permission_id) {
        Ok(_)  => HttpResponse::Ok().body("Permission attribuée"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/perm/{rid}/{pid}")]
async fn del_perm(state: web::Data<AppState>, path: web::Path<(i32, i32)>) -> HttpResponse {
    let (rid, pid) = path.into_inner();
    match db::remove_permission(&state.db, rid, pid) {
        Ok(_)  => HttpResponse::Ok().body("Permission retirée"),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/perm/{rid}")]
async fn perms(state: web::Data<AppState>, path: web::Path<i32>) -> HttpResponse {
    match db::permissions_of_role(&state.db, path.into_inner()) {
        Ok(p)  => HttpResponse::Ok().json(p),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

// ---------------------------------------------------------------------------

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/roles")
            .service(list)
            .service(create)
            .service(remove)
            .service(assign)
            .service(list_user_roles)
            .service(unassign)
            .service(add_perm)
            .service(del_perm)
            .service(perms)
    );
}
