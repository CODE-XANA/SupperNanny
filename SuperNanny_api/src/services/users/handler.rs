//! End-points /users (AdminUser).

use actix_web::{delete, get, post, web, HttpResponse};
use bcrypt::hash;
use serde::Deserialize;
use crate::{
    admin::{jwt::MANAGE_USERS, Needs}, services::users::db as users_db, state::AppState
};

/* ------------------------- helpers internes -------------------------------- */

fn bcrypt_hash(pwd: &str) -> Result<String, HttpResponse> {
    hash(pwd, bcrypt::DEFAULT_COST)
        .map_err(|_| HttpResponse::InternalServerError().body("hash error"))
}

/* ----------------------------- handlers ----------------------------------- */

#[get("")]
async fn list(state: web::Data<AppState>) -> HttpResponse {
    match users_db::list(&state.db) {
        Ok(v)  => HttpResponse::Ok().json(v),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/roles")]
async fn roles(state: web::Data<AppState>) -> HttpResponse {
    match users_db::all_roles(&state.db) {
        Ok(v)  => HttpResponse::Ok().json(v),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/* ---- création simple ------------------------------------------------------ */

#[derive(Deserialize)]
struct CreateUserForm {
    username: String,
    password: String,
}

#[post("")]
async fn create(state: web::Data<AppState>, body: web::Json<CreateUserForm>) -> HttpResponse {
    let hash_pwd = match bcrypt_hash(&body.password) {
        Ok(h) => h,
        Err(e) => return e,
    };

    let new = users_db::NewUser {
        username: &body.username,
        password_hash: &hash_pwd,
    };

    match users_db::insert_returning_id(&state.db, new) {
        Ok(uid) => HttpResponse::Ok().json(serde_json::json!({ "user_id": uid })),
        Err(e)  => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/* ---- création + rôle ------------------------------------------------------ */

#[derive(Deserialize)]
struct CreateWithRole {
    username: String,
    password: String,
    role_id:  i32,
}

#[post("/create_with_role")]
async fn create_with_role(
    state: web::Data<AppState>,
    body: web::Json<CreateWithRole>,
) -> HttpResponse {
    let hash_pwd = match bcrypt_hash(&body.password) {
        Ok(h) => h,
        Err(e) => return e,
    };

    let uid = match users_db::insert_returning_id(
        &state.db,
        users_db::NewUser { username: &body.username, password_hash: &hash_pwd },
    ) {
        Ok(id) => id,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    if let Err(e) = users_db::assign_role(&state.db, uid, body.role_id) {
        return HttpResponse::InternalServerError()
            .body(format!("user ok but role assign failed: {e}"));
    }

    HttpResponse::Ok().json(serde_json::json!({ "user_id": uid }))
}

/* ---- suppression et lecture des rôles ------------------------------------ */

#[delete("/{uid}")]
async fn remove(state: web::Data<AppState>, uid: web::Path<i32>) -> HttpResponse {
    match users_db::delete(&state.db, uid.into_inner()) {
        Ok(_)  => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/{uid}/roles")]
async fn user_roles(state: web::Data<AppState>, uid: web::Path<i32>) -> HttpResponse {
    match users_db::roles_of_user(&state.db, uid.into_inner()) {
        Ok(v)  => HttpResponse::Ok().json(v),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/* -------------------------------- scope ----------------------------------- */

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .wrap(Needs(MANAGE_USERS))
            .service(list)
            .service(roles)
            .service(create)
            .service(create_with_role)
            .service(remove)
            .service(user_roles),
    );
}
