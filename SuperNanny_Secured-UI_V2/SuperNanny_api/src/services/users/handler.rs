use actix_web::{delete, get, post, web, HttpResponse};
use bcrypt;

use crate::state::AppState;
use crate::admin::Needs;
use crate::admin::jwt::MANAGE_USERS;

use super::db::{self, NewUser};

#[get("")]
async fn list(state: web::Data<AppState>) -> HttpResponse {
    match db::list(&state.db) {
        Ok(vec)  => HttpResponse::Ok().json(vec),
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

#[post("")]
async fn create(state: web::Data<AppState>, body: web::Json<NewUserRequest>) -> HttpResponse {
    let hash = match bcrypt::hash(&body.password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    let new = NewUser { username: &body.username, password_hash: &hash };
    match db::insert(&state.db, new) {
        Ok(_)  => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[delete("/{id}")]
async fn remove(state: web::Data<AppState>, path: web::Path<i32>) -> HttpResponse {
    match db::delete(&state.db, path.into_inner()) {
        Ok(_)  => HttpResponse::Ok().finish(),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[derive(serde::Deserialize)]
struct NewUserRequest {
    username: String,
    password: String,
}

// ---------------------------------------------------------------------------

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .wrap(Needs(MANAGE_USERS))
            .service(list)
            .service(create)
            .service(remove),
    );
}
