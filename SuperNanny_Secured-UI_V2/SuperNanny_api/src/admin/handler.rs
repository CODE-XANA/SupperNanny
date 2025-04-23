use actix_web::{
    cookie::{Cookie, SameSite},
    post,
    web::{self, Data, Json},
    HttpResponse,
};
use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};
use serde::Deserialize;

use crate::{admin::{db, jwt}, state::AppState};

#[derive(Deserialize)]
struct LoginBody { username: String, password: String }

#[post("/admin/login")]
pub async fn login(state: Data<AppState>, body: Json<LoginBody>) -> HttpResponse {
    // 1) récupère admin + permissions
    let (admin, perms) = match db::get_admin_with_perms(&state.db, &body.username) {
        Ok(Some(t)) => t,
        Ok(None)    => return HttpResponse::Unauthorized().body("Unknown user"),
        Err(e)      => return HttpResponse::InternalServerError().body(e.to_string()),
    };

    // 2) vérifie le mot de passe
    let parsed = PasswordHash::new(&admin.password_hash_admin).unwrap();
    if Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed)
        .is_err()
    {
        return HttpResponse::Unauthorized().body("Bad credentials");
    }

    // 3) signe un JWT
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET");
    let ttl    = std::env::var("JWT_TTL_MIN").unwrap_or_else(|_| "60".into()).parse().unwrap_or(60);
    let token  = jwt::sign(admin.user_admin_id, perms, &secret, ttl);

    // 4) cookie HttpOnly
    let cookie = Cookie::build("admin_token", token)
        .http_only(true).secure(false)
        .same_site(SameSite::Strict).path("/")
        .max_age(time::Duration::minutes(ttl))
        .finish();

    HttpResponse::Ok().cookie(cookie).body("Logged in")
}

pub fn config(cfg: &mut web::ServiceConfig) { cfg.service(login); }
