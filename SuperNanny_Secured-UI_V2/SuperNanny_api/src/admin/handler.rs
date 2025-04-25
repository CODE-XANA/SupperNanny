use actix_web::{
    cookie::{Cookie, SameSite},
    get, post,
    web::{self, Data, Json},
    HttpResponse,
};
use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};
use serde::Deserialize;

use crate::{
    admin::{db, jwt},
    state::{AppState, JWT_BLACKLIST},
};

#[derive(Deserialize)]
struct LoginBody { username: String, password: String }

#[post("/admin/login")]
pub async fn login(state: Data<AppState>, body: Json<LoginBody>, req: actix_web::HttpRequest) -> HttpResponse {
    use crate::state::{now, LOGIN_ATTEMPTS};

    // 0) IP de la requête
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    // 1) Vérifie/compte les tentatives
    {
        let mut map = LOGIN_ATTEMPTS.lock().unwrap();
        let entry = map.entry(ip.clone()).or_insert((0, now() + 600));
        if now() > entry.1 {
            // fenêtre expirée → on repart à zéro
            *entry = (0, now() + 600);
        }
        if entry.0 >= 5 {
            // trop de tentatives dans la fenêtre
            return HttpResponse::TooManyRequests()
                .body("Trop de tentatives, réessayez dans quelques minutes.");
        }
        // on incrémente **provisoirement** ; si auth réussit, on remettra à 0
        entry.0 += 1;
    }

    // 2) récupère admin + permissions
    let (admin, perms) = match db::get_admin_with_perms(&state.db, &body.username) {
        Ok(Some(t)) => t,
        _ => {
            // compte comme tentative ratée
            return HttpResponse::Unauthorized().body("Bad credentials");
        }
    };

    // 3) vérifie mot de passe
    let parsed = PasswordHash::new(&admin.password_hash_admin).unwrap();
    if Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed)
        .is_err()
    {
        return HttpResponse::Unauthorized().body("Bad credentials");
    }

    // 4) Auth OK → on remet le compteur IP à 0
    LOGIN_ATTEMPTS.lock().unwrap().remove(&ip);

    // 5) signe JWT
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET");
    let ttl    = std::env::var("JWT_TTL_MIN").unwrap_or_else(|_| "60".into()).parse().unwrap_or(60);
    let token  = jwt::sign(admin.user_admin_id, perms, &secret, ttl);

    // 6) set-cookie
    let cookie = Cookie::build("admin_token", token)
        .http_only(true).secure(false)
        .same_site(SameSite::Strict).path("/")
        .max_age(time::Duration::minutes(ttl))
        .finish();

    HttpResponse::Ok().cookie(cookie).body("Logged in")
}


#[get("/admin/logout")]
pub async fn logout(req: actix_web::HttpRequest) -> HttpResponse {
    // 1) le cookie doit exister
    let Some(cookie) = req.cookie("admin_token") else {
        return HttpResponse::Unauthorized().finish();
    };

    // 2) vérifie le token → récupère jti
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET");
    let claims = match jwt::verify(cookie.value(), &secret) {
        Ok(c) => c,
        Err(_) => return HttpResponse::Unauthorized().finish(),
    };

    // 3) ajoute le jti à la black-list
    JWT_BLACKLIST.lock().unwrap().insert(claims.jti);

    // 4) renvoie un cookie expiré
    let expired = Cookie::build("admin_token", "")
        .http_only(true).secure(false)
        .same_site(SameSite::Strict)
        .path("/").max_age(time::Duration::seconds(0)).finish();

    HttpResponse::Ok().cookie(expired).body("Logged out")
}

pub fn config(cfg: &mut web::ServiceConfig) { 
    cfg.service(login).service(logout); 
}
