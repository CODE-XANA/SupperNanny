//! End‑points publics : /admin/login  /admin/logout  et /admin/me

use actix_web::{
    cookie::{Cookie, SameSite},
    get, post,
    web::{self, Data, Json},
    HttpRequest, HttpResponse,
};
use argon2::{password_hash::PasswordHash, Argon2, PasswordVerifier};
use serde::{Deserialize, Serialize};

use crate::{
    admin::{db, jwt},
    state::{AppState, JWT_BLACKLIST, now, LOGIN_ATTEMPTS},
    utils::crypto,
};

/* -------------------------------------------------------------------------- */
/* ----------------------------- /admin/login --------------------------------*/
/* -------------------------------------------------------------------------- */

#[derive(Deserialize)]
struct LoginBody {
    username: String,
    password: String,
}

#[post("/admin/login")]
pub async fn login(
    state: Data<AppState>,
    body: Json<LoginBody>,
    req: HttpRequest,
) -> HttpResponse {
    // 0) IP
    let ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    // 1) tentative rate‑limit
    {
        let mut map = LOGIN_ATTEMPTS.lock().unwrap();
        let entry = map.entry(ip.clone()).or_insert((0, now() + 600));
        if now() > entry.1 {
            *entry = (0, now() + 600);
        }
        if entry.0 >= 5 {
            return HttpResponse::TooManyRequests()
                .body("Trop de tentatives, réessayez dans quelques minutes.");
        }
        entry.0 += 1;
    }

    // 2) récupère admin + perms
    let (admin, perms) = match db::get_admin_with_perms(&state.db, &body.username) {
        Ok(Some(t)) => t,
        _ => return HttpResponse::Unauthorized().body("Bad credentials"),
    };

    // 3) vérifie mot de passe
    let parsed = PasswordHash::new(&admin.password_hash_admin).unwrap();
    if Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed)
        .is_err()
    {
        return HttpResponse::Unauthorized().body("Bad credentials");
    }

    // 4) reset compteur
    LOGIN_ATTEMPTS.lock().unwrap().remove(&ip);

    // 5) JWT
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET");
    let ttl: i64 = std::env::var("JWT_TTL_MIN")
        .unwrap_or_else(|_| "60".into())
        .parse()
        .unwrap_or(60);
    let token = jwt::sign(admin.user_admin_id, perms.clone(), &secret, ttl);

    // 6) cookies
    let jwt_cookie = Cookie::build("admin_token", token)
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::minutes(ttl))
        .finish();

    let csrf_val = crypto::random_base64::<16>();
    let csrf_cookie = Cookie::build("csrf_token", &csrf_val)
        .http_only(false) // accessible par le navigateur
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::minutes(ttl))
        .finish();

    #[derive(Serialize)]
    struct LoginResp<'a> {
        csrf: &'a str,
    }

    HttpResponse::Ok()
        .cookie(jwt_cookie)
        .cookie(csrf_cookie)
        .json(LoginResp { csrf: &csrf_val })
}

/* -------------------------------------------------------------------------- */
/* ----------------------------- /admin/logout ------------------------------ */
/* -------------------------------------------------------------------------- */

#[get("/admin/logout")]
pub async fn logout(req: HttpRequest) -> HttpResponse {
    let Some(cookie) = req.cookie("admin_token") else {
        return HttpResponse::Unauthorized().finish();
    };
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET");
    let claims = match jwt::verify(cookie.value(), &secret) {
        Ok(c) => c,
        Err(_) => return HttpResponse::Unauthorized().finish(),
    };
    JWT_BLACKLIST.lock().unwrap().insert(claims.jti);

    // expire les deux cookies
    let expired_jwt = Cookie::build("admin_token", "")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::seconds(0))
        .finish();
    let expired_csrf = Cookie::build("csrf_token", "")
        .http_only(false)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(time::Duration::seconds(0))
        .finish();

    HttpResponse::Ok()
        .cookie(expired_jwt)
        .cookie(expired_csrf)
        .body("Logged out")
}

/* -------------------------------------------------------------------------- */
/* ------------------------------- /admin/me -------------------------------- */
/* -------------------------------------------------------------------------- */

#[derive(Serialize)]
struct MeResp {
    username: String,
    perms:    Vec<String>,
}

/// Renvoie le username + la liste des permissions du token.
#[get("/admin/me")]
pub async fn me(req: HttpRequest, state: Data<AppState>) -> HttpResponse {
    // 1) récupérer & vérifier le cookie
    let Some(cookie) = req.cookie("admin_token") else {
        return HttpResponse::Unauthorized().finish();
    };
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET");
    let claims = match jwt::verify(cookie.value(), &secret) {
        Ok(c) => c,
        Err(_) => return HttpResponse::Unauthorized().finish(),
    };

    // 2) username
    match db::get_admin_username(&state.db, claims.sub) {
        Ok(Some(uname)) => HttpResponse::Ok().json(MeResp {
            username: uname,
            perms: claims.perms,
        }),
        _ => HttpResponse::InternalServerError().body("admin not found"),
    }
}

/* -------------------------------------------------------------------------- */
/* --------------------------- configuration Actix -------------------------- */
/* -------------------------------------------------------------------------- */

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(login)
        .service(logout)
        .service(me);
}
