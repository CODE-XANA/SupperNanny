// src/main.rs

extern crate dotenv;

mod schema;

use actix_cors::Cors;
use actix_service::{forward_ready, Service, Transform};
use actix_web::{
    cookie::{Cookie, SameSite},
    dev::{ServiceRequest, ServiceResponse},
    get, post, put, delete,
    web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder,
    body::BoxBody,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::{Duration as StdDuration, Instant};
use time::Duration as TimeDuration;

use argon2::{Argon2, PasswordVerifier};
use argon2::password_hash::PasswordHash;
use once_cell::sync::Lazy;
use rand::RngCore;
use base64::{engine::general_purpose, Engine};
use chrono::{Utc, Duration as ChronoDuration, NaiveDateTime};
use serde::{Deserialize, Serialize};

use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use diesel::prelude::*;
use dotenv::dotenv;
use std::env;

use notify_rust::{Notification, NotificationHandle};

// ==========================================================================
// Config et Constantes
// ==========================================================================

const PASSWORD_FILE: &str = "password_hash.txt";

static LOGIN_ATTEMPTS: Lazy<Mutex<HashMap<String, (u32, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static SERVER_TOKEN: Lazy<Mutex<TokenData>> =
    Lazy::new(|| Mutex::new(generate_access_token()));
static CSRF_TOKEN: Lazy<Mutex<String>> =
    Lazy::new(|| Mutex::new(generate_csrf_token()));

// ==========================================================================
// Structures et Fonctions pour les Tokens
// ==========================================================================

struct TokenData {
    value: String,
    expires_at: i64,
}

fn generate_access_token() -> TokenData {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = general_purpose::STANDARD.encode(bytes);
    TokenData {
        value: token,
        expires_at: (Utc::now() + ChronoDuration::minutes(60)).timestamp(),
    }
}

fn generate_csrf_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    general_purpose::STANDARD.encode(bytes)
}

fn is_valid_token(token: &str) -> bool {
    let stored_token = SERVER_TOKEN.lock().unwrap();
    let now = Utc::now().timestamp();
    if now > stored_token.expires_at {
        println!("[INFO] Token expiré, l’utilisateur doit se reconnecter");
        return false;
    }
    token == stored_token.value
}

// ==========================================================================
// Vérification du mot de passe pour l'admin (Argon2)
// ==========================================================================

fn verify_password(password: &str) -> bool {
    if let Ok(hash_str) = fs::read_to_string(PASSWORD_FILE) {
        if let Ok(parsed_hash) = PasswordHash::new(&hash_str) {
            return Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .is_ok();
        }
    }
    false
}

// ==========================================================================
// Middleware d’authentification
// ==========================================================================

pub struct AuthMiddleware;

impl<S> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Transform = AuthMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service: Arc::new(service),
        }))
    }
}

pub struct AuthMiddlewareService<S> {
    service: Arc<S>,
}

impl<S> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = Arc::clone(&self.service);
        Box::pin(async move {
            if let Some(cookie) = req.cookie("access_token") {
                if is_valid_token(cookie.value()) {
                    if let Some(csrf_header) = req.headers().get("X-CSRF-Token") {
                        let csrf_str = csrf_header.to_str().unwrap_or("");
                        let csrf_guard = CSRF_TOKEN.lock().unwrap();
                        if csrf_str == csrf_guard.as_str() {
                            return srv.call(req).await;
                        }
                    }
                    return Ok(req.into_response(
                        HttpResponse::Forbidden().body("CSRF token invalide"),
                    ));
                }
            }
            Ok(req.into_response(HttpResponse::Forbidden().body("Permission denied")))
        })
    }
}

// ==========================================================================
// Endpoints d’authentification (ADMIN)
// ==========================================================================

#[derive(Deserialize)]
struct LoginRequest {
    password: String,
}

#[post("/login")]
async fn login(req: HttpRequest, credentials: web::Json<LoginRequest>) -> HttpResponse {
    let ip = req.peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let mut attempts = LOGIN_ATTEMPTS.lock().unwrap();
    let now = Utc::now().timestamp();
    if let Some((count, expiry)) = attempts.get(&ip) {
        if *count >= 5 && now < *expiry {
            return HttpResponse::TooManyRequests().body("Trop de tentatives, réessayez dans 10 minutes.");
        }
    }
    if verify_password(&credentials.password) {
        let access_token = generate_access_token();
        let csrf_token = generate_csrf_token();
        *SERVER_TOKEN.lock().unwrap() = access_token;
        *CSRF_TOKEN.lock().unwrap() = csrf_token;
        let access_cookie = Cookie::build("access_token", SERVER_TOKEN.lock().unwrap().value.clone())
            .http_only(true)
            .secure(false)
            .same_site(SameSite::Strict)
            .path("/")
            .finish();
        let csrf_cookie = Cookie::build("csrf_token", CSRF_TOKEN.lock().unwrap().clone())
            .http_only(false)
            .secure(false)
            .same_site(SameSite::Strict)
            .path("/")
            .finish();
        attempts.remove(&ip);
        return HttpResponse::Ok()
            .cookie(access_cookie)
            .cookie(csrf_cookie)
            .body("Authentifié avec succès");
    }
    let entry = attempts.entry(ip.clone()).or_insert((0, now + 600));
    entry.0 += 1;
    if entry.0 >= 5 {
        entry.1 = now + 600;
        return HttpResponse::TooManyRequests().body("Trop de tentatives, réessayez plus tard");
    }
    HttpResponse::Unauthorized().body("Mot de passe incorrect")
}

#[get("/protected")]
async fn protected_route(_req: HttpRequest) -> impl Responder {
    HttpResponse::Ok().body("Accès autorisé à /protected")
}

#[get("/check_auth")]
async fn check_auth(req: HttpRequest) -> HttpResponse {
    if let Some(cookie) = req.cookie("access_token") {
        if !is_valid_token(cookie.value()) {
            return HttpResponse::Forbidden().body("Accès refusé");
        }
    } else {
        return HttpResponse::Forbidden().body("Accès refusé");
    }
    if let Some(csrf_header) = req.headers().get("X-CSRF-Token") {
        let csrf_str = csrf_header.to_str().unwrap_or("");
        let csrf_guard = CSRF_TOKEN.lock().unwrap();
        if csrf_str != csrf_guard.as_str() {
            return HttpResponse::Forbidden().body("CSRF token invalide");
        }
    } else {
        return HttpResponse::Forbidden().body("CSRF token manquant");
    }
    HttpResponse::Ok().body("Accès autorisé")
}

#[post("/logout")]
async fn logout(req: HttpRequest) -> HttpResponse {
    if let Some(cookie) = req.cookie("access_token") {
        if !is_valid_token(cookie.value()) {
            return HttpResponse::Forbidden().body("Permission denied");
        }
    } else {
        return HttpResponse::Forbidden().body("Permission denied");
    }
    if let Some(csrf_header) = req.headers().get("X-CSRF-Token") {
        let csrf_str = csrf_header.to_str().unwrap_or("");
        let csrf_guard = CSRF_TOKEN.lock().unwrap();
        if csrf_str != csrf_guard.as_str() {
            return HttpResponse::Forbidden().body("CSRF token invalide");
        }
    } else {
        return HttpResponse::Forbidden().body("CSRF token manquant");
    }
    {
        let mut token_data = SERVER_TOKEN.lock().unwrap();
        token_data.value = String::new();
        token_data.expires_at = 0;
    }
    {
        let mut csrf_token = CSRF_TOKEN.lock().unwrap();
        *csrf_token = String::new();
    }
    let access_cookie = Cookie::build("access_token", "")
        .http_only(true)
        .secure(false)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(TimeDuration::seconds(0))
        .finish();
    let csrf_cookie = Cookie::build("csrf_token", "")
        .http_only(false)
        .secure(false)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(TimeDuration::seconds(0))
        .finish();
    HttpResponse::Ok()
        .cookie(access_cookie)
        .cookie(csrf_cookie)
        .body("Déconnecté")
}

// ==========================================================================
// Endpoints de gestion des utilisateurs (Admin uniquement)
// ==========================================================================

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
}

#[derive(Queryable, Serialize, Deserialize)]
struct User {
    user_id: i32,
    username: String,
    password_hash: String,
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = schema::users)]
struct NewUser {
    username: String,
    password_hash: String,
}

#[get("/users")]
async fn list_users(pool: web::Data<DbPool>) -> HttpResponse {
    use schema::users::dsl::*;
    let mut conn = pool.get().expect("Connexion échouée");
    match users.load::<User>(&mut conn) {
        Ok(user_list) => HttpResponse::Ok().json(user_list),
        Err(err) => HttpResponse::InternalServerError().body(format!("Erreur: {}", err)),
    }
}

#[post("/users")]
async fn create_user(pool: web::Data<DbPool>, data: web::Json<CreateUserRequest>) -> HttpResponse {
    use schema::users::dsl::*;
    let mut conn = pool.get().expect("Connexion échouée");
    // Vérifier si l'utilisateur existe déjà
    if let Ok(_) = users.filter(username.eq(&data.username)).first::<User>(&mut conn) {
        return HttpResponse::BadRequest().body("Cet utilisateur existe déjà.");
    }
    // Hachage du mot de passe avec bcrypt pour les utilisateurs (non-admin)
    let hashed_password = match bcrypt::hash(&data.password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().body("Erreur de hashage"),
    };
    let new_user = NewUser {
        username: data.username.clone(),
        password_hash: hashed_password,
    };
    match diesel::insert_into(schema::users::table)
        .values(&new_user)
        .execute(&mut conn)
    {
        Ok(_) => HttpResponse::Ok().body("Utilisateur créé"),
        Err(err) => HttpResponse::InternalServerError().body(format!("Erreur: {}", err)),
    }
}

#[delete("/users/{user_id}")]
async fn delete_user(pool: web::Data<DbPool>, user_id_param: web::Path<i32>) -> HttpResponse {
    use schema::users::dsl::*;
    let mut conn = pool.get().expect("Connexion échouée");
    match diesel::delete(users.filter(user_id.eq(*user_id_param)))
        .execute(&mut conn)
    {
        Ok(_) => HttpResponse::Ok().body("Utilisateur supprimé"),
        Err(err) => HttpResponse::InternalServerError().body(format!("Erreur: {}", err)),
    }
}

// ==========================================================================
// Endpoints de gestion des rôles
// ==========================================================================

#[derive(Queryable, Serialize, Deserialize)]
struct Role {
    role_id: i32,
    role_name: String,
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = schema::roles)]
struct NewRole {
    role_name: String,
}

#[get("/roles")]
async fn list_roles(pool: web::Data<DbPool>) -> HttpResponse {
    use schema::roles::dsl::*;
    let mut conn = pool.get().expect("Connexion échouée");
    match roles.load::<Role>(&mut conn) {
        Ok(roles_list) => HttpResponse::Ok().json(roles_list),
        Err(err) => HttpResponse::InternalServerError().body(format!("Erreur: {}", err)),
    }
}

#[post("/roles")]
async fn create_role(pool: web::Data<DbPool>, data: web::Json<NewRole>) -> HttpResponse {
    use schema::roles::dsl::*;
    let mut conn = pool.get().expect("Connexion échouée");
    match diesel::insert_into(roles)
        .values(&data.into_inner())
        .execute(&mut conn)
    {
        Ok(_) => HttpResponse::Ok().body("Rôle créé"),
        Err(err) => HttpResponse::InternalServerError().body(format!("Erreur: {}", err)),
    }
}

#[delete("/roles/{role_id}")]
async fn delete_role(pool: web::Data<DbPool>, role_id_param: web::Path<i32>) -> HttpResponse {
    use schema::roles::dsl::*;
    let mut conn = pool.get().expect("Connexion échouée");
    match diesel::delete(roles.filter(role_id.eq(*role_id_param)))
        .execute(&mut conn)
    {
        Ok(_) => HttpResponse::Ok().body("Rôle supprimé"),
        Err(err) => HttpResponse::InternalServerError().body(format!("Erreur: {}", err)),
    }
}

// ==========================================================================
// Endpoints pour la gestion des affectations de rôles aux utilisateurs
// ==========================================================================

#[derive(Deserialize)]
struct AssignRoleRequest {
    user_id: i32,
    role_id: i32,
}

#[post("/user_roles")]
async fn assign_role(pool: web::Data<DbPool>, data: web::Json<AssignRoleRequest>) -> HttpResponse {
    use schema::user_roles::dsl::*;
    let mut conn = pool.get().expect("Connexion échouée");
    // Vérifier si l'affectation existe déjà
    if let Ok(_) = user_roles.filter(user_id.eq(data.user_id))
                             .filter(role_id.eq(data.role_id))
                             .first::<(i32, i32)>(&mut conn)
    {
        return HttpResponse::BadRequest().body("Le rôle est déjà attribué à cet utilisateur");
    }
    let new_assignment = (user_id.eq(data.user_id), role_id.eq(data.role_id));
    match diesel::insert_into(user_roles)
        .values(&new_assignment)
        .execute(&mut conn)
    {
        Ok(_) => HttpResponse::Ok().body("Rôle attribué"),
        Err(err) => HttpResponse::InternalServerError().body(format!("Erreur: {}", err)),
    }
}

#[get("/user_roles/{user_id}")]
async fn get_user_roles(pool: web::Data<DbPool>, user_id_param: web::Path<i32>) -> HttpResponse {
    use schema::user_roles::dsl::*;
    use schema::roles::dsl::{roles as roles_table, role_id as r_role_id, role_name};
    let mut conn = pool.get().expect("Connexion échouée");
    let uid = user_id_param.into_inner();
    let results = roles_table.inner_join(user_roles.on(r_role_id.eq(role_id)))
        .filter(schema::user_roles::dsl::user_id.eq(uid))
        .select((r_role_id, role_name))
        .load::<(i32, String)>(&mut conn);
    match results {
        Ok(vec) => {
            let roles: Vec<_> = vec.into_iter().map(|(id, name)| {
                serde_json::json!({ "role_id": id, "role_name": name })
            }).collect();
            HttpResponse::Ok().json(roles)
        },
        Err(err) => HttpResponse::InternalServerError().body(format!("Erreur: {}", err)),
    }
}

#[delete("/user_roles/{user_id}/{role_id}")]
async fn remove_role(pool: web::Data<DbPool>, params: web::Path<(i32, i32)>) -> HttpResponse {
    use schema::user_roles::dsl::*;
    let mut conn = pool.get().expect("Connexion échouée");
    let (uid, rid) = params.into_inner();
    match diesel::delete(user_roles.filter(user_id.eq(uid)).filter(role_id.eq(rid)))
        .execute(&mut conn)
    {
        Ok(_) => HttpResponse::Ok().body("Rôle retiré"),
        Err(err) => HttpResponse::InternalServerError().body(format!("Erreur: {}", err)),
    }
}

// ==========================================================================
// Endpoints pour la gestion des permissions associées aux rôles
// ==========================================================================

#[derive(Deserialize)]
struct AssignPermissionRequest {
    role_id: i32,
    permission_id: i32,
}

#[post("/role_permissions")]
async fn assign_permission(pool: web::Data<DbPool>, data: web::Json<AssignPermissionRequest>) -> HttpResponse {
    use schema::role_permissions::dsl::*;
    let mut conn = pool.get().expect("Connexion échouée");
    if let Ok(_) = role_permissions
        .filter(schema::role_permissions::dsl::role_id.eq(data.role_id))
        .filter(schema::role_permissions::dsl::permission_id.eq(data.permission_id))
        .first::<(i32, i32)>(&mut conn)
    {
        return HttpResponse::BadRequest().body("La permission est déjà attribuée à ce rôle");
    }
    let new_assignment = (schema::role_permissions::dsl::role_id.eq(data.role_id),
                          schema::role_permissions::dsl::permission_id.eq(data.permission_id));
    match diesel::insert_into(role_permissions)
        .values(&new_assignment)
        .execute(&mut conn)
    {
        Ok(_) => HttpResponse::Ok().body("Permission attribuée"),
        Err(err) => HttpResponse::InternalServerError().body(format!("Erreur: {}", err)),
    }
}

#[get("/role_permissions/{role_id}")]
async fn get_role_permissions(pool: web::Data<DbPool>, role_id_param: web::Path<i32>) -> HttpResponse {
    use schema::role_permissions::dsl::*;
    use schema::permissions::dsl::{permissions as permissions_table, permission_id as p_permission_id, permission_name};
    let mut conn = pool.get().expect("Connexion échouée");
    let rid = role_id_param.into_inner();
    let results = permissions_table.inner_join(role_permissions.on(p_permission_id.eq(permission_id)))
        .filter(schema::role_permissions::dsl::role_id.eq(rid))
        .select((p_permission_id, permission_name))
        .load::<(i32, String)>(&mut conn);
    match results {
        Ok(vec) => {
            let perms: Vec<_> = vec.into_iter().map(|(id, name)| {
                serde_json::json!({ "permission_id": id, "permission_name": name })
            }).collect();
            HttpResponse::Ok().json(perms)
        },
        Err(err) => HttpResponse::InternalServerError().body(format!("Erreur: {}", err)),
    }
}

#[delete("/role_permissions/{role_id}/{permission_id}")]
async fn remove_permission(pool: web::Data<DbPool>, params: web::Path<(i32, i32)>) -> HttpResponse {
    use schema::role_permissions::dsl::*;
    let mut conn = pool.get().expect("Connexion échouée");
    let (rid, pid) = params.into_inner();
    match diesel::delete(role_permissions.filter(role_id.eq(rid)).filter(permission_id.eq(pid)))
        .execute(&mut conn)
    {
        Ok(_) => HttpResponse::Ok().body("Permission retirée"),
        Err(err) => HttpResponse::InternalServerError().body(format!("Erreur: {}", err)),
    }
}

// ==========================================================================
// Endpoints de gestion de configuration (App Policies)
// ==========================================================================

#[derive(Queryable, Serialize, Deserialize)]
#[diesel(table_name = schema::app_policy)]
pub struct AppPolicy {
    pub policy_id: i32,
    pub app_name: String,
    pub role_id: i32,
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
    pub allowed_ips: String,
    pub allowed_domains: String,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = schema::app_policy)]
pub struct NewAppPolicy {
    pub app_name: String,
    pub role_id: i32,
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
    pub allowed_ips: String,
    pub allowed_domains: String,
}

#[get("/envs")]
async fn get_envs(pool: web::Data<DbPool>) -> impl Responder {
    use schema::app_policy::dsl::*;
    let mut conn = pool.get().expect("Impossible d'obtenir la connexion DB");
    let results = app_policy.load::<AppPolicy>(&mut conn);
    match results {
        Ok(policies) => HttpResponse::Ok().json(policies),
        Err(err) => HttpResponse::InternalServerError()
                        .body(format!("Erreur lors de la récupération des règles : {}", err)),
    }
}

#[get("/env/{program}")]
async fn get_env_content(
    pool: web::Data<DbPool>,
    program: web::Path<String>,
) -> impl Responder {
    use schema::app_policy::dsl::*;
    let mut conn = pool.get().expect("Impossible d'obtenir la connexion DB");
    let program_name = program.into_inner();
    let result = app_policy
        .filter(app_name.eq(&program_name))
        .first::<AppPolicy>(&mut conn);
    match result {
        Ok(policy) => HttpResponse::Ok().json(policy),
        Err(_) => HttpResponse::NotFound().body("Aucune règle trouvée"),
    }
}

#[post("/env")]
async fn create_env(
    pool: web::Data<DbPool>,
    data: web::Json<NewAppPolicy>,
) -> impl Responder {
    use schema::app_policy::dsl::*;
    let mut conn = pool.get().expect("Impossible d'obtenir la connexion DB");
    let new_policy = data.into_inner();
    let result = diesel::insert_into(app_policy)
        .values(&new_policy)
        .execute(&mut conn);
    match result {
        Ok(_) => HttpResponse::Ok().body("Configuration ajoutée"),
        Err(err) => HttpResponse::InternalServerError()
                        .body(format!("Erreur lors de l'ajout : {}", err)),
    }
}

#[derive(Deserialize)]
struct UpdateEnvData {
    ll_fs_ro: Vec<String>,
    ll_fs_rw: Vec<String>,
    ll_tcp_bind: Option<String>,
    ll_tcp_connect: Option<String>,
}

#[put("/env/{program}")]
async fn update_env(
    pool: web::Data<DbPool>,
    program: web::Path<String>,
    data: web::Json<UpdateEnvData>,
) -> impl Responder {
    use schema::app_policy::dsl::*;
    let mut conn = pool.get().expect("Impossible d'obtenir la connexion DB");
    let program_name = program.into_inner();
    if app_policy.filter(app_name.eq(&program_name)).first::<AppPolicy>(&mut conn).is_err() {
        return HttpResponse::NotFound().body(format!("Aucune règle trouvée pour '{}'", program_name));
    }
    let update = data.into_inner();
    let new_ro = update.ll_fs_ro.join(":");
    let new_rw = update.ll_fs_rw.join(":");
    let new_tcp_bind = update.ll_tcp_bind.unwrap_or_else(|| "9418".to_string());
    let new_tcp_connect = update.ll_tcp_connect.unwrap_or_else(|| "80:443".to_string());
    let result = diesel::update(app_policy.filter(app_name.eq(&program_name)))
        .set((
            default_ro.eq(new_ro),
            default_rw.eq(new_rw),
            tcp_bind.eq(new_tcp_bind),
            tcp_connect.eq(new_tcp_connect),
            updated_at.eq(chrono::Utc::now().naive_utc()),
        ))
        .execute(&mut conn);
    match result {
        Ok(_) => HttpResponse::Ok().body("Configuration mise à jour"),
        Err(err) => HttpResponse::InternalServerError()
                        .body(format!("Erreur lors de la mise à jour : {}", err)),
    }
}

#[delete("/env/{program}")]
async fn delete_env(
    pool: web::Data<DbPool>,
    program: web::Path<String>,
) -> impl Responder {
    use schema::app_policy::dsl::*;
    let mut conn = pool.get().expect("Impossible d'obtenir la connexion DB");
    let program_name = program.into_inner();
    let result = diesel::delete(app_policy.filter(app_name.eq(&program_name)))
        .execute(&mut conn);
    match result {
        Ok(_) => HttpResponse::Ok().body("Configuration supprimée"),
        Err(err) => HttpResponse::InternalServerError()
                        .body(format!("Erreur lors de la suppression : {}", err)),
    }
}

// ==========================================================================
// Main : configuration du serveur HTTP
// ==========================================================================

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Échec de connexion à la BDD");
    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://127.0.0.1:8080")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                actix_web::http::header::CONTENT_TYPE,
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::HeaderName::from_static("x-csrf-token"),
            ])
            .supports_credentials()
            .max_age(3600);
        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .service(login)
            .service(check_auth)
            .service(logout)
            .service(
                web::scope("")
                    .wrap(AuthMiddleware)
                    .service(protected_route)
                    .service(list_users)
                    .service(create_user)
                    .service(delete_user)
                    .service(list_roles)
                    .service(create_role)
                    .service(delete_role)
                    .service(assign_role)
                    .service(get_user_roles)
                    .service(remove_role)
                    .service(assign_permission)
                    .service(get_role_permissions)
                    .service(remove_permission)
                    .service(get_envs)
                    .service(get_env_content)
                    .service(create_env)
                    .service(update_env)
                    .service(delete_env)
            )
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}
