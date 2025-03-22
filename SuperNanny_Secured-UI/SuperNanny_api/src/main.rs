use actix_web::{
    middleware,
    get, post, put, delete,
    cookie::{Cookie, SameSite},
    dev::{Transform, ServiceRequest, ServiceResponse},
    web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder,
    body::BoxBody,
};
use actix_cors::Cors;
use actix_service::{Service, forward_ready};
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

mod schema;

/* ============================= Config et const ============================ */

const PASSWORD_FILE: &str = "password_hash.txt";
static LOGIN_ATTEMPTS: Lazy<Mutex<HashMap<String, (u32, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static SERVER_TOKEN: Lazy<Mutex<TokenData>> =
    Lazy::new(|| Mutex::new(generate_access_token()));
static CSRF_TOKEN: Lazy<Mutex<String>> =
    Lazy::new(|| Mutex::new(generate_csrf_token()));

/* ========================================================================== */

/* ======================== Structure pour les tokens ======================= */

struct TokenData {
    value: String,
    expires_at: i64,
}

// Génère un token d’accès (aléatoire, 32 octets)
fn generate_access_token() -> TokenData {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = general_purpose::STANDARD.encode(bytes);

    TokenData {
        value: token,
        expires_at: (Utc::now() + ChronoDuration::minutes(60)).timestamp(),
    }
}

// Génère un token CSRF (16 octets aléatoires)
fn generate_csrf_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    general_purpose::STANDARD.encode(bytes)
}

// Vérifie si le token d’accès est valide (non expiré, et correspond au token stocké)
fn is_valid_token(token: &str) -> bool {
    let stored_token = SERVER_TOKEN.lock().unwrap();
    let now = Utc::now().timestamp();

    if now > stored_token.expires_at {
        println!("[INFO] Token expiré, l’utilisateur doit se reconnecter");
        return false;
    }
    token == stored_token.value
}

/* ========================================================================== */

/* ======================== Vérification password ========================= */

// Vérifie si le mot de passe fourni correspond au hash stocké
fn verify_password(password: &str) -> bool {
    if let Ok(hash_str) = fs::read_to_string(PASSWORD_FILE) {
        if let Ok(parsed_hash) = PasswordHash::new(&hash_str) {
            return Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok();
        }
    }
    false
}

/* ========================================================================== */

/* ========================= Middleware d'authent =========================== */

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
            // Vérifie la présence du cookie "access_token"
            if let Some(cookie) = req.cookie("access_token") {
                if is_valid_token(cookie.value()) {
                    // Vérifie le token CSRF dans l’en-tête X-CSRF-Token
                    if let Some(csrf_header) = req.headers().get("X-CSRF-Token") {
                        let csrf_str = csrf_header.to_str().unwrap_or("");
                        let csrf_guard = CSRF_TOKEN.lock().unwrap();
                        if csrf_str == csrf_guard.as_str() {
                            // Si ok, on laisse passer la requête
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

/* ========================================================================== */

/* ========================== Endpoints d'authent =========================== */

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

    // Vérifie si l’IP est temporairement bloquée
    if let Some((count, expiry)) = attempts.get(&ip) {
        if *count >= 5 && now < *expiry {
            return HttpResponse::TooManyRequests().body("Trop de tentatives, réessayez dans 10 minutes.");
        }
    }

    // Vérifie le mot de passe
    if verify_password(&credentials.password) {
        // Génère un nouveau token d’accès + un token CSRF
        let access_token = generate_access_token();
        let csrf_token = generate_csrf_token();

        // Stocke en mémoire
        *SERVER_TOKEN.lock().unwrap() = access_token;
        *CSRF_TOKEN.lock().unwrap() = csrf_token;

        // Crée les cookies
        let access_cookie = Cookie::build("access_token", SERVER_TOKEN.lock().unwrap().value.clone())
            .http_only(true)
            .secure(false) // On reste en HTTP pour simplifier (pas SSL)
            .same_site(SameSite::Strict)
            .path("/")
            .finish();

        let csrf_cookie = Cookie::build("csrf_token", CSRF_TOKEN.lock().unwrap().clone())
            .http_only(false)
            .secure(false)
            .same_site(SameSite::Strict)
            .path("/")
            .finish();

        // Réinitialise les tentatives pour cette IP
        attempts.remove(&ip);

        return HttpResponse::Ok()
            .cookie(access_cookie)
            .cookie(csrf_cookie)
            .body("Authentifié avec succès");
    }

    // Incrémente le nombre de tentatives
    let entry = attempts.entry(ip.clone()).or_insert((0, now + 600));
    entry.0 += 1;
    // Bloque l’IP après 5 tentatives (durée 600 sec = 10 min)
    if entry.0 >= 5 {
        entry.1 = now + 600;
        return HttpResponse::TooManyRequests().body("Trop de tentatives, réessayez plus tard");
    }

    HttpResponse::Unauthorized().body("Mot de passe incorrect")
}

// Test endpoint protégé minimal
#[get("/protected")]
async fn protected_route(_req: HttpRequest) -> impl Responder {
    HttpResponse::Ok().body("Accès autorisé à /protected")
}

#[get("/check_auth")]
async fn check_auth(req: HttpRequest) -> HttpResponse {
    // Vérifier le cookie "access_token"
    if let Some(cookie) = req.cookie("access_token") {
        if !is_valid_token(cookie.value()) {
            return HttpResponse::Forbidden().body("Accès refusé");
        }
    } else {
        return HttpResponse::Forbidden().body("Accès refusé");
    }

    // Vérifier le header CSRF
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
    // Vérification manuelle de l'authentification

    // Vérifier le cookie "access_token"
    if let Some(cookie) = req.cookie("access_token") {
        if !is_valid_token(cookie.value()) {
            return HttpResponse::Forbidden().body("Permission denied");
        }
    } else {
        return HttpResponse::Forbidden().body("Permission denied");
    }

    // Vérifier le header CSRF
    if let Some(csrf_header) = req.headers().get("X-CSRF-Token") {
        let csrf_str = csrf_header.to_str().unwrap_or("");
        let csrf_guard = CSRF_TOKEN.lock().unwrap();
        if csrf_str != csrf_guard.as_str() {
            return HttpResponse::Forbidden().body("CSRF token invalide");
        }
    } else {
        return HttpResponse::Forbidden().body("CSRF token manquant");
    }

    // Réinitialiser les tokens côté serveur
    {
        let mut token_data = SERVER_TOKEN.lock().unwrap();
        token_data.value = String::new();
        token_data.expires_at = 0;
    }
    {
        let mut csrf_token = CSRF_TOKEN.lock().unwrap();
        *csrf_token = String::new();
    }

    // Créer des cookies "vides" pour forcer la suppression côté client
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



/* ========================================================================== */

/* ===================== Endpoints de gestion de configuration ========================= */

#[derive(Queryable, Insertable, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = schema::app_policy)]
pub struct AppPolicy {
    pub app_name: String,
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = schema::app_policy)]
pub struct NewAppPolicy {
    pub app_name: String,
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
}

#[derive(Queryable, Serialize, Deserialize)]
#[diesel(table_name = schema::sandbox_events)]
pub struct SandboxEvent {
    pub event_id: i32,
    pub timestamp: NaiveDateTime,
    pub hostname: String,
    pub app_name: String,
    pub denied_path: Option<String>,
    pub operation: String,
    pub result: String,
}

type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[get("/envs")]
async fn get_envs(pool: web::Data<DbPool>) -> impl Responder {
    use crate::schema::app_policy::dsl::*;
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
    use crate::schema::app_policy::dsl::*;
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
    use crate::schema::app_policy::dsl::*;
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
    use crate::schema::app_policy::dsl::*;
    let mut conn = pool.get().expect("Impossible d'obtenir la connexion DB");
    let program_name = program.into_inner();

    // Vérifier si la configuration existe
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
    use crate::schema::app_policy::dsl::*;
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

/* ========================================================================== */

/* ===================== Endpoints de communication pour le script ===================== */

#[derive(Serialize, Deserialize, Clone)]
struct ScriptPrompt {
    app: String,
    path: String,
}

#[derive(Deserialize)]
struct ScriptQuery {
    app: String,
    path: String,
}

#[derive(Deserialize)]
struct ScriptAnswer {
    app: String,
    path: String,
    choice: String,
}

// État partagé pour stocker les choix par (app, path) et limiter la fréquence de log
struct ScriptState {
    choices: Mutex<HashMap<(String, String), String>>,
    last_log: Mutex<HashMap<(String, String), Instant>>,
}

impl ScriptState {
    fn new() -> Self {
        ScriptState {
            choices: Mutex::new(HashMap::new()),
            last_log: Mutex::new(HashMap::new()),
        }
    }
}

/// Enregistre le prompt envoyé par le script
#[post("/script_prompt")]
async fn script_prompt(
    data: web::Json<ScriptPrompt>,
    state: web::Data<ScriptState>,
) -> impl Responder {
    let prompt = data.into_inner();
    {
        let mut choices_map = state.choices.lock().unwrap();
        choices_map.entry((prompt.app.clone(), prompt.path.clone()))
            .or_insert(String::new());
    }
    println!(
        "[API] Reçu prompt: app='{}', path='{}'.",
        prompt.app, prompt.path
    );

    let state_for_thread = state.clone();
    std::thread::spawn(move || {
        // Afficher la notification dans un thread séparé
        let notification_handle: NotificationHandle = Notification::new()
            .summary("Permission demandée")
            .body(&format!(
                "L'app '{}' demande la permission pour:\n{}",
                prompt.app, prompt.path
            ))
            .icon("dialog-information")
            .action("r", "Read-Only")
            .action("w", "Writable")
            .action("s", "Skip")
            .show()
            .expect("Impossible d'afficher la notification");

        notification_handle.wait_for_action(move |action_id| {
            let mut map = state_for_thread.choices.lock().unwrap();
            match action_id {
                "r" => { map.insert((prompt.app.clone(), prompt.path.clone()), "r".to_string()); },
                "w" => { map.insert((prompt.app.clone(), prompt.path.clone()), "w".to_string()); },
                "s" => { map.insert((prompt.app.clone(), prompt.path.clone()), "s".to_string()); },
                _   => { println!("Action inconnue : {}", action_id); },
            }
        });
    });

    HttpResponse::Ok().body("Prompt enregistré, notification envoyée")
}

/// Retourne le choix défini pour le script, avec un log limité toutes les 20 secondes
#[get("/get_choice")]
async fn get_choice(
    query: web::Query<ScriptQuery>,
    state: web::Data<ScriptState>,
) -> impl Responder {
    let key = (query.app.clone(), query.path.clone());
    let map = state.choices.lock().unwrap();
    let choice = map.get(&key).cloned().unwrap_or_default();
    drop(map);
    let mut last_log_map = state.last_log.lock().unwrap();
    let now = Instant::now();
    if last_log_map.get(&key).map_or(true, |last| now.duration_since(*last) >= StdDuration::from_secs(20)) {
        last_log_map.insert(key.clone(), now);
        println!(
            "[API] Le script interroge pour (app: '{}', path: '{}'). Choix actuel: '{}'",
            query.app, query.path, choice
        );
    }
    HttpResponse::Ok().body(choice)
}

/// Définit le choix pour une application et un chemin
#[post("/set_choice")]
async fn set_choice(
    data: web::Json<ScriptAnswer>,
    state: web::Data<ScriptState>,
) -> impl Responder {
    let answer = data.into_inner();
    let key = (answer.app.clone(), answer.path.clone());
    let mut choices_map = state.choices.lock().unwrap();
    choices_map.insert(key, answer.choice.clone());
    println!(
        "[API] Réponse définie pour (app: '{}', path: '{}'): '{}'",
        answer.app, answer.path, answer.choice
    );
    HttpResponse::Ok().body("Réponse enregistrée")
}

/// Retourne la liste des prompts en attente (aucun choix défini)
#[get("/pending_prompts")]
async fn pending_prompts(state: web::Data<ScriptState>) -> impl Responder {
    let map = state.choices.lock().unwrap();
    let pending: Vec<ScriptPrompt> = map
        .iter()
        .filter(|(_k, v)| v.is_empty())
        .map(|((app, path), _)| ScriptPrompt {
            app: app.clone(),
            path: path.clone(),
        })
        .collect();
    HttpResponse::Ok().json(pending)
}

#[get("/events/{app_name}")]
async fn get_events_by_app(
    pool: web::Data<DbPool>,
    app_param: web::Path<String>,
) -> impl Responder {
    use crate::schema::sandbox_events::dsl::*;
    let mut conn = pool.get().expect("Impossible d'obtenir la connexion DB");

    let app_name_filter = app_param.into_inner();

    let results = sandbox_events
        .filter(app_name.eq(app_name_filter))
        .order(timestamp.desc())
        .load::<SandboxEvent>(&mut conn);

    match results {
        Ok(events) => HttpResponse::Ok().json(events),
        Err(err) => HttpResponse::InternalServerError()
            .body(format!("Erreur lors de la récupération des logs : {}", err)),
    }
}

/* ========================================================================== */

/* ================================== Main ================================== */

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialisation de dotenv pour charger les variables d'environnement
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Échec de connexion à la BDD");

    // État partagé pour la communication avec le script
    let script_state = web::Data::new(ScriptState::new());

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
            // Données partagées pour la BDD et l'état du script
            .app_data(web::Data::new(pool.clone()))
            .app_data(script_state.clone())
            
            // Endpoints d'authentification
            .service(login)
            .service(check_auth)
            .service(logout) // logout fait sa propre vérification de token
            // Endpoints protégés avec middleware (préfixe explicite pour éviter tout conflit)
            .service(
                web::scope("")
                    .wrap(AuthMiddleware)
                    // Test Route Protégé
                    .service(protected_route)
                    // Endpoints de gestion de configuration (publics)
                    .service(get_envs)
                    .service(get_env_content)
                    .service(create_env)
                    .service(update_env)
                    .service(delete_env)
                    // Endpoints de communication pour le script
                    .service(script_prompt)
                    .service(get_choice)
                    .service(set_choice)
                    .service(pending_prompts)
                    .service(get_events_by_app)
            )
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}
