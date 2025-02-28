use actix_web::{
    get, post, put, delete,
    cookie::{Cookie, SameSite},
    dev::{Transform, ServiceRequest, ServiceResponse},
    web, App, Error, HttpRequest, HttpResponse, HttpServer, Responder,
    body::BoxBody,
};
use actix_service::{Service, forward_ready};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use argon2::{Argon2, PasswordVerifier};
use argon2::password_hash::{PasswordHash};
use once_cell::sync::Lazy;
use rand::RngCore;
use base64::{engine::general_purpose, Engine};
use chrono::{Utc, Duration as ChronoDuration};
use serde::{Deserialize, Serialize};


/* ============================= Config et const ============================ */

const ENV_DIR: &str = "/home/vmubuntu/Bureau/rust-landlock/application_conf";
const PASSWORD_FILE: &str = "password_hash.txt";
static LOGIN_ATTEMPTS: Lazy<Mutex<HashMap<String, (u32, i64)>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static SERVER_TOKEN: Lazy<Mutex<TokenData>> = Lazy::new(|| Mutex::new(generate_access_token()));
static CSRF_TOKEN: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(generate_csrf_token()));

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



/* ======================== Vérifification password ========================= */

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

// Transform = construction du middleware
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
                    return Ok(req.into_response(HttpResponse::Forbidden().body("CSRF token invalide")));
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
            .secure(false) // On reste en HTTP, pour simplifier (pas SSL)
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

/* ========================================================================== */



/* ====================== ScriptState et Communication ====================== */

#[derive(Serialize, Deserialize, Clone)]
struct ScriptPrompt2 {
    app: String,
    path: String,
}

#[derive(Deserialize)]
struct ScriptQuery2 {
    app: String,
    path: String,
}

#[derive(Deserialize)]
struct ScriptAnswer2 {
    app: String,
    path: String,
    choice: String,
}

// État partagé pour le script
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

/* ========================================================================== */



/* ======================== Endpoints .env / Script ========================= */

#[post("/script_prompt")]
async fn script_prompt(
    data: web::Json<ScriptPrompt2>,
    state: web::Data<ScriptState>,
) -> impl Responder {
    let prompt = data.into_inner();
    let key = (prompt.app.clone(), prompt.path.clone());
    let mut choices_map = state.choices.lock().unwrap();
    choices_map.entry(key.clone()).or_insert(String::new());
    println!(
        "[API] Reçu prompt: Le script pour l'app '{}' et path '{}' attend une réponse.",
        prompt.app, prompt.path
    );
    HttpResponse::Ok().body("Prompt enregistré")
}

#[get("/get_choice")]
async fn get_choice(
    query: web::Query<ScriptQuery2>,
    state: web::Data<ScriptState>,
) -> impl Responder {
    let key = (query.app.clone(), query.path.clone());
    let map = state.choices.lock().unwrap();
    let choice = map.get(&key).cloned().unwrap_or_default();
    drop(map);

    let mut last_log_map = state.last_log.lock().unwrap();
    let now = Instant::now();
    let should_log = if let Some(last) = last_log_map.get(&key) {
        now.duration_since(*last) >= Duration::from_secs(20)
    } else {
        true
    };
    if should_log {
        last_log_map.insert(key.clone(), now);
        println!(
            "[API] Le script interroge pour (app: '{}', path: '{}'). Choix actuel: '{}'",
            query.app, query.path, choice
        );
    }
    HttpResponse::Ok().body(choice)
}

#[post("/set_choice")]
async fn set_choice(
    data: web::Json<ScriptAnswer2>,
    state: web::Data<ScriptState>,
) -> impl Responder {
    let answer = data.into_inner();
    let key = (answer.app.clone(), answer.path.clone());
    let mut choices_map = state.choices.lock().unwrap();
    choices_map.insert(key.clone(), answer.choice.clone());
    println!(
        "[API] Réponse définie pour (app: '{}', path: '{}'): '{}'",
        answer.app, answer.path, answer.choice
    );
    HttpResponse::Ok().body("Réponse enregistrée")
}

#[get("/pending_prompts")]
async fn pending_prompts(state: web::Data<ScriptState>) -> impl Responder {
    let map = state.choices.lock().unwrap();
    let pending: Vec<ScriptPrompt2> = map
        .iter()
        .filter(|(_k, v)| v.is_empty())
        .map(|((app, path), _)| ScriptPrompt2 {
            app: app.clone(),
            path: path.clone(),
        })
        .collect();
    HttpResponse::Ok().json(pending)
}

/* ========================================================================== */



/* ============================= Endpoints .env ============================= */

#[get("/envs")]
async fn get_envs() -> impl Responder {
    let mut programs = Vec::new();
    match fs::read_dir(ENV_DIR) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    if file_name.starts_with("rules.") && file_name.ends_with(".env") {
                        let start = "rules.".len();
                        let end = file_name.len() - ".env".len();
                        programs.push(file_name[start..end].to_string());
                    }
                }
            }
        }
        Err(err) => {
            return HttpResponse::InternalServerError()
                .body(format!("Erreur lors de la lecture du dossier : {}", err))
        }
    }
    HttpResponse::Ok().json(programs)
}

#[get("/env/{program}")]
async fn get_env_content(program: web::Path<String>) -> impl Responder {
    let program = program.into_inner();
    let file_path = format!("{}/rules.{}.env", ENV_DIR, program);
    if !Path::new(&file_path).exists() {
        return HttpResponse::NotFound().body(format!("Le fichier pour '{}' n'existe pas", program));
    }
    match fs::read_to_string(&file_path) {
        Ok(content) => HttpResponse::Ok().body(content),
        Err(err) => HttpResponse::InternalServerError()
            .body(format!("Erreur lors de la lecture du fichier : {}", err)),
    }
}

#[derive(Deserialize)]
struct EnvData {
    program: String,
    ll_fs_ro: String,
    ll_fs_rw: String,
    ll_tcp_bind: Option<String>,
    ll_tcp_connect: Option<String>,
}

#[post("/env")]
async fn create_env(data: web::Json<EnvData>) -> impl Responder {
    let data = data.into_inner();
    let tcp_bind = data.ll_tcp_bind.unwrap_or_else(|| "9418".to_string());
    let tcp_connect = data.ll_tcp_connect.unwrap_or_else(|| "80:443".to_string());
    let file_path = format!("{}/rules.{}.env", ENV_DIR, data.program);
    let content = format!(
        "export LL_FS_RO=\"{}\"\nexport LL_FS_RW=\"{}\"\nexport LL_TCP_BIND=\"{}\"\nexport LL_TCP_CONNECT=\"{}\"\n",
        data.ll_fs_ro, data.ll_fs_rw, tcp_bind, tcp_connect
    );
    match fs::write(&file_path, content) {
        Ok(_) => HttpResponse::Ok().body("Fichier créé avec succès"),
        Err(e) => HttpResponse::InternalServerError()
            .body(format!("Erreur lors de la création du fichier : {}", e)),
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
    program: web::Path<String>,
    data: web::Json<UpdateEnvData>,
) -> impl Responder {
    let program = program.into_inner();
    let file_path = format!("{}/rules.{}.env", ENV_DIR, program);
    if !Path::new(&file_path).exists() {
        return HttpResponse::NotFound().body(format!("Le fichier pour '{}' n'existe pas", program));
    }
    let current_content = fs::read_to_string(&file_path).unwrap_or_default();
    let mut current_tcp_bind = "9418".to_string();
    let mut current_tcp_connect = "80:443".to_string();
    for line in current_content.lines() {
        if line.starts_with("export LL_TCP_BIND=") {
            current_tcp_bind = line
                .trim_start_matches("export LL_TCP_BIND=")
                .trim_matches('"')
                .to_string();
        }
        if line.starts_with("export LL_TCP_CONNECT=") {
            current_tcp_connect = line
                .trim_start_matches("export LL_TCP_CONNECT=")
                .trim_matches('"')
                .to_string();
        }
    }
    let update = data.into_inner();
    let new_tcp_bind = update.ll_tcp_bind.unwrap_or(current_tcp_bind);
    let new_tcp_connect = update.ll_tcp_connect.unwrap_or(current_tcp_connect);
    let new_ro = update.ll_fs_ro.join(":");
    let new_rw = update.ll_fs_rw.join(":");
    let new_content = format!(
        "export LL_FS_RO=\"{}\"\nexport LL_FS_RW=\"{}\"\nexport LL_TCP_BIND=\"{}\"\nexport LL_TCP_CONNECT=\"{}\"\n",
        new_ro, new_rw, new_tcp_bind, new_tcp_connect
    );
    match fs::write(&file_path, new_content) {
        Ok(_) => HttpResponse::Ok().body("Fichier modifié avec succès"),
        Err(e) => HttpResponse::InternalServerError()
            .body(format!("Erreur lors de la modification du fichier : {}", e)),
    }
}

#[delete("/env/{program}")]
async fn delete_env(
    program: web::Path<String>,
    state: web::Data<ScriptState>,
) -> impl Responder {
    let program = program.into_inner();
    let file_path = format!("{}/rules.{}.env", ENV_DIR, program);
    if !Path::new(&file_path).exists() {
        return HttpResponse::NotFound().body(format!("Fichier non trouvé pour '{}'", program));
    }
    match fs::remove_file(&file_path) {
        Ok(_) => {
            // Supprimer également toutes les entrées de prompt associées à ce programme.
            let mut choices = state.choices.lock().unwrap();
            choices.retain(|(app, _), _| app != &program);
            HttpResponse::Ok().body("Fichier supprimé avec succès")
        }
        Err(e) => HttpResponse::InternalServerError()
            .body(format!("Erreur lors de la suppression du fichier : {}", e)),
    }
}

/* ========================================================================== */



/* ================================== Main ================================== */

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // État partagé pour la partie script
    let script_state = web::Data::new(ScriptState::new());

    HttpServer::new(move || {
        App::new()
            .app_data(script_state.clone())
            .service(login)
            // Scope protégé
            .service(
                web::scope("")
                    .wrap(AuthMiddleware) 
                    .service(protected_route) // Endpoint test
                    // Endpoints .env
                    .service(get_envs)
                    .service(get_env_content)
                    .service(create_env)
                    .service(update_env)
                    .service(delete_env)
                    // Endpoints script
                    .service(script_prompt)
                    .service(get_choice)
                    .service(set_choice)
                    .service(pending_prompts)
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

/* ========================================================================== */