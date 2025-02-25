use actix_web::{delete, get, post, put, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const ENV_DIR: &str = "/home/vmubuntu/Bureau/rust-landlock/application_conf";


/* ======================== Endpoints gestions .env ========================= */

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



/* ===================== Endpoints communication script ===================== */

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

// État partagé pour stocker les choix pour chaque (app, path)
// et mémoriser le dernier instant où un log a été affiché
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

/// Endpoint pour recevoir le prompt du script
#[post("/script_prompt")]
async fn script_prompt(
    data: web::Json<ScriptPrompt>,
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

/// Endpoint pour que le script récupère le choix
/// On affiche le log une fois toutes les 20 secondes pour éviter le spam
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

/// Endpoint pour que le frontend définisse le choix
#[post("/set_choice")]
async fn set_choice(
    data: web::Json<ScriptAnswer>,
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

/// Endpoint pour renvoyer les prompts en attente (pour lesquels la réponse est vide)
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

/* ========================================================================== */



/* ================================== Main ================================== */

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let script_state = web::Data::new(ScriptState::new());
    HttpServer::new(move || {
        App::new()
            .app_data(script_state.clone())
            .service(get_envs)
            .service(get_env_content)
            .service(create_env)
            .service(update_env)
            .service(delete_env)
            .service(script_prompt)
            .service(get_choice)
            .service(set_choice)
            .service(pending_prompts)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

/* ========================================================================== */