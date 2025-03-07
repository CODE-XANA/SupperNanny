use actix_web::{delete, get, post, put, web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use diesel::prelude::*;
use dotenv::dotenv;
use std::env;
use chrono::NaiveDateTime;

mod schema;

// Structure correspondant à la table "app_policy"
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

/* ======================== Endpoints de gestion de configuration ========================= */

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

// Pour créer une configuration, nous utilisons directement la structure AppPolicy.
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


// Structure pour la mise à jour : les champs "ll_fs_ro" et "ll_fs_rw" sont transmis en vecteur.
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
    let key = (prompt.app.clone(), prompt.path.clone());
    let mut choices_map = state.choices.lock().unwrap();
    choices_map.entry(key.clone()).or_insert(String::new());
    println!(
        "[API] Reçu prompt: Le script pour l'app '{}' et path '{}' attend une réponse.",
        prompt.app, prompt.path
    );
    HttpResponse::Ok().body("Prompt enregistré")
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
    if last_log_map.get(&key).map_or(true, |last| now.duration_since(*last) >= Duration::from_secs(20)) {
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
    app_param: web::Path<String>, // Renommé pour éviter le conflit
) -> impl Responder {
    use crate::schema::sandbox_events::dsl::*;
    let mut conn = pool.get().expect("Impossible d'obtenir la connexion DB");

    let app_name_filter = app_param.into_inner(); // Maintenant, c'est le paramètre

    let results = sandbox_events
        .filter(app_name.eq(app_name_filter)) // Ici, app_name est la colonne Diesel
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
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Échec de connexion à la BDD");

    // État partagé pour la communication avec le script
    let script_state = web::Data::new(ScriptState::new());

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
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
            .service(get_events_by_app)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
