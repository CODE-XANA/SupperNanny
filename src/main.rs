use actix_web::{get, post, web, App, HttpServer, HttpResponse, Responder};
use actix_web::web::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::process::Output;
use std::thread;
use tokio::process::Command;
use std::sync::mpsc;
use std::sync::Mutex;
use regex::Regex;


/* ---------- Struct pour les données ---------- */

#[derive(Serialize, Deserialize, Clone)]
struct Rule {
    id: String,
    description: String,
    pattern: String,
    action: String,
    enabled: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct Application {
    id: String,
    name: String,
    path: String,
    rules: Vec<Rule>,
    // custom_rules: HashMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Data {
    applications: Vec<Application>,
}

struct AppState {
    data: Mutex<Data>,
}

#[derive(Deserialize)]
struct DeleteRequest {
    name: String,
    confirm: Option<bool>,
}

/* --------------------------------------------- */



/* ----------------- Fonctions ----------------- */

/// Lecture des données depuis un JSON
fn read_data_from_file(path: &str) -> Data {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
        .expect("Impossible d'ouvrir le fichier JSON.");
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Erreur de lecture du fichier.");
    if contents.is_empty() {
        Data { applications: vec![] }
    } else {
        serde_json::from_str(&contents).expect("Erreur de parsing JSON.")
    }
}

/// Écriture dans le fichier JSON
fn write_data_to_file(path: &str, data: &Data) {
    let json = serde_json::to_string_pretty(data).expect("Erreur de sérialisation JSON.");
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .expect("Impossible d'ouvrir le fichier JSON.");
    file.write_all(json.as_bytes()).expect("Erreur d'écriture dans le fichier JSON.");
}

/// Supression d'App
fn delete_application(applications: &mut Vec<Application>, name: &str) -> bool {
    if let Some(index) = applications.iter().position(|app| app.name == name) {
        applications.remove(index);
        true
    } else {
        false
    }
}

/// Lecture des logs
pub fn read_logs_by_application(file_path: &str) -> io::Result<HashMap<String, Vec<String>>> {
    let mut logs_by_app = HashMap::new();

    if let Ok(file) = File::open(file_path) {
        let lines = BufReader::new(file).lines();

        for line in lines {
            if let Ok(log) = line {
                if let Some((app_name, horodatage, log_message)) = parse_log_entry(&log) {
                    logs_by_app
                        .entry(app_name.clone())
                        .or_insert_with(Vec::new)
                        .push(format!("[{}] {}", horodatage, log_message));
                }
            }
        }
    }

    Ok(logs_by_app)
}

/// Parse des logs
fn parse_log_entry(log: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = log.split_whitespace().collect();
    
    if parts.len() < 5 {
        return None;  // Évite les logs incomplets
    }

    // Extraire les parties essentielles
    let app_name_with_id = parts[0]; // Les logs ressemblents à "Discord-44616...". vérifier le nom de l'app
    let horodatage = format!("{} {} {}", parts[1], parts[2], parts[3]); // Logs ressemblent à "[011] ...21 27939.679778" on vérifie ça
    
    // Extraire le vrai nom de l'application
    let app_name = app_name_with_id.split_once('-').map(|(name, _)| name.to_lowercase());

    // Tout ce qui reste après ":" est le message complet
    if let Some((_, message)) = log.split_once(": ") {
        return Some((
            app_name?,
            horodatage,
            message.trim().to_string(),
        ));
    }

    None
}

/// Fonction pour le script Python
async fn run_python_script(script_path: &str) -> io::Result<Output> {
    Command::new("python3")
    .arg(script_path) 
    .output()
    .await
}

/// Charge les applications depuis `data.json`
fn load_applications() -> Vec<String> {
    let file = File::open("data.json").expect("[ERREUR] Impossible d'ouvrir data.json");
    let reader = BufReader::new(file);
    let data: serde_json::Value = serde_json::from_reader(reader).expect("[ERREUR] Parsing JSON");

    let apps: Vec<String> = data["applications"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|app| app["name"].as_str().map(|s| s.to_lowercase()))
        .collect();

    apps
}

/// Regex pour l'app
fn build_app_regex() -> Regex {
    let app_names = load_applications();
    
    if app_names.is_empty() {
        eprintln!("[ERREUR] Aucune application surveillée trouvée !");
    }

    let pattern = format!(r"(?i)^\s*({})-\d+", app_names.join("|")); // (?i) pour ignorer la casse, \s* = pour ignorer les espaces

    Regex::new(&pattern).expect("[ERREUR] Construction du regex")
}

/// Vérification disposition logs
fn is_log_valid(log: &str, app_regex: &Regex, app_names: &[String]) -> bool {
    let log_cleaned = log.trim(); // Supprime les espaces en début/fin

    // Vérification avec Regex
    if app_regex.is_match(log_cleaned) {
        return true;
    }

    // Vérification manuelle (au cas où la regex ne fonctionne pas)
    for app in app_names {
        if log_cleaned.to_lowercase().contains(&format!("{}-", app)) {
            return true;
        }
    }

    false
}

/* --------------------------------------------- */



/* --------------- Endpoints API --------------- */

/// Récupérer les logs
#[get("/logs/{application}")]
async fn get_logs_for_application(app_name: web::Path<String>) -> impl Responder {
    let file_path = "logs.txt";
    let app_name = app_name.into_inner().to_lowercase();

    match read_logs_by_application(file_path) {
        Ok(logs_by_app) => {
            if let Some(app_logs) = logs_by_app.get(&app_name) {
                HttpResponse::Ok().json(app_logs.clone())
            } else {
                HttpResponse::NotFound().body(format!("Aucun log trouvé pour l'application : {}", app_name))
            }
        }
        Err(err) => {
            HttpResponse::InternalServerError().body(format!("Erreur lors de la lecture des logs : {}", err))
        }
    }
}

/// Récupérer la liste des applications
#[get("/applications")]
async fn get_applications(data: web::Data<AppState>) -> impl Responder {
    let data = data.data.lock().unwrap();
    let applications: Vec<_> = data.applications.iter().map(|app| app.name.clone()).collect();
    web::Json(applications)
}

/// Récupérer le nom de l'user
#[get("/user/{application}")]
async fn get_user(data: web::Data<AppState>, app_name: web::Path<String>) -> impl Responder {
    let app_name = app_name.into_inner().to_lowercase();
    let data = data.data.lock().unwrap();

    // Vérifie si l'application existe
    if data.applications.iter().any(|a| a.name == app_name) {
        let current_user = whoami::username();
        web::Json(current_user)
    } else {
        web::Json("Application introuvable".to_string())
    }
}

/// Récupérer les règles standards pour une application
#[get("/rules/{application}")]
async fn get_rules(data: web::Data<AppState>, app_name: web::Path<String>) -> impl Responder {
    let app_name = app_name.into_inner().to_lowercase();
    let data = data.data.lock().unwrap();
    if let Some(app) = data.applications.iter().find(|a| a.name == app_name) {
        web::Json(app.rules.clone())
    } else {
        web::Json(Vec::<Rule>::new())
    }
}

/// Mettre à jour une règle standard
#[post("/rules/{application}")]
async fn update_rule(
    data: web::Data<AppState>,
    app_name: web::Path<String>,
    updated_rule: web::Json<Rule>,
) -> impl Responder {
    let app_name = app_name.into_inner().to_lowercase();
    let mut data = data.data.lock().unwrap();
    if let Some(app) = data.applications.iter_mut().find(|a| a.name == app_name) {
        if let Some(rule) = app.rules.iter_mut().find(|r| r.id == updated_rule.id) {
            *rule = updated_rule.into_inner();
            write_data_to_file("data.json", &*data);
            return "Règle mise à jour";
        }
    }
    "Application ou règle introuvable"
}

/*
/// Récupérer les règles personnalisées pour une application (network_blacklist, file_blacklist)
#[get("/custom_rules/{application}/{type}")]
async fn get_custom_rules(
    data: web::Data<AppState>,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (app_name, rule_type) = path.into_inner();
    let data = data.data.lock().unwrap();
    if let Some(app) = data.applications.iter().find(|a| a.name == app_name) {
        if let Some(custom_rules) = app.custom_rules.get(&rule_type) {
            return web::Json(custom_rules.clone());
        }
    }
    web::Json(Vec::<String>::new())
}

/// Ajouter une règle personnalisée (ajout dans network_blacklist ou file_blacklist)
#[post("/custom_rules/{application}/{type}/add")]
async fn add_custom_rule(
    data: web::Data<AppState>,
    path: web::Path<(String, String)>,
    new_rule: web::Json<String>,
) -> impl Responder {
    let (app_name, rule_type) = path.into_inner();
    let mut data = data.data.lock().unwrap();
    if let Some(app) = data.applications.iter_mut().find(|a| a.name == app_name) {
        app.custom_rules
            .entry(rule_type.clone())
            .or_insert_with(Vec::new)
            .push(new_rule.into_inner());
        write_data_to_file("data.json", &*data);
        return "Règle ajoutée";
    }
    "Application introuvable"
}

/// Supprimer une règle personnalisée
#[post("/custom_rules/{application}/{type}/remove")]
async fn remove_custom_rule(
    data: web::Data<AppState>,
    path: web::Path<(String, String)>,
    rule_to_remove: web::Json<String>,
) -> impl Responder {
    let (app_name, rule_type) = path.into_inner();
    let mut data = data.data.lock().unwrap();
    if let Some(app) = data.applications.iter_mut().find(|a| a.name == app_name) {
        if let Some(blacklist) = app.custom_rules.get_mut(&rule_type) {
            let rule_to_remove_value = rule_to_remove.into_inner();
            blacklist.retain(|rule| rule != &rule_to_remove_value);
            write_data_to_file("data.json", &*data);
            return "Règle supprimée";
        }
    }
    "Application ou règle introuvable"
}
*/

/// Récupérer le path des applications
#[get("/path/{application}")]
async fn get_application_path(
    data: web::Data<AppState>,
    app_name: web::Path<String>,
) -> impl Responder {
    let app_name = app_name.into_inner().to_lowercase();
    let data = data.data.lock().unwrap();
    if let Some(app) = data.applications.iter().find(|a| a.name == app_name) {
        web::Json(app.path.clone())
    } else {
        web::Json("Application introuvable".to_string())
    }
}

/// Ajouter une application
#[post("/add_application")]
async fn add_application(
    data: web::Data<AppState>,
    new_app: web::Json<(String, String)>,
) -> impl Responder {
    let (name, path) = new_app.into_inner();
    let name = name.to_lowercase();

    // Vérification des champs vides
    if name.trim().is_empty() || path.trim().is_empty() {
        return actix_web::HttpResponse::BadRequest().body("Le nom et le chemin de l'application sont obligatoires.");
    }

    let mut data = data.data.lock().unwrap();

    // Générer un nouvel ID
    let new_id = (data.applications.len() + 1).to_string();

    // Les règles standard
    let default_rules = vec![
        Rule {
            id: "1".to_string(),
            description: "Interdire l'accès aux clés SSH privées".to_string(),
            pattern: "~/.ssh/id_rsa".to_string(),
            action: "block".to_string(),
            enabled: false,
        },
        Rule {
            id: "2".to_string(),
            description: "Bloquer l'accès aux hashes des mots de passe".to_string(),
            pattern: "/etc/shadow".to_string(),
            action: "block".to_string(),
            enabled: false,
        },
        Rule {
            id: "3".to_string(),
            description: "Empêcher la modification des logs de sécurité".to_string(),
            pattern: "/var/log/auth.log".to_string(),
            action: "block".to_string(),
            enabled: false,
        },
        Rule {
            id: "4".to_string(),
            description: "Bloquer l'accès au fichier des mots de passe système".to_string(),
            pattern: "/etc/passwd".to_string(),
            action: "block".to_string(),
            enabled: true,
        },
        Rule {
            id: "5".to_string(),
            description: "Bloquer la suppression des journaux système".to_string(),
            pattern: "/var/log/syslog".to_string(),
            action: "block".to_string(),
            enabled: false,
        }
    ];
    

    // Ajouter la nouvelle application
    data.applications.push(Application {
        id: new_id,
        name,
        path,
        rules: default_rules,
        //custom_rules: HashMap::new(),
    });

    // Mettre à jour le fichier JSON
    write_data_to_file("data.json", &*data);

    actix_web::HttpResponse::Ok().body("Nouvelle application ajoutée")
}

/// Supprimer une application
#[post("/remove_application")]
async fn remove_application(
    state: web::Data<AppState>,
    req: web::Json<DeleteRequest>,
) -> impl Responder {
    let mut applications = state.data.lock().unwrap();

    // Validation de l'entrée
    if req.name.trim().is_empty() {
        return HttpResponse::BadRequest().body("Le nom de l'application est obligatoire.");
    }

    if let Some(true) = req.confirm {
        if delete_application(&mut applications.applications, &req.name) {
            write_data_to_file("data.json", &*applications);
            return HttpResponse::Ok().body("Application supprimée.");
        } else {
            return HttpResponse::NotFound().body("Application introuvable.");
        }        
    }

    if applications.applications.iter().any(|app| app.name == req.name) {
        return HttpResponse::Ok().body(format!(
            "Confirmez-vous la suppression de l'application '{}' ?",
            req.name
        ));
    }
    

    HttpResponse::NotFound().body("Application introuvable.")
}

/// Lancer le script
#[post("/run_script")]
async fn run_script_endpoint() -> impl Responder {

    // Path du script à modifier ici
    let script_path = "/home/user/Downloads/SuperNanny/appapi/insert_data_to_map.py";

    match run_python_script(script_path).await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "stdout": stdout,
                "stderr": stderr
            }))
        }
        Err(err) => HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "message": err.to_string()
        })),
    }
}

#[get("/sse/logs")]
async fn sse_logs() -> impl Responder {
    let (tx, rx) = mpsc::channel();
    let trace_pipe_path = "/sys/kernel/debug/tracing/trace_pipe";
    let log_destination = "logs.txt";
    let app_regex = build_app_regex();
    let app_names = load_applications();

    eprintln!("[DEBUG] Ouverture de trace_pipe...");

    thread::spawn(move || {
        let file = match File::open(trace_pipe_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("[ERREUR] Impossible d'ouvrir trace_pipe: {}", e);
                return;
            }
        };

        let reader = BufReader::new(file);
        eprintln!("[DEBUG] Début de la lecture des logs...");

        for line in reader.lines() {
            match line {
                Ok(log) => {
                    let log_cleaned = log.trim_start(); // Supprime les espaces/tabs au début

		    // Voir si logs detecté
                    if is_log_valid(&log_cleaned, &app_regex, &app_names) {

                        // Écriture sans tabulation dans logs.txt
                        if let Ok(mut file) = OpenOptions::new().append(true).create(true).open(log_destination) {
                            let _ = writeln!(file, "{}", log_cleaned);
                        }

                        // Envoi en SSE sans tabulation
                        if tx.send(log_cleaned.to_string()).is_err() {
                            break;
                        }
                    }
                }
                Err(_e) => {
                    break;
                }
            }
        }
    });

    HttpResponse::Ok()
        .insert_header(("Content-Type", "text/event-stream"))
        .insert_header(("Cache-Control", "no-cache"))
        .insert_header(("Connection", "keep-alive"))
        .streaming(futures_util::stream::iter(rx.into_iter().map(|item| {
            Ok::<Bytes, std::io::Error>(Bytes::from(format!("data: {}\n\n", item)))
        })))
}

/* --------------------------------------------- */



/* -------------------- Main ------------------- */

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let data_path = "data.json";

    /*for app in &mut data.applications {
        app.custom_rules
            .entry("network_blacklist".to_string())
            .or_insert_with(Vec::new);
        app.custom_rules
            .entry("file_blacklist".to_string())
            .or_insert_with(Vec::new);
    }*/

    let data = read_data_from_file(data_path);
    let app_state = web::Data::new(AppState {
        data: Mutex::new(data),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .service(get_applications)
            .service(get_rules)
            .service(update_rule)
            //.service(get_custom_rules)
            //.service(add_custom_rule)
            //.service(remove_custom_rule)
            .service(add_application) 
            .service(get_application_path)
            .service(get_user)
            .service(remove_application)
            .service(get_logs_for_application) 
            .service(run_script_endpoint)
            .service(sse_logs)
    })
    .bind("127.0.0.1:8000")?
    .run()
    .await
}

/* --------------------------------------------- */