use actix_web::{delete, get, post, put, web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use std::fs;
use std::path::Path;

const ENV_DIR: &str = "/home/vmubuntu/Bureau/rust-landlock/application_conf";

/// Endpoint pour récupérer la liste des fichiers .env
#[get("/envs")]
async fn get_envs() -> impl Responder {
    let mut programs = Vec::new();

    match fs::read_dir(ENV_DIR) {
        Ok(entries) => {
            for entry in entries.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    // Filtrer les fichiers suivant le format "rules.<program>.env"
                    if file_name.starts_with("rules.") && file_name.ends_with(".env") {
                        let start = "rules.".len();
                        let end = file_name.len() - ".env".len();
                        let prog = &file_name[start..end];
                        programs.push(prog.to_string());
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

/// Endpoint pour lire le contenu d'un fichier selon le programme
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

/// Structure pour la création d'un fichier .env via POST
#[derive(Deserialize)]
struct EnvData {
    program: String,
    ll_fs_ro: String,
    ll_fs_rw: String,
    ll_tcp_bind: Option<String>,
    ll_tcp_connect: Option<String>,
}

/// Endpoint pour créer ou mettre à jour un fichier .env (création initiale)
#[post("/env")]
async fn create_env(data: web::Json<EnvData>) -> impl Responder {
    let data = data.into_inner();
    // Utiliser des valeurs par défaut si non renseignées
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

/// Structure pour la modification d'un fichier .env via PUT  
/// Les listes sont attendues sous forme de tableau de chaînes pour faciliter les modifications côté frontend.
#[derive(Deserialize)]
struct UpdateEnvData {
    ll_fs_ro: Vec<String>,
    ll_fs_rw: Vec<String>,
    ll_tcp_bind: Option<String>,
    ll_tcp_connect: Option<String>,
}

/// Endpoint pour modifier le contenu d'un fichier .env existant
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

    // Lire le contenu existant pour récupérer les valeurs TCP si non modifiées
    let current_content = fs::read_to_string(&file_path).unwrap_or_default();
    let mut current_tcp_bind = "9418".to_string();
    let mut current_tcp_connect = "80:443".to_string();
    for line in current_content.lines() {
        if line.starts_with("export LL_TCP_BIND=") {
            current_tcp_bind = line.trim_start_matches("export LL_TCP_BIND=")
                .trim_matches('"')
                .to_string();
        }
        if line.starts_with("export LL_TCP_CONNECT=") {
            current_tcp_connect = line.trim_start_matches("export LL_TCP_CONNECT=")
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

/// Endpoint pour supprimer un fichier .env
#[delete("/env/{program}")]
async fn delete_env(program: web::Path<String>) -> impl Responder {
    let program = program.into_inner();
    let file_path = format!("{}/rules.{}.env", ENV_DIR, program);
    if !Path::new(&file_path).exists() {
        return HttpResponse::NotFound().body(format!("Fichier non trouvé pour '{}'", program));
    }

    match fs::remove_file(&file_path) {
        Ok(_) => HttpResponse::Ok().body("Fichier supprimé avec succès"),
        Err(e) => HttpResponse::InternalServerError()
            .body(format!("Erreur lors de la suppression du fichier : {}", e)),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(get_envs)
            .service(get_env_content)
            .service(create_env)
            .service(update_env)
            .service(delete_env)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
