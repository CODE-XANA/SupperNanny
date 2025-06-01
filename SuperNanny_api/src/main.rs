mod schema;
mod state;
mod utils;
mod admin;
mod services;
mod middleware;
mod tls;

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use dotenv::dotenv;
use rustls::crypto::{ring::default_provider, CryptoProvider};
use rustls::ServerConfig;
use std::env;

use crate::{
    middleware::rate_limit::IpLimiter,
    services::{logs, roles, rules, users},
    state::AppState,
    utils::logger,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    logger::init();

    // Mount du provider rustls
    CryptoProvider::install_default(default_provider())
        .expect("install rustls provider");

    // Lecture du port HTTPS
    let https_port: u16 = env::var("HTTPS_PORT")
        .unwrap_or_else(|_| "9443".into())
        .parse()
        .expect("HTTPS_PORT must be a number");

    // Connexion PostgreSQL + pool
    let url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            env::var("DB_USER").unwrap_or_else(|_| "postgres".into()),
            env::var("DB_PASS").unwrap_or_default(),
            env::var("DB_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
            env::var("DB_PORT").unwrap_or_else(|_| "5432".into()),
            env::var("DB_NAME").unwrap_or_else(|_| "postgres".into()),
        )
    });

    let pool = r2d2::Pool::builder()
        .build(ConnectionManager::<PgConnection>::new(url))
        .expect("DB pool");

    // Crée l’état (AppState) avec le pool
    let state = AppState::new(pool.clone());

    // Configuration TLS
    let tls_cfg: ServerConfig = tls::rustls_config().expect("TLS config");

    // CORS (autorise le front à 127.0.0.1:8444 en dev, puis 127.0.0.1 en prod)
    fn build_cors() -> Cors {
        Cors::default()
            .allowed_origin("https://127.0.0.1:8444")
            .allowed_origin("https://127.0.0.1")
            .allow_any_method()
            .allow_any_header()
            .supports_credentials()
            .max_age(3600)
    }

    // Factory pour créer l’App
    let make_app = {
        let state = state.clone();
        let db_pool = pool.clone(); 
        move || {
            App::new()
                // 1) Enregistrement de AppState dans le Data<>
                .app_data(web::Data::new(state.clone()))
                // 2) Middleware rate limiter (avec accès au pool)
                .wrap(IpLimiter::new(db_pool.clone()))
                // 3) CORS + logger
                .wrap(build_cors())
                .wrap(Logger::default())
                // 4) Routes publiques (login, logout, etc.)
                .configure(admin::config)
                // 5) /logs (protégé par CSRF et JWT Needs(VIEW_EVENTS))
                .configure(logs::init)
                // 6) Autres endpoints protégés
                .configure(users::init)
                .configure(roles::init)
                .configure(rules::init)
                // 7) Événements (exemple : /events, Need Guard)
                .configure(logs::init_with_guard)
        }
    };

    // On lie le serveur sur le port HTTPS configuré
    HttpServer::new(make_app)
        .bind_rustls_0_23(("0.0.0.0", https_port), tls_cfg)?
        .run()
        .await
}
