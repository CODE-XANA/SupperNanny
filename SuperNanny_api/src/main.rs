mod schema;
mod state;
mod utils;
mod admin;
mod services;
mod middleware;
mod tls;

use actix_cors::Cors;
use actix_web::http::header;
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

    // -------- rustls provider global -------------------------------------------
    CryptoProvider::install_default(default_provider())
        .expect("install rustls provider");

    // -------- port HTTPS configurable ------------------------------------------
    let https_port: u16 = env::var("HTTPS_PORT")
        .unwrap_or_else(|_| "9443".into())
        .parse()
        .expect("HTTPS_PORT must be a number");

    // -------- pool Diesel -------------------------------------------------------
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

    let state = AppState::new(pool);

    // -------- TLS config --------------------------------------------------------
    let tls_cfg: ServerConfig = tls::rustls_config().expect("TLS config");

    fn build_cors() -> Cors {
        Cors::default()
            // --- dev -------------------------------------------------------
            .allowed_origin("https://127.0.0.1:8444")  // static_server https
            // --- prod ------------------------------------------------------
            .allowed_origin("https://127.0.0.1")       // port 443 implicite
            // ---------------------------------------------------------------
            .allow_any_method()          // GET/POST/PUT/DELETE/OPTIONS
            .allow_any_header()          // Content-Type, X-CSRF‑Token, …
            .supports_credentials()      // indispensable pour le cookie JWT
            .max_age(3600)
    }

    // -------- app factory -------------------------------------------------------
    let make_app = {
        let state = state.clone();
        move || {
            App::new()
                .app_data(web::Data::new(state.clone()))
                .wrap(IpLimiter)
                .wrap(build_cors())
                .wrap(Logger::default())
                // routes publiques
                .configure(admin::config)
                .configure(logs::init)
                // routes protégées
                .configure(users::init)
                .configure(roles::init)
                .configure(rules::init)
                .configure(logs::init_with_guard)
        }
    };

    // -------- HTTPS -------------------------------------------------------------
    HttpServer::new(make_app)
        .bind_rustls_0_23(("0.0.0.0", https_port), tls_cfg)?
        .run()
        .await
}
