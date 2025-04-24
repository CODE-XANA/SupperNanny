mod schema;
mod state;
mod utils;
mod admin;
mod services;
mod middleware;

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use dotenv::dotenv;
use std::env;

use crate::{
    services::{logs, roles, rules, users},
    middleware::rate_limit::IpLimiter,
    state::AppState,
    utils::logger,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    logger::init();

    // ---------- pool Diesel ----------
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
    let mgr  = ConnectionManager::<PgConnection>::new(url);
    let pool = r2d2::Pool::builder().build(mgr).expect("DB pool");

    let state = AppState::new(pool);

    // ---------- HTTP serveur ----------
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(IpLimiter)
            .wrap(Logger::default())
            .wrap(
                Cors::default()
                    .allowed_origin("http://127.0.0.1:8080")
                    .supports_credentials()
                    .max_age(3_600),
            )
            // --- routes publiques ---
            .configure(admin::config)   // /admin/login /admin/logout
            .configure(logs::init)      // /logs/alert

            // --- routes protégées ---
            .configure(users::init)     // /users/…  (permission gérée dans le module)
            .configure(roles::init)     // /roles/…
            .configure(rules::init)     // /rules/…
            .configure(logs::init_with_guard) // /events/…
    })
    .bind(("127.0.0.1", 8081))?
    .run()
    .await
}
