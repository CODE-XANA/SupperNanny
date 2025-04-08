mod state;
mod auth;
mod roles;
mod ruleset;
mod models;
mod events;


use axum::{Router, routing::{get, post}, extract::Extension};

use std::net::SocketAddr;
use tracing::info;
use dotenvy::dotenv;

use auth::handlers::{login, who_am_i};
use roles::get_roles;
use ruleset::get_ruleset;
use state::AppState;
use crate::events::log_event;

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    let db_url = format!(
        "postgres://{}:{}@{}:{}/{}",
        std::env::var("DB_USER").unwrap(),
        std::env::var("DB_PASS").unwrap(),
        std::env::var("DB_HOST").unwrap(),
        std::env::var("DB_PORT").unwrap(),
        std::env::var("DB_NAME").unwrap()
    );

    let manager = r2d2_postgres::PostgresConnectionManager::new(
        db_url.parse().unwrap(),
        postgres::NoTls,
    );
    let pool = r2d2::Pool::builder().max_size(10).build(manager).expect("Failed to create pool");
    let app_state = AppState { db_pool: pool };

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/auth/login", post(login))
        .route("/whoami", get(who_am_i))
        .route("/auth/roles", get(get_roles))
        .route("/auth/ruleset", get(get_ruleset))
        .route("/events/log", post(log_event))
        .layer(Extension(app_state));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3005));
    info!("Starting server on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
