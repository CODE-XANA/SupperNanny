mod state;
mod auth;
mod roles;
mod ruleset;
mod models;
mod events;

use axum::{
    Router,
    extract::Extension,
    routing::{get, post},
};
use tower_governor::{
    GovernorLayer,
    governor::GovernorConfigBuilder,
    key_extractor::SmartIpKeyExtractor,
};
use std::{net::SocketAddr, sync::Arc};
use tracing::info;
use dotenvy::dotenv;

use auth::handlers::{login, who_am_i};
use roles::get_roles;
use ruleset::get_ruleset;
use crate::events::log_event;
use state::AppState;

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

    let pool = r2d2::Pool::builder()
        .max_size(10)
        .build(manager)
        .expect("Failed to create pool");

    let app_state = AppState { db_pool: pool };

    // ✅ Governor config with Arc
    let governor_cfg = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(10)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("Failed to build GovernorConfig"),
    );

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/auth/login", post(login))
        .route("/whoami", get(who_am_i))
        .route("/auth/roles", get(get_roles))
        .route("/auth/ruleset", get(get_ruleset))
        .route("/events/log", post(log_event))
        .layer(GovernorLayer {
            config: governor_cfg.clone(),
        })
        .layer(Extension(app_state));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3005));
    info!("🚀 Server running at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app).await.unwrap();
}
