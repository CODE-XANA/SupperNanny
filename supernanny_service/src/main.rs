mod auth;
mod events;
mod models;
mod policy;
mod roles;
mod ruleset;
mod state;
mod utils;

use axum::{
    extract::Extension,
    http::Request,
    routing::{get, post},
    Router,
};
use dotenvy::dotenv;
use r2d2_postgres::PostgresConnectionManager;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio;
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::KeyExtractor,
    GovernorError,
    GovernorLayer,
};
use tracing::info;

use crate::auth::handlers::{login, who_am_i};
use crate::events::log_event;
use crate::policy::handler::{
    add_app_policy, get_policy_requests, process_policy_request, request_policy_change,
};
use crate::roles::get_roles;
use crate::ruleset::handlers::get_ruleset;
use crate::state::AppState;

#[derive(Clone, Copy)]
pub struct SafeIpExtractor;

impl KeyExtractor for SafeIpExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Result<IpAddr, GovernorError> {
        Ok(req.extensions()
            .get::<SocketAddr>()
            .map(|sock| sock.ip())
            .unwrap_or_else(|| {
                tracing::debug!("Falling back to 127.0.0.1 for rate-limiting key");
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
            }))
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    // 🌐 DB connection
    let db_url = format!(
        "postgres://{}:{}@{}:{}/{}",
        std::env::var("DB_USER").unwrap(),
        std::env::var("DB_PASS").unwrap(),
        std::env::var("DB_HOST").unwrap(),
        std::env::var("DB_PORT").unwrap(),
        std::env::var("DB_NAME").unwrap()
    );

    let manager = PostgresConnectionManager::new(db_url.parse().unwrap(), postgres::NoTls);
    let pool = r2d2::Pool::builder()
        .max_size(10)
        .build(manager)
        .expect("Failed to create pool");

    let app_state = AppState { db_pool: pool };

    // 🚦 Rate limiting configuration
    let governor_cfg = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(10)
            .key_extractor(SafeIpExtractor)
            .finish()
            .expect("Failed to build GovernorConfig"),
    );

    // 🚀 Build router
    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/auth/login", post(login))
        .route("/whoami", get(who_am_i))
        .route("/auth/roles", get(get_roles))
        .route("/auth/ruleset", get(get_ruleset))
        .route("/auth/ruleset/update", post(add_app_policy))
        .route("/events/log", post(log_event))
        .route("/policy/request", post(request_policy_change))
        .route("/admin/policy/requests", get(get_policy_requests))
        .route("/admin/policy/requests/{request_id}", post(process_policy_request))
        .layer(GovernorLayer {
            config: governor_cfg,
        })
        .layer(Extension(app_state));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3005));
    info!("🚀 Server running at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
