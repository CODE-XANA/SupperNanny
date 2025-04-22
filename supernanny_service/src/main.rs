mod auth;
mod events;
mod models;
mod policy;
mod roles;
mod ruleset;
mod state;
mod utils;
mod tls;

use axum::{
    extract::{Extension, Path},
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use dotenvy::dotenv;
use r2d2_postgres::PostgresConnectionManager;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio_postgres::NoTls;
use tower_governor::{
    governor::GovernorConfigBuilder,
    key_extractor::KeyExtractor,
    GovernorError,
    GovernorLayer,
};
use tracing::{debug, info};

use crate::auth::handlers::{login, who_am_i};
use crate::events::log_event;
use crate::policy::handler::{
    add_app_policy, get_policy_requests, process_policy_request, request_policy_change,
};
use crate::roles::get_roles;
use crate::ruleset::handlers::get_ruleset;
use crate::state::AppState;
use crate::tls::generate_self_signed_cert;

#[derive(Clone, Copy)]
pub struct SafeIpExtractor;

impl KeyExtractor for SafeIpExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Result<IpAddr, GovernorError> {
        Ok(req
            .extensions()
            .get::<SocketAddr>()
            .map(|sock| sock.ip())
            .unwrap_or_else(|| {
                debug!("Falling back to 127.0.0.1 for rate-limiting key");
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
            }))
    }
}

// Serve static file response to ACME challenge
async fn serve_acme_challenge(Path(token): Path<String>) -> impl IntoResponse {
    let path = format!("./acme-challenges/{}", token);
    match fs::read_to_string(path) {
        Ok(content) => content.into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Challenge not found").into_response(),
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    // 🔗 DB setup
    let db_url = format!(
        "postgres://{}:{}@{}:{}/{}",
        std::env::var("DB_USER").unwrap(),
        std::env::var("DB_PASS").unwrap(),
        std::env::var("DB_HOST").unwrap(),
        std::env::var("DB_PORT").unwrap(),
        std::env::var("DB_NAME").unwrap()
    );

    let manager = PostgresConnectionManager::new(db_url.parse().unwrap(), NoTls);
    let pool = r2d2::Pool::builder()
        .max_size(10)
        .build(manager)
        .expect("Failed to create connection pool");

    let app_state = AppState { db_pool: pool };

    // 🧠 Rate limiting
    let governor_cfg = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5)
            .burst_size(10)
            .key_extractor(SafeIpExtractor)
            .finish()
            .expect("Failed to build rate limiter"),
    );

    // 🔧 App router
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
        .route("/.well-known/acme-challenge/{token}", get(serve_acme_challenge)) 
        .layer(GovernorLayer {
            config: governor_cfg,
        })
        .layer(Extension(app_state));

    // 🔐 Load TLS config
    let tls_config = generate_self_signed_cert().expect("Failed to generate self-signed TLS");

    let rustls_config = RustlsConfig::from_config(tls_config);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8443));
    info!("🔒 HTTPS server running at https://{}", addr);

    axum_server::bind_rustls(addr, rustls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
