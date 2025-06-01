use actix_service::{forward_ready, Service, Transform};
use actix_web::{
    body::BoxBody,
    dev::{ServiceRequest, ServiceResponse},
    Error, HttpResponse, HttpMessage
};
use crate::{
    services::logs::db::insert as record_security_event,
    state::DbPool,
    admin::jwt,
    admin::db::get_admin_username,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::sync::Arc;

const MAX_REQ_PER_MIN: u32 = 100;

pub struct IpLimiter {
    pub db_pool: DbPool,
}

impl IpLimiter {
    pub fn new(db_pool: DbPool) -> Self {
        Self { db_pool }
    }
}

pub struct Inner<S> {
    srv: Arc<S>,
    db_pool: DbPool,
}

impl<S> Transform<S, ServiceRequest> for IpLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = Inner<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, srv: S) -> Self::Future {
        ready(Ok(Inner {
            srv: Arc::new(srv),
            db_pool: self.db_pool.clone(),
        }))
    }
}

impl<S> Service<ServiceRequest> for Inner<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error    = Error;
    type Future   = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(srv);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        use crate::state::{now, RATE_LIMIT};

        let ip = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_string();

        // Gestion du compteur rate-limit
        let should_block = {
            let mut map = RATE_LIMIT.lock().unwrap();
            let entry = map.entry(ip.clone()).or_insert((0, now() + 60));
            if now() > entry.1 {
                *entry = (0, now() + 60);
            }
            entry.0 += 1;
            entry.0 > MAX_REQ_PER_MIN
        };

        if should_block {
            // On récupère le pool pour pouvoir interroger la DB
            let db_pool = self.db_pool.clone();
            let ip_for_log = ip.clone();

            // Essaie de décoder le JWT (si présent) pour récupérer l’admin_id
            // puis le transformer en username. Si échec, username restera None.
            let username_opt = if let Some(cookie) = req.cookie("admin_token") {
                let secret = std::env::var("JWT_SECRET").unwrap();
                if let Ok(claims) = jwt::verify(cookie.value(), &secret) {
                    // get_admin_username renvoie Result<Option<String>, _>
                    match get_admin_username(&db_pool, claims.sub) {
                        Ok(opt) => opt,      // Some(username) ou None si introuvable
                        Err(_)   => None,
                    }
                } else {
                    None
                }
            } else {
                None
            };

            Box::pin(async move {
                // Insère la ligne de log avec l’username (ou None) + IP, action, etc.
                if let Err(e) = record_security_event(
                    &db_pool,
                    username_opt.as_deref(),       // Option<&str>
                    Some(&ip_for_log),
                    "rate_limit_block",
                    Some("100 req/min exceeded"),
                    "warning",                     // doit respecter le CHECK (info|warning|critical)
                ) {
                    eprintln!("Failed to record security event: {}", e);
                }

                // Retourne 429 Too Many Requests sans exécuter l’handler appelant
                Ok(req.into_response(HttpResponse::TooManyRequests().finish()))
            })
        } else {
            let srv = self.srv.clone();
            Box::pin(async move { srv.call(req).await })
        }
    }
}
