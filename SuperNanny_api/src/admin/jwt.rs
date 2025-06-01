// src/admin/jwt.rs

use actix_service::{forward_ready, Service, Transform};
use actix_web::{
    body::BoxBody,
    dev::{ServiceRequest, ServiceResponse},
    Error as ActixErr, HttpResponse, HttpMessage,
};
use chrono::{Duration, Utc};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{
    services::logs::db::insert as record_security_event,
    state::{JWT_BLACKLIST, random_bytes, AppState},
    admin::db::get_admin_username,
};

/// ---------------------------------------------------------------------
/// Permissions declared in JWT
/// ---------------------------------------------------------------------
pub const MANAGE_RULES: &str = "manage_rules";
pub const MANAGE_ROLES: &str = "manage_roles";
pub const MANAGE_USERS: &str = "manage_users";
pub const VIEW_EVENTS: &str = "view_events";

/// ---------------------------------------------------------------------
/// JWT claims
/// ---------------------------------------------------------------------
#[derive(Debug, Serialize, Deserialize)]
pub struct AdminClaims {
    pub sub:   i32,
    pub perms: Vec<String>,
    exp:       usize,
    pub jti:   String,
}

/// ---------------------------------------------------------------------
/// Helpers – sign / verify
/// ---------------------------------------------------------------------
pub fn sign(admin_id: i32, perms: Vec<String>, secret: &str, ttl_min: i64) -> String {
    let exp = (Utc::now() + Duration::minutes(ttl_min)).timestamp() as usize;
    let jti = base64::engine::general_purpose::STANDARD
        .encode(random_bytes::<16>());
    let claims = AdminClaims { sub: admin_id, perms, exp, jti };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
        .expect("jwt encode")
}

pub fn verify(token: &str, secret: &str) -> Result<AdminClaims, jsonwebtoken::errors::Error> {
    let data = decode::<AdminClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )?;
    if JWT_BLACKLIST.lock().unwrap().contains(&data.claims.jti) {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ));
    }
    Ok(data.claims)
}

/// ---------------------------------------------------------------------
/// Middleware Needs(permission)
/// ---------------------------------------------------------------------
#[derive(Clone)]
pub struct Needs(pub &'static str);

pub struct NeedGuard<S> {
    inner:  Arc<S>,
    need:   &'static str,
    secret: String,
}

impl<S> Transform<S, ServiceRequest> for Needs
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = ActixErr> + 'static,
{
    type Response  = ServiceResponse<BoxBody>;
    type Error     = ActixErr;
    type InitError = ();
    type Transform = NeedGuard<S>;
    type Future    = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, srv: S) -> Self::Future {
        let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET");
        ready(Ok(NeedGuard {
            inner: Arc::new(srv),
            need:  self.0,
            secret,
        }))
    }
}

impl<S> Service<ServiceRequest> for NeedGuard<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = ActixErr> + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error    = ActixErr;
    type Future   = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(inner);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let inner  = self.inner.clone();
        let secret = self.secret.clone();
        let need   = self.need;
        let ip     = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_string();

        // Récupèrer le pool Diesel depuis AppState
        let pool   = req
            .app_data::<actix_web::web::Data<AppState>>()
            .map(|d| d.db.clone());

        Box::pin(async move {
            // 1) Vérifier la présence du cookie JWT
            let cookie = if let Some(c) = req.cookie("admin_token") {
                c
            } else {
                if let Some(pool) = &pool {
                    let _ = record_security_event(
                        pool,
                        None,
                        Some(&ip),
                        "missing_jwt",
                        None,
                        "warning",
                    );
                }
                return Ok(req.into_response(HttpResponse::Unauthorized().finish()));
            };

            // 2) Vérifier la validité du JWT
            let claims = match verify(cookie.value(), &secret) {
                Ok(c) => c,
                Err(_) => {
                    if let Some(pool) = &pool {
                        let _ = record_security_event(
                            pool,
                            None,
                            Some(&ip),
                            "invalid_jwt",
                            None,
                            "warning",
                        );
                    }
                    return Ok(req.into_response(HttpResponse::Unauthorized().finish()));
                }
            };

            // 3) Vérifier que la permission requise est présente dans le token
            if !claims.perms.iter().any(|p| p == need) {
                if let Some(pool) = &pool {
                    // Récupère le username depuis l'ID dans les claims
                    let username_opt = get_admin_username(pool, claims.sub)
                        .unwrap_or(None);

                    let _ = record_security_event(
                        pool,
                        username_opt.as_deref(),
                        Some(&ip),
                        "forbidden_access",
                        Some(need),
                        "warning",
                    );
                }
                return Ok(req.into_response(HttpResponse::Forbidden().finish()));
            }

            // 4) Tout est bon → stocke les claims pour les handlers en aval
            req.extensions_mut().insert(claims);
            inner.call(req).await
        })
    }
}
