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
    state::{self, JWT_BLACKLIST, random_bytes},
};

/// Permissions…
pub const MANAGE_RULES:  &str = "manage_rules";
pub const MANAGE_ROLES:  &str = "manage_roles";
pub const MANAGE_USERS:  &str = "manage_users";
pub const VIEW_EVENTS:   &str = "view_events";

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminClaims {
    sub:   i32,           // user_admin_id
    perms: Vec<String>,
    exp:   usize,
    pub jti:   String,        // identifiant unique du jeton
}

/// Génère un JWT HS256 avec jti + TTL.
pub fn sign(admin_id: i32, perms: Vec<String>, secret: &str, ttl_min: i64) -> String {
    let now = Utc::now();
    let exp = (now + Duration::minutes(ttl_min)).timestamp() as usize;
    let jti = base64::engine::general_purpose::STANDARD
        .encode(random_bytes::<16>());
    let claims = AdminClaims { sub: admin_id, perms, exp, jti };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
        .expect("jwt encode")
}

/// Retourne les claims SI le token est valide ET non blacklisté.
pub fn verify(token: &str, secret: &str) -> Result<AdminClaims, jsonwebtoken::errors::Error> {
    let data = decode::<AdminClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )?;
    // black-list ?
    if JWT_BLACKLIST.lock().unwrap().contains(&data.claims.jti) {
        return Err(jsonwebtoken::errors::Error::from(
            jsonwebtoken::errors::ErrorKind::InvalidToken,
        ));
    }
    Ok(data.claims)
}

// ---------------------------------------------------------------------------
// Middleware « Needs(permission) »
// ---------------------------------------------------------------------------

/// Attribute carried in App data to say “this scope needs X permission”.
#[derive(Clone)]
pub struct Needs(pub &'static str);

pub struct NeedGuard<S> {
    inner: Arc<S>,
    need:  &'static str,
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

        Box::pin(async move {
            let Some(cookie) = req.cookie("admin_token") else {
                return Ok(req.into_response(HttpResponse::Unauthorized().finish()));
            };

            let claims = match verify(cookie.value(), &secret) {
                Ok(c) => c,
                Err(_) => return Ok(req.into_response(HttpResponse::Unauthorized().finish())),
            };

            if !claims.perms.iter().any(|p| p == need) {
                return Ok(req.into_response(HttpResponse::Forbidden().finish()));
            }

            // stocke les claims pour les handlers en aval
            req.extensions_mut().insert(claims);
            inner.call(req).await
        })
    }
}
