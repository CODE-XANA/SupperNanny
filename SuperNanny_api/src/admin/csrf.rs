use actix_service::{forward_ready, Service, Transform};
use actix_web::{
    body::BoxBody,
    dev::{ServiceRequest, ServiceResponse},
    Error, HttpResponse,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::sync::Arc;

use crate::{
    services::logs::db::insert as record_security_event,
    state::AppState,
};

/* -------------------------------------------------------------------------- */
/* Middleware – vérification du jeton CSRF                                    */
/* -------------------------------------------------------------------------- */
#[derive(Clone)]
pub struct Csrf;

pub struct Guard<S> {
    inner: Arc<S>,
}

impl<S> Transform<S, ServiceRequest> for Csrf
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
{
    type Response  = ServiceResponse<BoxBody>;
    type Error     = Error;
    type InitError = ();
    type Transform = Guard<S>;
    type Future    = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, srv: S) -> Self::Future {
        ready(Ok(Guard { inner: Arc::new(srv) }))
    }
}

impl<S> Service<ServiceRequest> for Guard<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error    = Error;
    type Future   = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(inner);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let require_check = matches!(req.method().as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
        let inner         = self.inner.clone();
        let ip            = req.connection_info().realip_remote_addr().unwrap_or("unknown").to_string();
        let pool          = req
            .app_data::<actix_web::web::Data<AppState>>()
            .map(|d| d.db.clone());

        Box::pin(async move {
            if require_check {
                let valid = matches!(
                    (req.cookie("csrf_token"), req.headers().get("x-csrf-token")),
                    (Some(c), Some(h)) if h == c.value()
                );

                if !valid {
                    if let Some(pool) = pool {
                        let _ = record_security_event(
                            &pool,
                            None,
                            Some(&ip),
                            "csrf_mismatch",
                            None,
                            "warning",
                        );
                    }
                    let resp = HttpResponse::Forbidden().finish().map_into_boxed_body();
                    return Ok(req.into_response(resp));
                }
            }

            inner.call(req).await
        })
    }
}
