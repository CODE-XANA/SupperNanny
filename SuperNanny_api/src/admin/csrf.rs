use actix_service::{forward_ready, Service, Transform};
use actix_web::{
    body::BoxBody,
    dev::{ServiceRequest, ServiceResponse},
    Error, HttpResponse,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::sync::Arc;

/* -------------------------------------------------------------------------- */
/*                      Middleware – vérif. du jeton CSRF                      */
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

        Box::pin(async move {
            if require_check {
                // Cookie + header doivent être présents & identiques
                match (req.cookie("csrf_token"), req.headers().get("x-csrf-token")) {
                    (Some(c), Some(h)) if h == c.value() => {}
                    _ => {
                        let resp = HttpResponse::Forbidden().finish().map_into_boxed_body();
                        return Ok(req.into_response(resp));
                    }
                }
            }

            inner.call(req).await
        })
    }
}
