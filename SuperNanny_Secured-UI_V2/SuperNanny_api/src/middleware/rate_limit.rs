use actix_service::{forward_ready, Service, Transform};
use actix_web::{
    body::BoxBody,
    dev::{ServiceRequest, ServiceResponse},
    Error, HttpResponse,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::sync::Arc;

const MAX_REQ_PER_MIN: u32 = 100;

pub struct IpLimiter;

pub struct Inner<S> { srv: Arc<S> }

impl<S> Transform<S, ServiceRequest> for IpLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
{
    type Response  = ServiceResponse<BoxBody>;
    type Error     = Error;
    type InitError = ();
    type Transform = Inner<S>;
    type Future    = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, srv: S) -> Self::Future {
        ready(Ok(Inner { srv: Arc::new(srv) }))
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

        {
            let mut map = RATE_LIMIT.lock().unwrap();
            let entry = map.entry(ip).or_insert((0, now() + 60));
            if now() > entry.1 { *entry = (0, now() + 60); }
            entry.0 += 1;
            if entry.0 > MAX_REQ_PER_MIN {
                return Box::pin(async move {
                    Ok(req.into_response(HttpResponse::TooManyRequests().finish()))
                });
            }
        }

        let srv = self.srv.clone();
        Box::pin(async move { srv.call(req).await })
    }
}
