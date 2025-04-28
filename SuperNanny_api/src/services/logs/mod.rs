pub mod handler;
pub mod db;

use actix_web::web;
pub use handler::config as init;

use crate::admin::{Needs, jwt::VIEW_EVENTS};

pub fn init_with_guard(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/events")
            .wrap(Needs(VIEW_EVENTS))
            .configure(handler::config)
    );
}
