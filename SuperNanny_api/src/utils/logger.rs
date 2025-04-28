//! Init d’`env_logger` avec une valeur par défaut.

use std::env;

pub fn init() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "info,actix_web=info,diesel=warn");
    }
    env_logger::init();
}
