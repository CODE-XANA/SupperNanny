use wasm_bindgen::JsCast;
use web_sys::{RequestCredentials};
use crate::utils::get_cookies;

pub fn some_api_function() {
    let cookies = get_cookies();
    if let Some(access_token) = cookies {
        web_sys::console::log_1(&format!("Access Token: {}", access_token).into());
    }
}
