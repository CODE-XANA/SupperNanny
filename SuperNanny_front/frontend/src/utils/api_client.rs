use gloo_net::http::Request;
use wasm_bindgen::JsCast;
use web_sys::RequestCredentials;

fn csrf() -> String {
    web_sys::window()
        .unwrap()
        .document()
        .unwrap()
        .cookie()
        .unwrap_or_default()
        .split("; ")
        .find(|c| c.starts_with("csrf_token="))
        .map(|c| c.trim_start_matches("csrf_token=").to_string())
        .unwrap_or_default()
}

/// construit une requête pré‑configurée
pub fn api(method: &str, url: &str) -> Request {
    Request::new(url)
        .unwrap()
        .method(method)
        .credentials(RequestCredentials::Include)
        .header("X-CSRF-Token", &csrf())
}
