use gloo_net::http::{Method, Request};
use gloo_net::Error;
use serde::{Serialize, de::DeserializeOwned};
use wasm_bindgen::JsValue;
use js_sys;
use web_sys::{window, RequestCredentials};
use js_sys::Reflect;

/* URL de base de l'API */
const BASE: &str = "https://127.0.0.1:8443";

/* Récupère le cookie csrf_token=… dans document.cookie */
fn csrf_from_cookie() -> Option<String> {
    // 1) window / document
    let doc = window()?.document()?;
    // 2) document.cookie via JS Reflect
    let cookie_js = Reflect::get(doc.as_ref(), &JsValue::from_str("cookie")).ok()?;
    let cookie_str = cookie_js.as_string()?;
    // 3) Cherche "csrf_token="
    cookie_str
        .split(';')
        .find_map(|kv| kv.trim().strip_prefix("csrf_token=").map(|v| v.to_string()))
}

/* Appel JSON générique */
pub async fn fetch_json<T, U>(
    method: Method,
    path: &str,
    body: Option<&T>,
) -> Result<U, Error>
where
    T: Serialize + ?Sized,
    U: DeserializeOwned,
{
    let url = format!("{BASE}{path}");
    let builder = match method {
        Method::GET => Request::get(&url),
        Method::POST => Request::post(&url),
        Method::PUT => Request::put(&url),
        Method::PATCH => Request::patch(&url),
        Method::DELETE => Request::delete(&url),
        _ => Request::get(&url),
    }
    .credentials(RequestCredentials::Include);
    
    let builder = if let Some(csrf) = csrf_from_cookie() {
        builder.header("X-CSRF-Token", &csrf)
    } else {
        builder
    };
    
    // Envoi + parse JSON
    let resp = if let Some(b) = body {
        builder.json(b)?.send().await?
    } else {
        builder.send().await?
    };
    
    resp.json().await
}

/// Appel DELETE "vide" (204 / 200 sans JSON) avec CSRF
pub async fn fetch_empty<T>(
    method: Method,
    path:   &str,
    body:   Option<&T>,                     // ← 3ᵉ paramètre facultatif
) -> Result<(), Error>
where
    T: Serialize + ?Sized,
{
    let url      = format!("{BASE}{path}");
    let mut req  = match method {
        Method::DELETE => Request::delete(&url),
        Method::PUT    => Request::put(&url),
        Method::POST   => Request::post(&url),
        _              => unreachable!("fetch_empty : DELETE / PUT / POST uniquement"),
    }
    .credentials(RequestCredentials::Include);

    if let Some(csrf) = csrf_from_cookie() {
        req = req.header("X-CSRF-Token", &csrf);
    }

    // PUT / POST → éventuel body JSON
    let resp = match (method, body) {
        (Method::PUT | Method::POST, Some(b)) => req.json(b)?.send().await?,
        _                                     => req.send().await?,
    };

    match resp.status() {
        200 | 204 => Ok(()),
        s => {
            // gloo‑net n’a **pas** de variant `Error::Response` : on encapsule tout
            let msg = format!("HTTP {} – {}", s, resp.status_text());
            Err(Error::JsError(js_sys::Error::new(&msg).into()))
        }
    }
}