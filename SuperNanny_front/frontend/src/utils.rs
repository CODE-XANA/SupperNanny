//! Helpers simples (cookies…).

use wasm_bindgen::JsCast;
use web_sys::{window, HtmlDocument};

/// Renvoie la chaîne complète des cookies.
pub fn get_cookies() -> Option<String> {
    let document = window()?.document()?;
    let html_doc: &HtmlDocument = document.unchecked_ref();
    html_doc.cookie().ok()
}
