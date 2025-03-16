use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use js_sys::Reflect;
use web_sys::{window, HtmlDocument};

pub fn get_cookies() -> Option<String> {
    // Récupère la fenêtre et le document
    let document = window()?.document()?;
    // Convertit le document en HtmlDocument
    let html_doc: &HtmlDocument = document.unchecked_ref();
    // Appelle la méthode cookie() et renvoie le résultat s'il y a
    html_doc.cookie().ok()
}