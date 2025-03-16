use yew::prelude::*;
use yew_router::prelude::*;
use web_sys::{window, Document};
use js_sys::Reflect;
use wasm_bindgen::JsValue;
use crate::Route;

#[function_component(Logout)]
pub fn logout() -> Html {
    let navigator = use_navigator().unwrap();
    let onclick = {
        let navigator = navigator.clone();
        Callback::from(move |_| {
            if let Some(document) = window().and_then(|w| w.document()) {
                // Supprimer le cookie "access_token"
                let _ = Reflect::set(
                    &document,
                    &JsValue::from_str("cookie"),
                    &JsValue::from_str("access_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/"),
                );
                // Supprimer le cookie "csrf_token"
                let _ = Reflect::set(
                    &document,
                    &JsValue::from_str("cookie"),
                    &JsValue::from_str("csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/"),
                );
                web_sys::console::log_1(&JsValue::from_str("Cookies supprimés, déconnexion réussie"));
            }
            // Redirige vers la page de connexion
            navigator.push(&Route::Login);
        })
    };

    html! {
        <button {onclick}>{ "Déconnexion" }</button>
    }
}
