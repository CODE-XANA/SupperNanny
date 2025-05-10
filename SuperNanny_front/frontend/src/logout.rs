use yew::prelude::*;
use yew_router::prelude::*;
use gloo_net::http::Method;

use crate::{api::fetch_json, Route};

#[function_component(Logout)]
pub fn logout() -> Html {
    let navigator = use_navigator().unwrap();

    let onclick = Callback::from(move |_| {
        let navigator = navigator.clone();

        wasm_bindgen_futures::spawn_local(async move {
            // GET /admin/logout pour expirer JWT + CSRF
            let _ : Result<(), _> = fetch_json::<(), ()>(Method::GET, "/admin/logout", None).await;

            // retour à la page de login et rafraîchissement
            navigator.replace(&Route::Login);
            web_sys::window().unwrap().location().reload().unwrap();
        });
    });

    html! { <button {onclick}>{ "Déconnexion" }</button> }
}
