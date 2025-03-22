use yew::prelude::*;
use yew_router::prelude::*;
use gloo_net::http::Request;
use web_sys::RequestCredentials;
use crate::Route;
use crate::utils::get_cookies;

#[function_component(Logout)]
pub fn logout() -> Html {
    let navigator = use_navigator().unwrap();

    let onclick = Callback::from(move |_| {
        let navigator = navigator.clone();
        // Récupérer les cookies pour extraire le token CSRF
        let cookies = get_cookies().unwrap_or_default();
        let csrf_token = cookies
            .split("; ")
            .find(|c| c.starts_with("csrf_token="))
            .map(|c| c.trim_start_matches("csrf_token=").to_string())
            .unwrap_or_default();

        wasm_bindgen_futures::spawn_local(async move {
            // Appeler l'endpoint /logout en incluant les cookies et l'en-tête CSRF
            let result = Request::post("http://127.0.0.1:8081/logout")
                .header("X-CSRF-Token", &csrf_token)
                .credentials(RequestCredentials::Include)
                .send()
                .await;
            match result {
                Ok(resp) if resp.status() == 200 => {
                    // Redirection vers la page de login après déconnexion réussie
                    navigator.push(&Route::Login);
                }
                Ok(resp) => {
                    log::error!("Erreur lors de la déconnexion, statut: {}", resp.status());
                }
                Err(err) => {
                    log::error!("Erreur lors de la requête de déconnexion: {:?}", err);
                }
            }
        });
    });

    html! {
        <button {onclick}>{ "Déconnexion" }</button>
    }
}
