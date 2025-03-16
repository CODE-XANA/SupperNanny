use yew::prelude::*;
use wasm_bindgen_futures::spawn_local;
use gloo::console::log;
use gloo_net::http::Request;
use web_sys::RequestCredentials;
use crate::utils::get_cookies;
use serde::Serialize;

#[function_component(ProtectedTest)]
pub fn protected_test() -> Html {
    let response_msg = use_state(|| String::new());

    let onclick = {
        let response_msg = response_msg.clone();
        Callback::from(move |_| {
            let response_msg = response_msg.clone();

            // Récupère les cookies via notre fonction utilitaire
            let cookies = get_cookies().unwrap_or_else(|| "".to_string());
            log!(format!("Cookies actuels: {}", cookies));

            // Par exemple, on extrait ici le token CSRF (à adapter selon votre format de cookie)
            // On peut utiliser une bibliothèque comme `cookie` (crate) pour parser les cookies.
            // On suppose que le cookie "csrf_token" est présent dans la chaîne.
            let csrf_token = cookies
                .split("; ")
                .find(|c| c.starts_with("csrf_token="))
                .map(|c| c.trim_start_matches("csrf_token=").to_string())
                .unwrap_or_default();
            log!(format!("CSRF Token récupéré: {}", csrf_token));

            spawn_local(async move {
                let result = Request::get("http://127.0.0.1:8081/protected")
                    .credentials(RequestCredentials::Include) // On inclut les cookies
                    .header("X-CSRF-Token", &csrf_token)
                    .send()
                    .await;

                match result {
                    Ok(resp) if resp.status() == 200 => {
                        log!("Accès autorisé à /protected");
                        response_msg.set("Accès autorisé".to_string());
                    }
                    Ok(resp) => {
                        log!(format!("Erreur sur /protected: {}", resp.status()));
                        response_msg.set(format!("Erreur: {}", resp.status()));
                    }
                    Err(err) => {
                        log!(format!("Erreur lors de l'appel /protected: {:?}", err));
                        response_msg.set("Erreur lors de l'appel".to_string());
                    }
                }
            });
        })
    };

    html! {
        <div>
            <button {onclick}>{ "Tester /protected" }</button>
            <p>{ (*response_msg).clone() }</p>
        </div>
    }
}
