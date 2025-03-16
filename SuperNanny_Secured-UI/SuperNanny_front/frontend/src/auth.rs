use yew::prelude::*;
use yew_router::prelude::*;
use wasm_bindgen_futures::spawn_local;
use gloo::console::log;
use gloo_net::http::Request;
use web_sys::RequestCredentials;
use web_sys::HtmlInputElement;
use crate::Route;

#[function_component(LoginForm)]
pub fn login_form() -> Html {
    let navigator = use_navigator().unwrap();
    let password_ref = use_node_ref();
    let message = use_state(|| String::new());

    let onsubmit = {
        let password_ref = password_ref.clone();
        let message = message.clone();
        let navigator = navigator.clone();

        Callback::from(move |event: yew::events::SubmitEvent| {
            event.prevent_default();
            let password_element = password_ref.cast::<HtmlInputElement>()
                .expect("L'élément n'est pas un HtmlInputElement");
            let password = password_element.value();

            let message_async = message.clone();
            let navigator = navigator.clone();
            spawn_local(async move {
                let request = Request::post("http://127.0.0.1:8081/login")
                    .header("Content-Type", "application/json")
                    // On inclut les credentials pour que les cookies soient bien envoyés
                    .credentials(RequestCredentials::Include)
                    .json(&LoginRequest { password })
                    .expect("Erreur lors de la sérialisation JSON")
                    .send()
                    .await;

                match request {
                    Ok(resp) if resp.status() == 200 => {
                        log!("Connexion réussie !");
                        message_async.set("Connexion réussie".to_string());
                        // Rediriger vers la page des environnements
                        navigator.push(&Route::Envs);
                    }
                    Ok(resp) => {
                        log!(format!("Échec de la connexion : statut {}", resp.status()));
                        message_async.set("Mot de passe incorrect".to_string());
                    }
                    Err(err) => {
                        log!(format!("Erreur lors de la requête : {:?}", err));
                        message_async.set("Erreur lors de la connexion".to_string());
                    }
                }
            });
        })
    };

    html! {
        <div>
            <h2>{ "Connexion" }</h2>
            <form {onsubmit}>
                <input ref={password_ref} type="password" placeholder="Mot de passe" />
                <button type="submit">{ "Se connecter" }</button>
            </form>
            <p>{ (*message).clone() }</p>
        </div>
    }
}

#[derive(serde::Serialize)]
pub struct LoginRequest {
    pub password: String,
}
