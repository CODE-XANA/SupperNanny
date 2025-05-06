use yew::prelude::*;
use yew_router::prelude::*;
use wasm_bindgen_futures::spawn_local;
use gloo_net::http::Request;
use web_sys::{HtmlInputElement, RequestCredentials};

use crate::Route;

/* -------------------------------------------------------------------------- */
/*                     structures échangées avec l’API                         */
/* -------------------------------------------------------------------------- */

#[derive(serde::Serialize)]
struct LoginBody {
    username: String,
    password: String,
}

#[derive(serde::Deserialize)]
struct MeResponse {
    username: String,
    perms:    Vec<String>,
}

/* -------------------------------------------------------------------------- */
/*                    mapping « perms »  →  route cible                        */
/* -------------------------------------------------------------------------- */

fn route_for_perms(perms: &[String]) -> Route {
    if perms.contains(&"manage_users".into()) {
        Route::ManageUsers
    } else if perms.contains(&"manage_roles".into()) {
        Route::ManageRoles
    } else if perms.contains(&"manage_rules".into()) {
        Route::Configurations
    } else {
        Route::Dashboard
    }
}

/* -------------------------------------------------------------------------- */
/*                               composant login                               */
/* -------------------------------------------------------------------------- */

#[function_component(LoginForm)]
pub fn login_form() -> Html {
    let navigator      = use_navigator().unwrap();
    let username_ref   = use_node_ref();
    let password_ref   = use_node_ref();
    let message_state  = use_state(|| String::new());

    /* ------------------ callback du <form onsubmit=…> --------------------- */
    let onsubmit = {
        let username_ref   = username_ref.clone();
        let password_ref   = password_ref.clone();
        let message_state  = message_state.clone();
        let navigator      = navigator.clone();

        Callback::from(move |ev: yew::events::SubmitEvent| {
            ev.prevent_default();

            let username = username_ref
                .cast::<HtmlInputElement>()
                .unwrap()
                .value();
            let password = password_ref
                .cast::<HtmlInputElement>()
                .unwrap()
                .value();

            /* --------------- étape 1 : /admin/login ----------------------- */
            spawn_local({
                let message_state = message_state.clone();
                let navigator     = navigator.clone();

                async move {
                    let login_resp = Request::post("https://127.0.0.1:8443/admin/login")
                        .header("Content-Type", "application/json")
                        .credentials(RequestCredentials::Include)
                        .json(&LoginBody { username, password })
                        .unwrap()
                        .send()
                        .await;

                    match login_resp {
                        Ok(r) if r.status() == 200 => {
                            /* ---------- étape 2 : /admin/me --------------- */
                            let me = Request::get("https://127.0.0.1:8443/admin/me")
                                .credentials(RequestCredentials::Include)
                                .send()
                                .await;

                            match me {
                                Ok(me_r) if me_r.status() == 200 => {
                                    match me_r.json::<MeResponse>().await {
                                        Ok(me_json) => {
                                            navigator.push(&route_for_perms(&me_json.perms));
                                        }
                                        Err(_) => {
                                            message_state.set("Réponse /admin/me invalide".into());
                                        }
                                    }
                                }
                                _ => message_state.set("Impossible d’appeler /admin/me".into()),
                            }
                        }
                        Ok(r) => message_state.set(format!("Échec : status {}", r.status())),
                        Err(e) => message_state.set(format!("Erreur réseau : {e:?}")),
                    }
                }
            });
        })
    };

    /* ---------------------------- rendu ---------------------------------- */
    html! {
        <div class="login-container">
            <h2>{"Connexion administrateur"}</h2>

            <form {onsubmit}>
                <input ref={username_ref} type="text"     placeholder="Nom d'utilisateur" />
                <input ref={password_ref} type="password" placeholder="Mot de passe" />
                <button type="submit">{"Se connecter"}</button>
            </form>

            {
                if !message_state.is_empty() {
                    html!(<p style="color:red;">{ &*message_state }</p>)
                } else {
                    Html::default()
                }
            }
        </div>
    }
}
