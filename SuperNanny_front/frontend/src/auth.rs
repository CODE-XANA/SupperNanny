//! frontend/src/auth.rs
use std::collections::HashSet;
use gloo_net::http::Method;
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::{api::fetch_json, session::Session, Route};

/* -------------------------------------------------------------------------- */
/*                       structures échangées avec l’API                      */
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
/*     mapping perms → 1ʳᵉ route à afficher après connexion                    */
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
/*                               composant Login                              */
/* -------------------------------------------------------------------------- */

#[function_component(LoginForm)]
pub fn login_form() -> Html {
    // refs pour les champs
    let username_ref = use_node_ref();
    let password_ref = use_node_ref();

    // états locaux
    let message    = use_state(String::new);
    let submitting = use_state(|| false);

    // navigateur et contexte de session
    let navigator  = use_navigator().unwrap();
    let session_ctx = use_context::<UseStateHandle<Option<Session>>>();

    // callback du form
    let onsubmit = {
        let message     = message.clone();
        let submitting  = submitting.clone();
        let navigator   = navigator.clone();
        let session_ctx = session_ctx.clone();
        let username_ref = username_ref.clone();
        let password_ref = password_ref.clone();

        Callback::from(move |ev: SubmitEvent| {
            ev.prevent_default();

            let username = username_ref
                .cast::<web_sys::HtmlInputElement>()
                .unwrap()
                .value();
            let password = password_ref
                .cast::<web_sys::HtmlInputElement>()
                .unwrap()
                .value();

            spawn_local({
                let message     = message.clone();
                let submitting  = submitting.clone();
                let navigator   = navigator.clone();
                let session_ctx = session_ctx.clone();

                async move {
                    // on bloque le formulaire
                    submitting.set(true);
                    message.set(String::new());

                    // 1) POST /admin/login
                    let login_res = fetch_json::<LoginBody, serde_json::Value>(
                        Method::POST,
                        "/admin/login",
                        Some(&LoginBody { username, password }),
                    )
                    .await;

                    match login_res {
                        Err(_) => {
                            // code HTTP ≠ 200 ou erreur réseau
                            message.set("Accès refusé : nom d’utilisateur ou mot de passe invalide".into());
                        }
                        Ok(_) => {
                            // 2) GET /admin/me
                            match fetch_json::<(), MeResponse>(Method::GET, "/admin/me", None::<&()>).await {
                                Err(_) => {
                                    message.set("Impossible de récupérer les informations de l’utilisateur".into());
                                }
                                Ok(me) => {
                                    // 2.a) on met à jour la session
                                    if let Some(ctx) = session_ctx {
                                        ctx.set(Some(Session {
                                            username: me.username.clone(),
                                            perms:    me.perms.iter().cloned().collect::<HashSet<_>>(),
                                        }));
                                    }
                                    // 2.b) redirection selon les perms
                                    navigator.push(&route_for_perms(&me.perms));
                                }
                            }
                        }
                    }

                    // on débloque le formulaire
                    submitting.set(false);
                }
            });
        })
    };

    html! {
        <div class="login-container">
            <div class="login-page">
                <h2>{ "Connexion administrateur" }</h2>
                <form {onsubmit}>
                    <input
                        ref={username_ref}
                        type="text"
                        placeholder="Nom d’utilisateur"
                        disabled={*submitting}
                    />
                    <input
                        ref={password_ref}
                        type="password"
                        placeholder="Mot de passe"
                        disabled={*submitting}
                    />
                    <button type="submit" disabled={*submitting}>
                        { if *submitting { "Connexion …" } else { "Se connecter" } }
                    </button>
                </form>

                {
                    if !message.is_empty() {
                        html!(<p>{ &*message }</p>)
                    } else {
                        Html::default()
                    }
                }
            </div>
        </div>
    }
}
