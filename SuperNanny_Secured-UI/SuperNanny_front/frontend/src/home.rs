use yew::prelude::*;
use wasm_bindgen_futures::spawn_local;
use gloo_net::http::Request;
use web_sys::RequestCredentials;
use crate::utils::get_cookies;
use crate::models::{AppPolicy, SandboxEvent};
use crate::logout::Logout;
use crate::Route;
use log::{error, info};

// Helper pour extraire le CSRF depuis la chaîne de cookies
fn extract_csrf(cookies: &str) -> String {
    cookies
        .split("; ")
        .find(|c| c.starts_with("csrf_token="))
        .map(|c| c.trim_start_matches("csrf_token=").to_string())
        .unwrap_or_default()
}

#[derive(Clone, PartialEq)]
enum AuthStatus {
    Loading,
    Valid,
    Invalid,
}

#[function_component(Home)]
pub fn home() -> Html {
    // Hooks principaux
    let auth_status = use_state(|| AuthStatus::Loading);
    let envs = use_state(|| Vec::<AppPolicy>::new());
    let selected_env = use_state(|| None as Option<AppPolicy>);
    let events = use_state(|| Vec::<SandboxEvent>::new());
    let is_edit_mode = use_state(|| true); // true: édition, false: afficher événements

    // Hooks pour création
    let new_app_name = use_state(|| "".to_string());
    let new_default_ro = use_state(|| "".to_string());
    let new_default_rw = use_state(|| "".to_string());
    let new_tcp_bind = use_state(|| "".to_string());
    let new_tcp_connect = use_state(|| "".to_string());

    // Vérification de l'authentification au montage
    {
        let auth_status_effect = auth_status.clone();
        spawn_local(async move {
            let cookies = get_cookies().unwrap_or_default();
            let csrf_token = extract_csrf(&cookies);
            let resp = Request::get("http://127.0.0.1:8081/check_auth")
                .header("X-CSRF-Token", &csrf_token)
                .credentials(RequestCredentials::Include)
                .send()
                .await;
            match resp {
                Ok(r) if r.status() == 200 => auth_status_effect.set(AuthStatus::Valid),
                _ => auth_status_effect.set(AuthStatus::Invalid),
            }
        });
    }

    // Récupération des configurations si authentification valide
    {
        let envs = envs.clone();
        let auth_status_effect = auth_status.clone();
        let auth_status_dep = (*auth_status_effect).clone();
        use_effect_with_deps(
            move |_| {
                if *auth_status_effect == AuthStatus::Valid {
                    spawn_local(async move {
                        let cookies = get_cookies().unwrap_or_default();
                        let csrf_token = extract_csrf(&cookies);
                        let resp = Request::get("http://127.0.0.1:8081/envs")
                            .credentials(RequestCredentials::Include)
                            .header("X-CSRF-Token", &csrf_token)
                            .send()
                            .await;
                        match resp {
                            Ok(resp) if resp.status() == 200 => {
                                if let Ok(list) = resp.json::<Vec<AppPolicy>>().await {
                                    envs.set(list);
                                }
                            }
                            Ok(resp) => error!("Erreur (envs): status {}", resp.status()),
                            Err(err) => error!("Erreur lors de la requête /envs: {:?}", err),
                        }
                    });
                }
                || ()
            },
            auth_status_dep
        );
    }

    // Récupération des événements pour la configuration sélectionnée
    {
        let selected_env_effect = selected_env.clone();
        let events_effect = events.clone();
        use_effect_with_deps(
            move |selected| {
                if let Some(env) = &**selected {
                    let app_name = env.app_name.clone();
                    spawn_local(async move {
                        let cookies = get_cookies().unwrap_or_default();
                        let csrf_token = extract_csrf(&cookies);
                        let url = format!("http://127.0.0.1:8081/events/{}", app_name);
                        match Request::get(&url)
                            .credentials(RequestCredentials::Include)
                            .header("X-CSRF-Token", &csrf_token)
                            .send()
                            .await
                        {
                            Ok(resp) if resp.status() == 200 => {
                                if let Ok(evts) = resp.json::<Vec<SandboxEvent>>().await {
                                    events_effect.set(evts);
                                }
                            }
                            Ok(resp) => error!("Erreur (events): status {}", resp.status()),
                            Err(err) => error!("Erreur lors de la requête /events: {:?}", err),
                        }
                    });
                } else {
                    events_effect.set(Vec::new());
                }
                || ()
            },
            selected_env.clone()
        );
    }

    // Callback de sélection d'une configuration
    let on_select_env = {
        let selected_env_effect = selected_env.clone();
        Callback::from(move |app_name: String| {
            let selected_env_effect = selected_env_effect.clone();
            let cookies = get_cookies().unwrap_or_default();
            let csrf_token = extract_csrf(&cookies);
            spawn_local(async move {
                let url = format!("http://127.0.0.1:8081/env/{}", app_name);
                match Request::get(&url)
                    .credentials(RequestCredentials::Include)
                    .header("X-CSRF-Token", &csrf_token)
                    .send()
                    .await
                {
                    Ok(resp) if resp.status() == 200 => {
                        if let Ok(policy) = resp.json::<AppPolicy>().await {
                            selected_env_effect.set(Some(policy));
                        }
                    }
                    Ok(resp) => error!("Erreur (detail): status {}", resp.status()),
                    Err(err) => error!("Erreur (detail): {:?}", err),
                }
            });
        })
    };

    // Callback pour update
    let on_update_env = {
        let selected_env_effect = selected_env.clone();
        let envs_effect = envs.clone();
        Callback::from(move |_| {
            if let Some(env_data) = (*selected_env_effect).clone() {
                let cookies = get_cookies().unwrap_or_default();
                let csrf_token = extract_csrf(&cookies);
                let url = format!("http://127.0.0.1:8081/env/{}", env_data.app_name);
                let body = serde_json::json!({
                    "ll_fs_ro": env_data.default_ro.split(':').collect::<Vec<_>>(),
                    "ll_fs_rw": env_data.default_rw.split(':').collect::<Vec<_>>(),
                    "ll_tcp_bind": env_data.tcp_bind,
                    "ll_tcp_connect": env_data.tcp_connect,
                });
                let envs_effect_clone = envs_effect.clone();
                spawn_local(async move {
                    let resp = Request::put(&url)
                        .header("Content-Type", "application/json")
                        .header("X-CSRF-Token", &csrf_token)
                        .credentials(RequestCredentials::Include)
                        .body(serde_json::to_string(&body).unwrap())
                        .unwrap()
                        .send()
                        .await;
                    match resp {
                        Ok(r) if r.status() == 200 => {
                            info!("Mise à jour réussie !");
                            // Rafraîchir la liste
                            let cookies = get_cookies().unwrap_or_default();
                            let csrf_token = extract_csrf(&cookies);
                            let resp = Request::get("http://127.0.0.1:8081/envs")
                                .credentials(RequestCredentials::Include)
                                .header("X-CSRF-Token", &csrf_token)
                                .send()
                                .await;
                            if let Ok(resp) = resp {
                                if resp.status() == 200 {
                                    if let Ok(list) = resp.json::<Vec<AppPolicy>>().await {
                                        envs_effect_clone.set(list);
                                    }
                                }
                            }
                        }
                        Ok(r) => error!("Erreur de mise à jour: status {}", r.status()),
                        Err(err) => error!("Erreur de requête: {:?}", err),
                    }
                });
            }
        })
    };

    // Callback pour delete
    let on_delete_env = {
        let selected_env_effect = selected_env.clone();
        let envs_effect = envs.clone();
        Callback::from(move |_| {
            if let Some(env_data) = (*selected_env_effect).clone() {
                let env_name = env_data.app_name.clone();
                let cookies = get_cookies().unwrap_or_default();
                let csrf_token = extract_csrf(&cookies);
                let envs_effect_clone = envs_effect.clone();
                let selected_env_clone = selected_env_effect.clone();
                spawn_local(async move {
                    let url = format!("http://127.0.0.1:8081/env/{}", env_name);
                    match Request::delete(&url)
                        .header("X-CSRF-Token", &csrf_token)
                        .credentials(RequestCredentials::Include)
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status() == 200 => {
                            info!("Suppression réussie !");
                            // Rafraîchir la liste
                            let cookies = get_cookies().unwrap_or_default();
                            let csrf_token = extract_csrf(&cookies);
                            let resp = Request::get("http://127.0.0.1:8081/envs")
                                .credentials(RequestCredentials::Include)
                                .header("X-CSRF-Token", &csrf_token)
                                .send()
                                .await;
                            if let Ok(resp) = resp {
                                if resp.status() == 200 {
                                    if let Ok(list) = resp.json::<Vec<AppPolicy>>().await {
                                        envs_effect_clone.set(list);
                                    }
                                }
                            }
                            selected_env_clone.set(None);
                        }
                        Ok(resp) => error!("Erreur de suppression: status {}", resp.status()),
                        Err(err) => error!("Erreur de requête: {:?}", err),
                    }
                });
            }
        })
    };

    // Callback pour créer une nouvelle configuration
    let on_create_env = {
        let envs_effect = envs.clone();
        let new_app_name_effect = new_app_name.clone();
        let new_default_ro_effect = new_default_ro.clone();
        let new_default_rw_effect = new_default_rw.clone();
        let new_tcp_bind_effect = new_tcp_bind.clone();
        let new_tcp_connect_effect = new_tcp_connect.clone();
        Callback::from(move |_| {
            let name_val = (*new_app_name_effect).clone();
            let ro_val = (*new_default_ro_effect).clone();
            let rw_val = (*new_default_rw_effect).clone();
            let bind_val = (*new_tcp_bind_effect).clone();
            let connect_val = (*new_tcp_connect_effect).clone();
            let cookies = get_cookies().unwrap_or_default();
            let csrf_token = extract_csrf(&cookies);
            let envs_effect_clone = envs_effect.clone();
            spawn_local(async move {
                let body = serde_json::json!({
                    "app_name": name_val,
                    "default_ro": ro_val,
                    "default_rw": rw_val,
                    "tcp_bind": bind_val,
                    "tcp_connect": connect_val,
                });
                let resp = Request::post("http://127.0.0.1:8081/env")
                    .header("Content-Type", "application/json")
                    .header("X-CSRF-Token", &csrf_token)
                    .credentials(RequestCredentials::Include)
                    .body(serde_json::to_string(&body).unwrap())
                    .unwrap()
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status() == 200 => {
                        info!("Création réussie !");
                        // Rafraîchir la liste
                        let cookies = get_cookies().unwrap_or_default();
                        let csrf_token = extract_csrf(&cookies);
                        let resp = Request::get("http://127.0.0.1:8081/envs")
                            .credentials(RequestCredentials::Include)
                            .header("X-CSRF-Token", &csrf_token)
                            .send()
                            .await;
                        if let Ok(resp) = resp {
                            if resp.status() == 200 {
                                if let Ok(list) = resp.json::<Vec<AppPolicy>>().await {
                                    envs_effect_clone.set(list);
                                }
                            }
                        }
                    }
                    Ok(r) => error!("Erreur lors de la création: status {}", r.status()),
                    Err(err) => error!("Erreur de requête: {:?}", err),
                }
            });
        })
    };

    // Handlers pour les inputs
    let on_new_app_name_input = {
        let new_app_name_effect = new_app_name.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                new_app_name_effect.set(input.value());
            }
        })
    };
    let on_new_default_ro_input = {
        let new_default_ro_effect = new_default_ro.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                new_default_ro_effect.set(input.value());
            }
        })
    };
    let on_new_default_rw_input = {
        let new_default_rw_effect = new_default_rw.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                new_default_rw_effect.set(input.value());
            }
        })
    };
    let on_new_tcp_bind_input = {
        let new_tcp_bind_effect = new_tcp_bind.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                new_tcp_bind_effect.set(input.value());
            }
        })
    };
    let on_new_tcp_connect_input = {
        let new_tcp_connect_effect = new_tcp_connect.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                new_tcp_connect_effect.set(input.value());
            }
        })
    };

    let on_selected_ro_change = {
        let selected_env_effect = selected_env.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(mut env_data) = (*selected_env_effect).clone() {
                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                    env_data.default_ro = input.value();
                    selected_env_effect.set(Some(env_data));
                }
            }
        })
    };
    let on_selected_rw_change = {
        let selected_env_effect = selected_env.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(mut env_data) = (*selected_env_effect).clone() {
                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                    env_data.default_rw = input.value();
                    selected_env_effect.set(Some(env_data));
                }
            }
        })
    };
    let on_selected_bind_change = {
        let selected_env_effect = selected_env.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(mut env_data) = (*selected_env_effect).clone() {
                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                    env_data.tcp_bind = input.value();
                    selected_env_effect.set(Some(env_data));
                }
            }
        })
    };
    let on_selected_connect_change = {
        let selected_env_effect = selected_env.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(mut env_data) = (*selected_env_effect).clone() {
                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                    env_data.tcp_connect = input.value();
                    selected_env_effect.set(Some(env_data));
                }
            }
        })
    };

    // Rendu selon le statut d'authentification
    html! {
        {
            match *auth_status {
                AuthStatus::Loading => html! { <p>{"Chargement..."}</p> },
                AuthStatus::Invalid => html! { <div style="font-weight: bold;">{"403 : Accès refusé"}</div> },
                AuthStatus::Valid => html! {
                    <>
                      <div class="container">
                        <div class="columns">
                          <div class="column" id="config-list">
                            <h3>{ "Configurations existantes" }</h3>
                            <ul>
                              { for envs.iter().map(|env_data| {
                                  let name = env_data.app_name.clone();
                                  html! {
                                    <li onclick={
                                      let on_select_env = on_select_env.clone();
                                      Callback::from(move |_| on_select_env.emit(name.clone()))
                                    }>
                                      { &env_data.app_name }
                                    </li>
                                  }
                              }) }
                            </ul>
                          </div>
                          <div class="column" id="config-details">
                            {
                              if let Some(env_data) = &*selected_env {
                                html! {
                                  <>
                                    <h3>{ format!("Configuration : {}", env_data.app_name) }</h3>
                                    <button class="toggle-button" onclick={
                                        let is_edit_mode_effect = is_edit_mode.clone();
                                        Callback::from(move |_| is_edit_mode_effect.set(!*is_edit_mode_effect))
                                    }>
                                      { if *is_edit_mode { "Voir les événements" } else { "Modifier la configuration" } }
                                    </button>
                                    
                                    {
                                      if *is_edit_mode {
                                        // Mode édition
                                        html! {
                                          <>
                                            <div class="form-group">
                                              <label>{ "LL_FS_RO" }</label>
                                              <input
                                                type="text"
                                                value={env_data.default_ro.clone()}
                                                oninput={on_selected_ro_change.clone()}
                                              />
                                            </div>
                                            <div class="form-group">
                                              <label>{ "LL_FS_RW" }</label>
                                              <input
                                                type="text"
                                                value={env_data.default_rw.clone()}
                                                oninput={on_selected_rw_change.clone()}
                                              />
                                            </div>
                                            <div class="form-group">
                                              <label>{ "TCP_BIND" }</label>
                                              <input
                                                type="text"
                                                value={env_data.tcp_bind.clone()}
                                                oninput={on_selected_bind_change.clone()}
                                              />
                                            </div>
                                            <div class="form-group">
                                              <label>{ "TCP_CONNECT" }</label>
                                              <input
                                                type="text"
                                                value={env_data.tcp_connect.clone()}
                                                oninput={on_selected_connect_change.clone()}
                                              />
                                            </div>
                                            <div class="btn-group">
                                              <button onclick={on_update_env.clone()}>{ "Enregistrer" }</button>
                                              <button onclick={on_delete_env.clone()} class="btn-danger">
                                                { "Supprimer" }
                                              </button>
                                            </div>
                                          </>
                                        }
                                      } else {
                                        // Mode affichage des événements
                                        html! {
                                          <>
                                            <h4>{ "Événements" }</h4>
                                            <ul id="events-list">
                                              { for events.iter().map(|evt| {
                                                  html! {
                                                    <li>{ format!("{} - {} - {}", evt.timestamp, evt.operation, evt.result) }</li>
                                                  }
                                              }) }
                                            </ul>
                                          </>
                                        }
                                      }
                                    }
                                  </>
                                }
                              } else {
                                html! { <p>{ "Sélectionnez une configuration pour voir les détails." }</p> }
                              }
                            }
                          </div>
                          <div class="column" id="config-create">
                            <h3>{ "Créer une nouvelle configuration" }</h3>
                            <div class="form-group">
                              <label>{ "Nom du programme" }</label>
                              <input
                                type="text"
                                value={(*new_app_name).clone()}
                                oninput={on_new_app_name_input.clone()}
                              />
                            </div>
                            <div class="form-group">
                              <label>{ "LL_FS_RO (séparé par ':')" }</label>
                              <input
                                type="text"
                                value={(*new_default_ro).clone()}
                                oninput={on_new_default_ro_input.clone()}
                              />
                            </div>
                            <div class="form-group">
                              <label>{ "LL_FS_RW (séparé par ':')" }</label>
                              <input
                                type="text"
                                value={(*new_default_rw).clone()}
                                oninput={on_new_default_rw_input.clone()}
                              />
                            </div>
                            <div class="form-group">
                              <label>{ "TCP_BIND" }</label>
                              <input
                                type="text"
                                value={(*new_tcp_bind).clone()}
                                oninput={on_new_tcp_bind_input.clone()}
                              />
                            </div>
                            <div class="form-group">
                              <label>{ "TCP_CONNECT" }</label>
                              <input
                                type="text"
                                value={(*new_tcp_connect).clone()}
                                oninput={on_new_tcp_connect_input.clone()}
                              />
                            </div>
                            <button onclick={on_create_env} class="btn-create">
                              { "Créer la configuration" }
                            </button>
                          </div>
                        </div>
                      </div>
                    </>
                }
            }
        }
    }
}

// Helper pour refetch la liste après update/delete/create
async fn refetch_envs(envs_state: &UseStateHandle<Vec<AppPolicy>>) {
    let cookies = get_cookies().unwrap_or_default();
    let csrf_token = extract_csrf(&cookies);

    match Request::get("http://127.0.0.1:8081/envs")
        .credentials(RequestCredentials::Include)
        .header("X-CSRF-Token", &csrf_token)
        .send()
        .await
    {
        Ok(resp) if resp.status() == 200 => {
            match resp.json::<Vec<AppPolicy>>().await {
                Ok(json) => envs_state.set(json),
                Err(err) => error!("Erreur de désérialisation (refetch): {:?}", err),
            }
        }
        Ok(resp) => error!("Erreur refetch: statut {}", resp.status()),
        Err(err) => error!("Erreur refetch: {:?}", err),
    }
}
