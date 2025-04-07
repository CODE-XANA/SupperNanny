use yew::prelude::*;
use wasm_bindgen_futures::spawn_local;
use gloo_net::http::Request;
use web_sys::{RequestCredentials, HtmlSelectElement};
use gloo_timers::callback::Interval;
use crate::utils::get_cookies;
use log::{error, info};

/// Extraction du CSRF depuis la chaîne de cookies
fn extract_csrf(cookies: &str) -> String {
    cookies
        .split("; ")
        .find(|c| c.starts_with("csrf_token="))
        .map(|c| c.trim_start_matches("csrf_token=").to_string())
        .unwrap_or_default()
}

/// État d'authentification
#[derive(Clone, PartialEq)]
enum AuthStatus {
    Loading,
    Valid,
    Invalid,
}

/// Représentation d'un rôle (pour /roles)
#[derive(Clone, PartialEq, serde::Deserialize, serde::Serialize, Debug)]
struct Role {
    pub role_id: i32,
    pub role_name: String,
}

/// Représentation d'une policy (ligne de `app_policy`)
#[derive(Clone, PartialEq, serde::Deserialize, serde::Serialize, Debug)]
pub struct AppPolicy {
    pub policy_id: i32,
    pub app_name: String,
    pub role_id: i32,
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
    pub allowed_ips: String,
    pub allowed_domains: String,
    /// On le met en string pour simplifier l'affichage
    pub updated_at: String,
}

/// Représentation d'un événement sandbox
#[derive(Clone, PartialEq, serde::Deserialize, serde::Serialize, Debug)]
pub struct SandboxEvent {
    pub event_id: i32,
    pub timestamp: String,
    pub hostname: String,
    pub app_name: String,
    pub denied_path: Option<String>,
    pub operation: String,
    pub result: String,
    // etc.
}

#[function_component(Configurations)]
pub fn configurations() -> Html {
    // ------------------------------------------------------------------
    // ÉTATS
    // ------------------------------------------------------------------
    let auth_status = use_state(|| AuthStatus::Loading);

    // Liste complète des policies récupérées depuis l’API
    let envs = use_state(|| Vec::<AppPolicy>::new());
    // Policy actuellement sélectionnée (pour édition / affichage)
    let selected_env = use_state(|| None as Option<AppPolicy>);
    // Liste des événements pour la config sélectionnée
    let events = use_state(|| Vec::<SandboxEvent>::new());
    // Toggle entre mode édition et mode "affichage événements"
    let is_edit_mode = use_state(|| true);

    // Liste de tous les rôles
    let roles = use_state(|| Vec::<Role>::new());
    // ID du rôle sélectionné, ici -1 signifie "aucun rôle choisi"
    let selected_role = use_state(|| -1);
    // NodeRef pour le <select> des rôles (pour un contrôle explicite de sa valeur)
    let role_select_ref = use_node_ref();

    // Pour créer une nouvelle configuration (POST /env)
    let new_app_name = use_state(|| "".to_string());
    let new_default_ro = use_state(|| "".to_string());
    let new_default_rw = use_state(|| "".to_string());
    let new_tcp_bind = use_state(|| "".to_string());
    let new_tcp_connect = use_state(|| "".to_string());
    let new_allowed_ips = use_state(|| "".to_string());
    let new_allowed_domains = use_state(|| "".to_string());

    // ------------------------------------------------------------------
    // 1) Vérification de l'authentification
    // ------------------------------------------------------------------
    {
        let auth_status_clone = auth_status.clone();
        use_effect_with_deps(
            move |_| {
                spawn_local(async move {
                    let cookies = get_cookies().unwrap_or_default();
                    let csrf_token = extract_csrf(&cookies);
                    let resp = Request::get("http://127.0.0.1:8081/check_auth")
                        .header("X-CSRF-Token", &csrf_token)
                        .credentials(RequestCredentials::Include)
                        .send()
                        .await;
                    match resp {
                        Ok(r) if r.status() == 200 => auth_status_clone.set(AuthStatus::Valid),
                        _ => auth_status_clone.set(AuthStatus::Invalid),
                    }
                });
                || ()
            },
            (),
        );
    }
    {
        let auth_status_clone = auth_status.clone();
        use_effect_with_deps(
            move |_| {
                let interval = Interval::new(10_000, move || {
                    let auth_status_inner = auth_status_clone.clone();
                    spawn_local(async move {
                        let cookies = get_cookies().unwrap_or_default();
                        let csrf_token = extract_csrf(&cookies);
                        let resp = Request::get("http://127.0.0.1:8081/check_auth")
                            .header("X-CSRF-Token", &csrf_token)
                            .credentials(RequestCredentials::Include)
                            .send()
                            .await;
                        match resp {
                            Ok(r) if r.status() == 200 => auth_status_inner.set(AuthStatus::Valid),
                            _ => auth_status_inner.set(AuthStatus::Invalid),
                        }
                    });
                });
                || drop(interval)
            },
            (),
        );
    }

    // ------------------------------------------------------------------
    // 2) Chargement des rôles via GET /roles
    // ------------------------------------------------------------------
    {
        let roles_state = roles.clone();
        use_effect_with_deps(
            move |auth_dep: &AuthStatus| {
                if *auth_dep == AuthStatus::Valid {
                    spawn_local(async move {
                        let cookies = get_cookies().unwrap_or_default();
                        let csrf_token = extract_csrf(&cookies);
                        let resp = Request::get("http://127.0.0.1:8081/roles")
                            .credentials(RequestCredentials::Include)
                            .header("X-CSRF-Token", &csrf_token)
                            .send()
                            .await;
                        match resp {
                            Ok(r) if r.status() == 200 => {
                                if let Ok(role_list) = r.json::<Vec<Role>>().await {
                                    roles_state.set(role_list);
                                }
                            }
                            Ok(r) => error!("Erreur GET /roles: status {}", r.status()),
                            Err(e) => error!("Erreur requête GET /roles: {:?}", e),
                        }
                    });
                }
                || ()
            },
            (*auth_status).clone(),
        );
    }
    // Conserver le placeholder du <select> jusqu'à ce qu'un rôle soit choisi
    {
        let select_ref = role_select_ref.clone();
        let current_val = selected_role.to_string();
        use_effect_with_deps(
            move |(cv,): &(String,)| {
                if let Some(sel) = select_ref.cast::<HtmlSelectElement>() {
                    sel.set_value(cv);
                    info!("Re-applied <select> value: {}", cv);
                }
                || ()
            },
            (current_val,),
        );
    }

    // ------------------------------------------------------------------
    // 3) Chargement des configurations (envs) via GET /envs
    // ------------------------------------------------------------------
    {
        let envs_state = envs.clone();
        use_effect_with_deps(
            move |auth_dep: &AuthStatus| {
                if *auth_dep == AuthStatus::Valid {
                    spawn_local(async move {
                        let cookies = get_cookies().unwrap_or_default();
                        let csrf_token = extract_csrf(&cookies);
                        let resp = Request::get("http://127.0.0.1:8081/envs")
                            .credentials(RequestCredentials::Include)
                            .header("X-CSRF-Token", &csrf_token)
                            .send()
                            .await;
                        match resp {
                            Ok(r) if r.status() == 200 => {
                                if let Ok(list) = r.json::<Vec<AppPolicy>>().await {
                                    envs_state.set(list);
                                }
                            }
                            Ok(r) => error!("Erreur GET /envs: status {}", r.status()),
                            Err(e) => error!("Erreur requête GET /envs: {:?}", e),
                        }
                    });
                }
                || ()
            },
            (*auth_status).clone(),
        );
    }

    // ------------------------------------------------------------------
    // 4) Filtrer les configs par le rôle sélectionné
    // ------------------------------------------------------------------
    let filtered_envs = {
        let sr = *selected_role;
        envs.iter()
            .filter(|policy| {
                if sr != -1 {
                    policy.role_id == sr
                } else {
                    false
                }
            })
            .cloned()
            .collect::<Vec<AppPolicy>>()
    };

    // ------------------------------------------------------------------
    // 5) Chargement des événements quand on sélectionne un env
    // ------------------------------------------------------------------
    {
        let events_state = events.clone();
        use_effect_with_deps(
            {
                let events_state = events.clone();
                move |sel_env_handle: &UseStateHandle<Option<AppPolicy>>| {
                    if let Some(env) = &**sel_env_handle {
                        let program_name = env.app_name.clone();
                        spawn_local(async move {
                            let cookies = get_cookies().unwrap_or_default();
                            let csrf_token = extract_csrf(&cookies);
                            let url = format!("http://127.0.0.1:8081/events/{}", program_name);
                            let resp = Request::get(&url)
                                .credentials(RequestCredentials::Include)
                                .header("X-CSRF-Token", &csrf_token)
                                .send()
                                .await;
                            match resp {
                                Ok(r) if r.status() == 200 => {
                                    if let Ok(evts) = r.json::<Vec<SandboxEvent>>().await {
                                        events_state.set(evts);
                                    }
                                }
                                Ok(r) => error!("Erreur GET events: status {}", r.status()),
                                Err(e) => error!("Erreur requête GET events: {:?}", e),
                            }
                        });
                    } else {
                        events_state.set(Vec::new());
                    }
                }
            },
            selected_env.clone(),
        );
    }

    // ------------------------------------------------------------------
    // 6) Sélectionner une config via son policy_id
    // ------------------------------------------------------------------
    let on_select_env = {
        let selected_env_state = selected_env.clone();
        Callback::from(move |pid: i32| {
            let selected_env_state = selected_env_state.clone();
            spawn_local(async move {
                let cookies = get_cookies().unwrap_or_default();
                let csrf_token = extract_csrf(&cookies);
                let url = format!("http://127.0.0.1:8081/env_id/{}", pid);
                let resp = Request::get(&url)
                    .credentials(RequestCredentials::Include)
                    .header("X-CSRF-Token", &csrf_token)
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status() == 200 => {
                        if let Ok(policy) = r.json::<AppPolicy>().await {
                            selected_env_state.set(Some(policy));
                        }
                    }
                    Ok(r) => error!("Erreur GET /env_id/..: status {}", r.status()),
                    Err(e) => error!("Erreur GET /env_id/..: {:?}", e),
                }
            });
        })
    };

    // ------------------------------------------------------------------
    // 7) Sélection du rôle via menu déroulant
    // ------------------------------------------------------------------
    let on_role_change = {
        let selected_role_state = selected_role.clone();
        Callback::from(move |e: Event| {
            let select: HtmlSelectElement = e.target_unchecked_into();
            let selected_id = select.value().parse().unwrap_or(-1);
            selected_role_state.set(selected_id);
        })
    };

    // ------------------------------------------------------------------
    // 8) Mettre à jour la config sélectionnée
    // ------------------------------------------------------------------
    let on_update_env = {
        let selected_env_state = selected_env.clone();
        let envs_state = envs.clone();
        Callback::from(move |_| {
            if let Some(env_data) = (*selected_env_state).clone() {
                let policy_id_val = env_data.policy_id;
                let cookies = get_cookies().unwrap_or_default();
                let csrf_token = extract_csrf(&cookies);
                let url = format!("http://127.0.0.1:8081/env_id/{}", policy_id_val);
                let body = serde_json::json!({
                    "ll_fs_ro": env_data.default_ro.split(':').collect::<Vec<_>>(),
                    "ll_fs_rw": env_data.default_rw.split(':').collect::<Vec<_>>(),
                    "ll_tcp_bind": env_data.tcp_bind,
                    "ll_tcp_connect": env_data.tcp_connect,
                    "allowed_ips": env_data.allowed_ips,
                    "allowed_domains": env_data.allowed_domains,
                });
                let envs_clone = envs_state.clone();
                spawn_local(async move {
                    let resp = Request::put(&url)
                        .credentials(RequestCredentials::Include)
                        .header("X-CSRF-Token", &csrf_token)
                        .header("Content-Type", "application/json")
                        .body(serde_json::to_string(&body).unwrap())
                        .unwrap()
                        .send()
                        .await;
                    match resp {
                        Ok(r) if r.status() == 200 => {
                            info!("Mise à jour réussie !");
                            let cookies2 = get_cookies().unwrap_or_default();
                            let csrf_token2 = extract_csrf(&cookies2);
                            let resp2 = Request::get("http://127.0.0.1:8081/envs")
                                .credentials(RequestCredentials::Include)
                                .header("X-CSRF-Token", &csrf_token2)
                                .send()
                                .await;
                            if let Ok(r2) = resp2 {
                                if r2.status() == 200 {
                                    if let Ok(list) = r2.json::<Vec<AppPolicy>>().await {
                                        envs_clone.set(list);
                                    }
                                }
                            }
                        }
                        Ok(r) => error!("Erreur update env: status {}", r.status()),
                        Err(e) => error!("Erreur requête update env: {:?}", e),
                    }
                });
            }
        })
    };

    // ------------------------------------------------------------------
    // 9) Supprimer la config sélectionnée avec confirmation
    // ------------------------------------------------------------------
    let on_delete_env = {
        let selected_env_state = selected_env.clone();
        let envs_state = envs.clone();
        Callback::from(move |_| {
            if let Some(env_data) = (*selected_env_state).clone() {
                let pid = env_data.policy_id;
                let cookies = get_cookies().unwrap_or_default();
                let csrf_token = extract_csrf(&cookies);
                let envs_clone = envs_state.clone();
                let selected_env_clone = selected_env_state.clone();
                spawn_local(async move {
                    if web_sys::window()
                        .unwrap()
                        .confirm_with_message("Confirmer la suppression de cette configuration ?")
                        .unwrap_or(false)
                    {
                        let url = format!("http://127.0.0.1:8081/env_id/{}", pid);
                        let resp = Request::delete(&url)
                            .header("X-CSRF-Token", &csrf_token)
                            .credentials(RequestCredentials::Include)
                            .send()
                            .await;
                        match resp {
                            Ok(r) if r.status() == 200 => {
                                info!("Suppression réussie !");
                                let cookies2 = get_cookies().unwrap_or_default();
                                let csrf_token2 = extract_csrf(&cookies2);
                                let resp2 = Request::get("http://127.0.0.1:8081/envs")
                                    .credentials(RequestCredentials::Include)
                                    .header("X-CSRF-Token", &csrf_token2)
                                    .send()
                                    .await;
                                if let Ok(rr) = resp2 {
                                    if rr.status() == 200 {
                                        if let Ok(list) = rr.json::<Vec<AppPolicy>>().await {
                                            envs_clone.set(list);
                                        }
                                    }
                                }
                                selected_env_clone.set(None);
                            }
                            Ok(r) => error!("Erreur suppression: status {}", r.status()),
                            Err(e) => error!("Erreur requête suppression: {:?}", e),
                        }
                    }
                });
            }
        })
    };

    // ------------------------------------------------------------------
    // 10) Créer une nouvelle config (POST /env)
    // ------------------------------------------------------------------
    let on_create_env = {
        let envs_state = envs.clone();
        let sr = selected_role.clone();
        let name_st = new_app_name.clone();
        let ro_st = new_default_ro.clone();
        let rw_st = new_default_rw.clone();
        let bind_st = new_tcp_bind.clone();
        let conn_st = new_tcp_connect.clone();
        let ips_st = new_allowed_ips.clone();
        let dom_st = new_allowed_domains.clone();

        Callback::from(move |_| {
            // Copy the selected role value to avoid moving the state handle.
            let role_value = *sr;
            if role_value != -1 {
                let name_val = (*name_st).clone();
                let ro_val = (*ro_st).clone();
                let rw_val = (*rw_st).clone();
                let bind_val = (*bind_st).clone();
                let conn_val = (*conn_st).clone();
                let ips_val = (*ips_st).clone();
                let dom_val = (*dom_st).clone();
                let envs_clone = envs_state.clone();
                spawn_local(async move {
                    let cookies = get_cookies().unwrap_or_default();
                    let csrf_token = extract_csrf(&cookies);
                    let body = serde_json::json!({
                        "app_name": name_val,
                        "role_id": role_value,
                        "default_ro": ro_val,
                        "default_rw": rw_val,
                        "tcp_bind": bind_val,
                        "tcp_connect": conn_val,
                        "allowed_ips": ips_val,
                        "allowed_domains": dom_val,
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
                            let cookies2 = get_cookies().unwrap_or_default();
                            let csrf_token2 = extract_csrf(&cookies2);
                            let resp2 = Request::get("http://127.0.0.1:8081/envs")
                                .credentials(RequestCredentials::Include)
                                .header("X-CSRF-Token", &csrf_token2)
                                .send()
                                .await;
                            if let Ok(rr) = resp2 {
                                if rr.status() == 200 {
                                    if let Ok(list) = rr.json::<Vec<AppPolicy>>().await {
                                        envs_clone.set(list);
                                    }
                                }
                            }
                        }
                        Ok(r) => error!("Erreur création: status {}", r.status()),
                        Err(e) => error!("Erreur requête création: {:?}", e),
                    }
                });
            } else {
                error!("Veuillez sélectionner un rôle avant de créer une configuration.");
            }
        })
    };

    // ------------------------------------------------------------------
    // 11) Handlers des inputs (creation)
    // ------------------------------------------------------------------
    let on_new_app_name_input = {
        let st = new_app_name.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                st.set(input.value());
            }
        })
    };
    let on_new_default_ro_input = {
        let st = new_default_ro.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                st.set(input.value());
            }
        })
    };
    let on_new_default_rw_input = {
        let st = new_default_rw.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                st.set(input.value());
            }
        })
    };
    let on_new_tcp_bind_input = {
        let st = new_tcp_bind.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                st.set(input.value());
            }
        })
    };
    let on_new_tcp_connect_input = {
        let st = new_tcp_connect.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                st.set(input.value());
            }
        })
    };
    let on_new_allowed_ips_input = {
        let st = new_allowed_ips.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                st.set(input.value());
            }
        })
    };
    let on_new_allowed_domains_input = {
        let st = new_allowed_domains.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                st.set(input.value());
            }
        })
    };

    // ------------------------------------------------------------------
    // 12) Handlers des inputs (mise à jour)
    // ------------------------------------------------------------------
    let on_selected_ro_change = {
        let sel_env = selected_env.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(mut data) = (*sel_env).clone() {
                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                    data.default_ro = input.value();
                    sel_env.set(Some(data));
                }
            }
        })
    };
    let on_selected_rw_change = {
        let sel_env = selected_env.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(mut data) = (*sel_env).clone() {
                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                    data.default_rw = input.value();
                    sel_env.set(Some(data));
                }
            }
        })
    };
    let on_selected_bind_change = {
        let sel_env = selected_env.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(mut data) = (*sel_env).clone() {
                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                    data.tcp_bind = input.value();
                    sel_env.set(Some(data));
                }
            }
        })
    };
    let on_selected_connect_change = {
        let sel_env = selected_env.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(mut data) = (*sel_env).clone() {
                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                    data.tcp_connect = input.value();
                    sel_env.set(Some(data));
                }
            }
        })
    };
    let on_selected_allowed_ips_change = {
        let sel_env = selected_env.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(mut data) = (*sel_env).clone() {
                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                    data.allowed_ips = input.value();
                    sel_env.set(Some(data));
                }
            }
        })
    };
    let on_selected_allowed_domains_change = {
        let sel_env = selected_env.clone();
        Callback::from(move |e: InputEvent| {
            if let Some(mut data) = (*sel_env).clone() {
                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                    data.allowed_domains = input.value();
                    sel_env.set(Some(data));
                }
            }
        })
    };

    // ------------------------------------------------------------------
    // 13) RENDU
    // ------------------------------------------------------------------
    html! {
        <div class="container">
        {
            match *auth_status {
                AuthStatus::Loading => html! { <p>{ "Chargement..." }</p> },
                AuthStatus::Invalid => html! { <p style="font-weight: bold;">{ "403 : Accès refusé" }</p> },
                AuthStatus::Valid => html! {
                    <div class="columns">
                        // Colonne 1: Rôles + liste des configurations filtrées
                        <div class="column" style="border:1px solid #ccc; padding:1rem;">
                            <h3>{ "Configurations existantes" }</h3>
                            <div class="form-group" style="margin-bottom:1rem;">
                                <label><b>{ "Sélection du rôle" }</b></label>
                                <select ref={role_select_ref}
                                        value={selected_role.to_string()}
                                        onchange={on_role_change.clone()}>
                                    <option value="-1" selected={*selected_role == -1}>
                                        { "Choisir un rôle" }
                                    </option>
                                    { for roles.iter().map(|role| html! {
                                        <option value={role.role_id.to_string()}>
                                            { &role.role_name }
                                        </option>
                                    }) }
                                </select>
                            </div>
                            <ul>
                            {
                                for filtered_envs.iter().map(|env_data| {
                                    let pid = env_data.policy_id;
                                    html! {
                                        <li
                                            onclick={Callback::from({
                                                let cb = on_select_env.clone();
                                                move |_| cb.emit(pid)
                                            })}
                                            style="cursor:pointer; margin-bottom:0.3rem;"
                                        >
                                            { env_data.app_name.clone() }
                                        </li>
                                    }
                                })
                            }
                            </ul>
                        </div>
                        // Colonne 2: Détails / Événements / Édition
                        <div class="column" style="border:1px solid #ccc; padding:1rem; margin-left:1rem; position:relative;">
                        {
                            if let Some(env_data) = &*selected_env {
                                html! {
                                    <>
                                        <h3>{ format!("Configuration : {}", env_data.app_name) }</h3>
                                        <p style="font-size:0.9rem; color:#555;">
                                            { format!("Policy ID = {}, Updated at = {}", env_data.policy_id, env_data.updated_at) }
                                        </p>
                                        <button
                                            class="toggle-button"
                                            onclick={Callback::from({
                                                let toggle = is_edit_mode.clone();
                                                move |_| toggle.set(!*toggle)
                                            })}
                                        >
                                            { if *is_edit_mode { "Voir les événements" } else { "Modifier la configuration" } }
                                        </button>
                                        {
                                            if *is_edit_mode {
                                                html! {
                                                    <div style="margin-top: 2rem">
                                                        <div class="form-group">
                                                            <label>{ "LL_FS_RO" }</label>
                                                            <input
                                                                type="text"
                                                                value={env_data.default_ro.clone()}
                                                                oninput={on_selected_ro_change.clone()}
                                                            />
                                                        </div>
                                                        <div class="form-group" style="margin-top:0.5rem;">
                                                            <label>{ "LL_FS_RW" }</label>
                                                            <input
                                                                type="text"
                                                                value={env_data.default_rw.clone()}
                                                                oninput={on_selected_rw_change.clone()}
                                                            />
                                                        </div>
                                                        <div class="form-group" style="margin-top:0.5rem;">
                                                            <label>{ "TCP_BIND" }</label>
                                                            <input
                                                                type="text"
                                                                value={env_data.tcp_bind.clone()}
                                                                oninput={on_selected_bind_change.clone()}
                                                            />
                                                        </div>
                                                        <div class="form-group" style="margin-top:0.5rem;">
                                                            <label>{ "TCP_CONNECT" }</label>
                                                            <input
                                                                type="text"
                                                                value={env_data.tcp_connect.clone()}
                                                                oninput={on_selected_connect_change.clone()}
                                                            />
                                                        </div>
                                                        <div class="form-group" style="margin-top:0.5rem;">
                                                            <label>{ "allowed_ips" }</label>
                                                            <input
                                                                type="text"
                                                                value={env_data.allowed_ips.clone()}
                                                                oninput={on_selected_allowed_ips_change.clone()}
                                                            />
                                                        </div>
                                                        <div class="form-group" style="margin-top:0.5rem;">
                                                            <label>{ "allowed_domains" }</label>
                                                            <input
                                                                type="text"
                                                                value={env_data.allowed_domains.clone()}
                                                                oninput={on_selected_allowed_domains_change.clone()}
                                                            />
                                                        </div>
                                                        <div style="margin-top:1rem;">
                                                            <button onclick={on_update_env.clone()} style="margin-right:0.5rem;">
                                                                { "Enregistrer" }
                                                            </button>
                                                            <button onclick={on_delete_env.clone()} class="btn-danger">
                                                                { "Supprimer" }
                                                            </button>
                                                        </div>
                                                    </div>
                                                }
                                            } else {
                                                html! {
                                                    <div>
                                                        <h4>{ "Événements" }</h4>
                                                        <ul>
                                                        {
                                                            for events.iter().map(|evt| {
                                                                html! {
                                                                    <li>
                                                                        { format!("{} - {} - {}", evt.timestamp, evt.operation, evt.result) }
                                                                    </li>
                                                                }
                                                            })
                                                        }
                                                        </ul>
                                                    </div>
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
                        // Colonne 3: Création d'une nouvelle config
                        <div class="column" style="border:1px solid #ccc; padding:1rem; margin-left:1rem;">
                            <h3>{ "Créer une nouvelle configuration" }</h3>
                            <p style="font-size:0.9rem; color:#555;">
                                { "Note : la configuration sera reliée au rôle sélectionné dans le menu déroulant." }
                            </p>
                            <div style="margin-top:2rem;">
                                <div class="form-group">
                                    <label>{ "Nom du programme" }</label>
                                    <input
                                        type="text"
                                        placeholder="app_name"
                                        value={(*new_app_name).clone()}
                                        oninput={on_new_app_name_input.clone()}
                                    />
                                </div>
                                <div class="form-group" style="margin-top:0.5rem;">
                                    <label>{ "default_ro (séparé par ':')" }</label>
                                    <input
                                        type="text"
                                        placeholder="/var/lib:/usr/bin"
                                        value={(*new_default_ro).clone()}
                                        oninput={on_new_default_ro_input.clone()}
                                    />
                                </div>
                                <div class="form-group" style="margin-top:0.5rem;">
                                    <label>{ "default_rw (séparé par ':')" }</label>
                                    <input
                                        type="text"
                                        placeholder="/var/lib:/usr/bin"
                                        value={(*new_default_rw).clone()}
                                        oninput={on_new_default_rw_input.clone()}
                                    />
                                </div>
                                <div class="form-group" style="margin-top:0.5rem;">
                                    <label>{ "tcp_bind" }</label>
                                    <input
                                        type="text"
                                        placeholder="9418"
                                        value={(*new_tcp_bind).clone()}
                                        oninput={on_new_tcp_bind_input.clone()}
                                    />
                                </div>
                                <div class="form-group" style="margin-top:0.5rem;">
                                    <label>{ "tcp_connect" }</label>
                                    <input
                                        type="text"
                                        placeholder="80:443"
                                        value={(*new_tcp_connect).clone()}
                                        oninput={on_new_tcp_connect_input.clone()}
                                    />
                                </div>
                                <div class="form-group" style="margin-top:0.5rem;">
                                    <label>{ "allowed_ips" }</label>
                                    <input
                                        type="text"
                                        placeholder="192.168.1.1,192.168.1.2"
                                        value={(*new_allowed_ips).clone()}
                                        oninput={on_new_allowed_ips_input.clone()}
                                    />
                                </div>
                                <div class="form-group" style="margin-top:0.5rem;">
                                    <label>{ "allowed_domains" }</label>
                                    <input
                                        type="text"
                                        placeholder="example.com,example.org"
                                        value={(*new_allowed_domains).clone()}
                                        oninput={on_new_allowed_domains_input.clone()}
                                    />
                                </div>
                                <button onclick={on_create_env.clone()} style="margin-top:1rem;">
                                    { "Créer la configuration" }
                                </button>
                            </div>
                        </div>
                    </div>
                }
            }
        }
        </div>
    }
}
