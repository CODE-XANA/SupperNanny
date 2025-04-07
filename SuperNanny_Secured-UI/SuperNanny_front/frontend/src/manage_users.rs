use yew::prelude::*;
use wasm_bindgen_futures::spawn_local;
use gloo_net::http::Request;
use web_sys::{RequestCredentials, HtmlSelectElement};
use serde_json::json;
use log::{error, info};
use std::collections::HashMap;
use futures::future::join_all;
use gloo_timers::callback::Interval;

use crate::utils::get_cookies;

#[derive(Copy, Clone, PartialEq)]
enum AuthStatus {
    Loading,
    Valid,
    Invalid,
}

#[derive(Clone, PartialEq, serde::Deserialize, serde::Serialize, Debug)]
pub struct User {
    pub user_id: i32,
    pub username: String,
    pub password_hash: String,
}

#[derive(Clone, PartialEq, serde::Deserialize, serde::Serialize, Debug)]
pub struct Role {
    pub role_id: i32,
    pub role_name: String,
}

fn extract_csrf(cookies: &str) -> String {
    cookies
        .split("; ")
        .find(|c| c.starts_with("csrf_token="))
        .map(|c| c.trim_start_matches("csrf_token=").to_string())
        .unwrap_or_default()
}

async fn reload_all_data(
    roles_state: UseStateHandle<Vec<Role>>,
    users_state: UseStateHandle<Vec<User>>,
    user_roles_state: UseStateHandle<HashMap<i32, i32>>,
) {
    let cookies = get_cookies().unwrap_or_default();
    let csrf_token = extract_csrf(&cookies);

    // 1) Rôles
    if let Ok(resp) = Request::get("http://127.0.0.1:8081/roles")
        .header("X-CSRF-Token", &csrf_token)
        .credentials(RequestCredentials::Include)
        .send()
        .await
    {
        if resp.status() == 200 {
            if let Ok(roles_list) = resp.json::<Vec<Role>>().await {
                info!("Fetched roles: {:?}", roles_list);
                roles_state.set(roles_list);
            }
        } else {
            error!("Erreur (roles): status {}", resp.status());
        }
    }

    // 2) Utilisateurs
    if let Ok(resp) = Request::get("http://127.0.0.1:8081/users")
        .header("X-CSRF-Token", &csrf_token)
        .credentials(RequestCredentials::Include)
        .send()
        .await
    {
        if resp.status() == 200 {
            if let Ok(users_list) = resp.json::<Vec<User>>().await {
                info!("Fetched users: {:?}", users_list);
                users_state.set(users_list.clone());

                // 3) Pour chaque user, récupérer le role_id
                let futures = users_list.iter().map(|u| {
                    let uid = u.user_id;
                    let csrf2 = csrf_token.clone();
                    async move {
                        let url = format!("http://127.0.0.1:8081/user_roles/{}", uid);
                        match Request::get(&url)
                            .header("X-CSRF-Token", &csrf2)
                            .credentials(RequestCredentials::Include)
                            .send()
                            .await
                        {
                            Ok(r) if r.status() == 200 => {
                                match r.json::<Vec<Role>>().await {
                                    Ok(rlist) if !rlist.is_empty() => (uid, rlist[0].role_id),
                                    _ => (uid, 0),
                                }
                            }
                            _ => (uid, 0),
                        }
                    }
                });
                let results = join_all(futures).await;
                let mut map = HashMap::new();
                for (uid, rid) in results {
                    map.insert(uid, rid);
                }
                user_roles_state.set(map);
            }
        } else {
            error!("Erreur (users): status {}", resp.status());
        }
    }
}

fn get_user_role_name(user_id: i32, user_roles: &HashMap<i32, i32>, roles: &[Role]) -> String {
    let role_id = user_roles.get(&user_id).copied().unwrap_or(0);
    if role_id == 0 {
        "No role".to_string()
    } else {
        match roles.iter().find(|r| r.role_id == role_id) {
            Some(rdef) => rdef.role_name.clone(),
            None => format!("Unknown role (ID: {})", role_id),
        }
    }
}

#[function_component(ManageUsers)]
pub fn manage_users() -> Html {
    // Commence en Loading
    let auth_status = use_state(|| AuthStatus::Loading);

    let roles = use_state(|| Vec::<Role>::new());
    let users = use_state(|| Vec::<User>::new());
    let user_roles = use_state(|| HashMap::<i32, i32>::new());

    // States pour le formulaire
    let new_username = use_state(|| "".to_string());
    let new_password = use_state(|| "".to_string());
    let new_role = use_state(|| -1);
    let select_ref = use_node_ref();

    // --- Vérification initiale de l'authentification ---
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
    // --- Vérification périodique toutes les 10 secondes ---
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

    // Recharge les données si l'authentification est validée
    {
        let roles_clone = roles.clone();
        let users_clone = users.clone();
        let user_roles_clone = user_roles.clone();
        use_effect_with_deps(
            move |_| {
                spawn_local(async move {
                    reload_all_data(roles_clone, users_clone, user_roles_clone).await;
                });
                || ()
            },
            *auth_status,
        );
    }

    // Effet pour forcer la valeur du <select> égale à new_role
    {
        let select_ref = select_ref.clone();
        let current_val = (*new_role).to_string();
        let dep = (current_val.clone(),);
        use_effect_with_deps(
            move |(cv,): &(String,)| {
                if let Some(sel) = select_ref.cast::<HtmlSelectElement>() {
                    sel.set_value(cv);
                    info!("Re-applied <select> value: {}", cv);
                }
                || ()
            },
            dep,
        );
    }

    // Handler pour changer le rôle dans le select
    let on_change_role = {
        let new_role = new_role.clone();
        Callback::from(move |e: Event| {
            let select: HtmlSelectElement = e.target_unchecked_into();
            let selected_id = select.value().parse().unwrap_or(-1);
            new_role.set(selected_id);
        })
    };

    // Création d'un utilisateur
    let on_create_user = {
        let roles_clone = roles.clone();
        let users_clone = users.clone();
        let user_roles_clone = user_roles.clone();
        let new_username_clone = new_username.clone();
        let new_password_clone = new_password.clone();
        let new_role_clone = new_role.clone();

        Callback::from(move |_| {
            let username_handle = new_username_clone.clone();
            let password_handle = new_password_clone.clone();
            let role_handle = new_role_clone.clone();

            let username_val = (*username_handle).clone();
            let password_val = (*password_handle).clone();
            let role_val = *role_handle;

            if username_val.is_empty() || password_val.is_empty() || role_val == -1 {
                error!("Veuillez renseigner le nom d'utilisateur, le mot de passe et sélectionner un rôle.");
                return;
            }

            let roles2 = roles_clone.clone();
            let users2 = users_clone.clone();
            let user_roles2 = user_roles_clone.clone();

            spawn_local(async move {
                let cookies = get_cookies().unwrap_or_default();
                let csrf_token = extract_csrf(&cookies);
                let body = json!({
                    "username": username_val,
                    "password": password_val,
                    "role_id": role_val
                });
                if let Ok(req) = Request::post("http://127.0.0.1:8081/create_user_with_role")
                    .header("Content-Type", "application/json")
                    .header("X-CSRF-Token", &csrf_token)
                    .credentials(RequestCredentials::Include)
                    .body(serde_json::to_string(&body).unwrap())
                {
                    if let Ok(resp) = req.send().await {
                        if resp.status() == 200 {
                            info!("Utilisateur créé avec succès (avec rôle)");
                            reload_all_data(roles2.clone(), users2.clone(), user_roles2.clone()).await;
                            // Reset des champs
                            username_handle.set("".to_string());
                            password_handle.set("".to_string());
                            role_handle.set(-1);
                        } else {
                            error!("Erreur de création : status {}", resp.status());
                        }
                    }
                }
            });
        })
    };

    // Suppression d'un utilisateur
    let on_delete_user = {
        let roles_clone = roles.clone();
        let users_clone = users.clone();
        let user_roles_clone = user_roles.clone();
        Callback::from(move |user_id: i32| {
            let roles2 = roles_clone.clone();
            let users2 = users_clone.clone();
            let user_roles2 = user_roles_clone.clone();
            spawn_local(async move {
                if web_sys::window()
                    .unwrap()
                    .confirm_with_message("Confirmer la suppression de cet utilisateur ?")
                    .unwrap_or(false)
                {
                    let cookies = get_cookies().unwrap_or_default();
                    let csrf_token = extract_csrf(&cookies);
                    let url = format!("http://127.0.0.1:8081/users/{}", user_id);
                    if let Ok(resp) = Request::delete(&url)
                        .header("X-CSRF-Token", &csrf_token)
                        .credentials(RequestCredentials::Include)
                        .send()
                        .await
                    {
                        if resp.status() == 200 {
                            info!("Utilisateur supprimé avec succès");
                            reload_all_data(roles2, users2, user_roles2).await;
                        } else {
                            error!("Erreur lors de la suppression : status {}", resp.status());
                        }
                    }
                }
            });
        })
    };

    html! {
        <>
            {
                match *auth_status {
                    AuthStatus::Loading => html! { <p>{ "Chargement..." }</p> },
                    AuthStatus::Invalid => html! { <p style="font-weight:bold;">{ "403 : Accès refusé" }</p> },
                    AuthStatus::Valid => html! {
                        <div class="container" style="margin-top:2rem;">
                            <div class="columns" style="gap: 2rem;">
                                // Colonne gauche : liste des utilisateurs
                                <div class="column" id="user-list">
                                    <h2 class="title is-4 has-text-centered">{ "Liste des utilisateurs" }</h2>
                                    <ul>
                                        { for (*users).iter().cloned().map(|u| {
                                            let role_name = get_user_role_name(u.user_id, &user_roles, &roles);
                                            html! {
                                                <li class="box" style="margin-bottom:0.5rem;">
                                                    <b>{ &u.username }</b>
                                                    { " → " }
                                                    <i>{ role_name }</i>
                                                    <button
                                                        class="button is-danger is-small"
                                                        style="margin-left: 1rem;"
                                                        onclick={Callback::from({
                                                            let on_delete_user = on_delete_user.clone();
                                                            move |_| { on_delete_user.emit(u.user_id); }
                                                        })}
                                                    >
                                                        { "Supprimer" }
                                                    </button>
                                                </li>
                                            }
                                        }) }
                                    </ul>
                                </div>

                                // Colonne droite : Formulaire de création
                                <div class="column" id="user-create" style="max-width: 450px; margin: 0 auto;">
                                    <h2 class="title is-4 has-text-centered">{ "Créer un utilisateur" }</h2>
                                    <div class="box" style="margin-top:1rem;">
                                        <div class="form-group">
                                            <label>{ "Nom d'utilisateur" }</label>
                                            <input
                                                type="text"
                                                placeholder="Entrez le nom d'utilisateur"
                                                value={(*new_username).clone()}
                                                oninput={Callback::from({
                                                    let new_username = new_username.clone();
                                                    move |e: InputEvent| {
                                                        if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                            new_username.set(input.value());
                                                        }
                                                    }
                                                })}
                                            />
                                        </div>
                                        <div class="form-group">
                                            <label>{ "Mot de passe" }</label>
                                            <input
                                                type="password"
                                                placeholder="Entrez le mot de passe"
                                                value={(*new_password).clone()}
                                                oninput={Callback::from({
                                                    let new_password = new_password.clone();
                                                    move |e: InputEvent| {
                                                        if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                            new_password.set(input.value());
                                                        }
                                                    }
                                                })}
                                            />
                                        </div>
                                        <div class="form-group">
                                            <label>{ "Rôle" }</label>
                                            <select
                                                ref={select_ref}
                                                onchange={on_change_role}
                                            >
                                                <option key="placeholder" value="-1">{ "Sélectionner le rôle" }</option>
                                                { for (*roles).iter().map(|r| html! {
                                                    <option key={r.role_id} value={r.role_id.to_string()}>
                                                        { &r.role_name }
                                                    </option>
                                                }) }
                                            </select>
                                        </div>
                                        <button class="btn-create" onclick={on_create_user}>
                                            { "Créer l'utilisateur avec un rôle" }
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    }
                }
            }
        </>
    }
}
