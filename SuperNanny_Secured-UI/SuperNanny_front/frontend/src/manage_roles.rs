use yew::prelude::*;
use gloo_net::http::Request;
use web_sys::RequestCredentials;
use wasm_bindgen_futures::spawn_local;
use log::{error, info};
use crate::utils::get_cookies;
use serde_json::json;

/// Extraction du CSRF depuis les cookies
fn extract_csrf(cookies: &str) -> String {
    cookies
        .split("; ")
        .find(|c| c.starts_with("csrf_token="))
        .map(|c| c.trim_start_matches("csrf_token=").to_string())
        .unwrap_or_default()
}

/// État d'authentification
#[derive(Copy, Clone, PartialEq)]
enum AuthStatus {
    Loading,
    Valid,
    Invalid,
}

/// Représentation d'un rôle
#[derive(Clone, PartialEq, serde::Deserialize, serde::Serialize, Debug)]
pub struct Role {
    pub role_id: i32,
    pub role_name: String,
}

/// Représentation d'une permission
#[derive(Clone, PartialEq, serde::Deserialize, serde::Serialize, Debug)]
pub struct Permission {
    pub permission_id: i32,
    pub permission_name: String,
}

/// Liste fixe d'exemple de permissions
fn all_permissions() -> Vec<Permission> {
    vec![
        Permission { permission_id: 1, permission_name: "manage_policies".into() },
        Permission { permission_id: 2, permission_name: "view_events".into() },
        Permission { permission_id: 3, permission_name: "execute_apps".into() },
        Permission { permission_id: 4, permission_name: "view_policies".into() },
    ]
}

/// Structure pour créer un rôle + default policies (POST /roles_with_default_policies)
#[derive(Clone, PartialEq, Default, serde::Deserialize, serde::Serialize)]
struct CreateRoleWithDP {
    role_name: String,
    default_ro: String,
    default_rw: String,
    tcp_bind: String,
    tcp_connect: String,
    allowed_ips: String,
    allowed_domains: String,
}

/// Structure pour charger/mettre à jour les default policies d'un rôle existant
#[derive(Clone, PartialEq, Default, serde::Deserialize, serde::Serialize)]
struct DefaultPoliciesData {
    default_ro: String,
    default_rw: String,
    tcp_bind: String,
    tcp_connect: String,
    allowed_ips: String,
    allowed_domains: String,
}

#[function_component(ManageRoles)]
pub fn manage_roles() -> Html {
    // 1. État d'authentification
    let auth_status = use_state(|| AuthStatus::Loading);
    {
        let auth_status_handle = auth_status.clone();
        spawn_local(async move {
            let cookies = get_cookies().unwrap_or_default();
            let csrf_token = extract_csrf(&cookies);

            let resp = Request::get("http://127.0.0.1:8081/check_auth")
                .header("X-CSRF-Token", &csrf_token)
                .credentials(RequestCredentials::Include)
                .send()
                .await;

            if let Ok(r) = resp {
                if r.status() == 200 {
                    auth_status_handle.set(AuthStatus::Valid);
                } else {
                    auth_status_handle.set(AuthStatus::Invalid);
                }
            } else {
                auth_status_handle.set(AuthStatus::Invalid);
            }
        });
    }

    // 2. États principaux
    let roles = use_state(|| Vec::<Role>::new());             // liste des rôles
    let selected_role = use_state(|| None as Option<Role>);    // rôle sélectionné
    let permissions = use_state(|| Vec::<Permission>::new()); // permissions du rôle sélectionné

    // 3. État pour la création d'un nouveau rôle + default policies (colonne droite)
    let create_role_with_dp = use_state(|| CreateRoleWithDP::default());

    // 4. État pour stocker/afficher/mettre à jour les default policies du rôle sélectionné
    let dp_data = use_state(|| DefaultPoliciesData::default());

    // 5. Charger la liste des rôles si auth ok
    {
        let roles_state = roles.clone();
        use_effect_with_deps(
            move |auth_status_handle: &UseStateHandle<AuthStatus>| {
                if **auth_status_handle == AuthStatus::Valid {
                    spawn_local(async move {
                        let cookies = get_cookies().unwrap_or_default();
                        let csrf_token = extract_csrf(&cookies);

                        let resp = Request::get("http://127.0.0.1:8081/roles")
                            .header("X-CSRF-Token", &csrf_token)
                            .credentials(RequestCredentials::Include)
                            .send()
                            .await;

                        if let Ok(r) = resp {
                            if r.status() == 200 {
                                if let Ok(role_list) = r.json::<Vec<Role>>().await {
                                    roles_state.set(role_list);
                                }
                            } else {
                                error!("Erreur chargement des rôles: status {}", r.status());
                            }
                        } else {
                            error!("Erreur requête GET /roles");
                        }
                    });
                }
                || ()
            },
            auth_status.clone(),
        );
    }

    // 6. Charger les permissions du rôle sélectionné
    {
        let permissions_state = permissions.clone();
        use_effect_with_deps(
            move |selected_handle: &UseStateHandle<Option<Role>>| {
                if let Some(role) = selected_handle.as_ref() {
                    let role_id = role.role_id;
                    spawn_local(async move {
                        let cookies = get_cookies().unwrap_or_default();
                        let csrf_token = extract_csrf(&cookies);

                        let url = format!("http://127.0.0.1:8081/role_permissions/{}", role_id);
                        let resp = Request::get(&url)
                            .header("X-CSRF-Token", &csrf_token)
                            .credentials(RequestCredentials::Include)
                            .send()
                            .await;

                        if let Ok(r) = resp {
                            if r.status() == 200 {
                                if let Ok(perms) = r.json::<Vec<Permission>>().await {
                                    permissions_state.set(perms);
                                }
                            } else {
                                error!("Erreur chargement des permissions: status {}", r.status());
                            }
                        } else {
                            error!("Erreur requête GET /role_permissions/...");
                        }
                    });
                } else {
                    permissions_state.set(Vec::new());
                }
                || ()
            },
            selected_role.clone(),
        );
    }

    // 7. Charger les default policies du rôle sélectionné (dp_data)
    {
        let dp_data_state = dp_data.clone();
        use_effect_with_deps(
            move |selected_handle: &UseStateHandle<Option<Role>>| {
                if let Some(role) = selected_handle.as_ref() {
                    let role_id = role.role_id;
                    spawn_local(async move {
                        let cookies = get_cookies().unwrap_or_default();
                        let csrf_token = extract_csrf(&cookies);
                        let url = format!("http://127.0.0.1:8081/default_policies/{}", role_id);
                        let resp = Request::get(&url)
                            .header("X-CSRF-Token", &csrf_token)
                            .credentials(RequestCredentials::Include)
                            .send()
                            .await;
                        if let Ok(r) = resp {
                            if r.status() == 200 {
                                match r.json::<DefaultPoliciesData>().await {
                                    Ok(dp) => {
                                        dp_data_state.set(dp);
                                    },
                                    Err(e) => {
                                        error!("Erreur parsing JSON default policies: {:?}", e);
                                        dp_data_state.set(DefaultPoliciesData::default());
                                    }
                                }
                            } else if r.status() == 404 {
                                dp_data_state.set(DefaultPoliciesData::default());
                            } else {
                                error!("Erreur GET default_policies: status {}", r.status());
                                dp_data_state.set(DefaultPoliciesData::default());
                            }
                        } else {
                            error!("Erreur requête GET /default_policies");
                            dp_data_state.set(DefaultPoliciesData::default());
                        }
                    });
                } else {
                    dp_data_state.set(DefaultPoliciesData::default());
                }
                || ()
            },
            selected_role.clone(),
        );
    }

    // 8. Sélection d'un rôle
    let on_select_role = {
        let selected_role_state = selected_role.clone();
        Callback::from(move |role: Role| {
            selected_role_state.set(Some(role));
        })
    };
    let on_select_role_cloned = on_select_role.clone();

    // 9. Supprimer un rôle avec confirmation
    let on_delete_role = {
        let selected_role_state = selected_role.clone();
        let roles_state = roles.clone();
        Callback::from(move |_| {
            if let Some(role) = &*selected_role_state {
                // Confirmation avant suppression
                if let Some(window) = web_sys::window() {
                    if !window.confirm_with_message("Êtes-vous sûr de vouloir supprimer ce rôle ?").unwrap_or(false) {
                        return;
                    }
                }
                let role_id = role.role_id;
                let roles_inner = roles_state.clone();
                let selected_role_inner = selected_role_state.clone();

                spawn_local(async move {
                    let cookies = get_cookies().unwrap_or_default();
                    let csrf_token = extract_csrf(&cookies);
                    let url = format!("http://127.0.0.1:8081/roles/{}", role_id);

                    let resp = Request::delete(&url)
                        .header("X-CSRF-Token", &csrf_token)
                        .credentials(RequestCredentials::Include)
                        .send()
                        .await;

                    if let Ok(r) = resp {
                        if r.status() == 200 {
                            info!("Rôle supprimé");
                            // Recharger la liste des rôles
                            let cookies = get_cookies().unwrap_or_default();
                            let csrf_token = extract_csrf(&cookies);
                            let resp = Request::get("http://127.0.0.1:8081/roles")
                                .header("X-CSRF-Token", &csrf_token)
                                .credentials(RequestCredentials::Include)
                                .send()
                                .await;
                            if let Ok(r2) = resp {
                                if r2.status() == 200 {
                                    if let Ok(role_list) = r2.json::<Vec<Role>>().await {
                                        roles_inner.set(role_list);
                                    }
                                }
                            }
                            // Annuler la sélection
                            selected_role_inner.set(None);
                        } else {
                            error!("Erreur suppression du rôle: status {}", r.status());
                        }
                    } else {
                        error!("Erreur requête DELETE /roles/..");
                    }
                });
            }
        })
    };

    // 10. Toggle permission
    let on_toggle_permission = {
        let selected_role_state = selected_role.clone();
        let permissions_state = permissions.clone();
        Callback::from(move |perm: Permission| {
            if let Some(role) = &*selected_role_state {
                let role_id = role.role_id;
                let permissions_state_clone = permissions_state.clone();
                spawn_local(async move {
                    let cookies = get_cookies().unwrap_or_default();
                    let csrf_token = extract_csrf(&cookies);

                    let current: &Vec<Permission> = permissions_state_clone.as_ref();
                    let is_assigned = current.iter().any(|p| p.permission_id == perm.permission_id);

                    if is_assigned {
                        // Retirer
                        let url = format!("http://127.0.0.1:8081/role_permissions/{}/{}", role_id, perm.permission_id);
                        let resp = Request::delete(&url)
                            .header("X-CSRF-Token", &csrf_token)
                            .credentials(RequestCredentials::Include)
                            .send()
                            .await;
                        if let Ok(r) = resp {
                            if r.status() == 200 {
                                info!("Permission retirée");
                            } else {
                                error!("Erreur retrait permission: {}", r.status());
                            }
                        }
                    } else {
                        // Ajouter
                        let body = json!({
                            "role_id": role_id,
                            "permission_id": perm.permission_id,
                        });
                        let resp = Request::post("http://127.0.0.1:8081/role_permissions")
                            .header("Content-Type", "application/json")
                            .header("X-CSRF-Token", &csrf_token)
                            .credentials(RequestCredentials::Include)
                            .body(serde_json::to_string(&body).unwrap())
                            .expect("Erreur body toggler permission")
                            .send()
                            .await;

                        if let Ok(r) = resp {
                            if r.status() == 200 {
                                info!("Permission ajoutée");
                            } else {
                                error!("Erreur ajout permission: {}", r.status());
                            }
                        }
                    }

                    // Recharger les permissions
                    let cookies2 = get_cookies().unwrap_or_default();
                    let csrf_token2 = extract_csrf(&cookies2);
                    let url2 = format!("http://127.0.0.1:8081/role_permissions/{}", role_id);
                    let resp2 = Request::get(&url2)
                        .header("X-CSRF-Token", &csrf_token2)
                        .credentials(RequestCredentials::Include)
                        .send()
                        .await;
                    if let Ok(r2) = resp2 {
                        if r2.status() == 200 {
                            if let Ok(perms) = r2.json::<Vec<Permission>>().await {
                                permissions_state_clone.set(perms);
                            }
                        }
                    }
                });
            }
        })
    };

    // 11. Mettre à jour les default policies
    let on_update_dp = {
        let selected_role_state = selected_role.clone();
        let dp_data_clone = dp_data.clone();
        Callback::from(move |_| {
            if let Some(role) = &*selected_role_state {
                let role_id = role.role_id;
                let payload = (*dp_data_clone).clone();

                spawn_local(async move {
                    let cookies = get_cookies().unwrap_or_default();
                    let csrf_token = extract_csrf(&cookies);
                    let url = format!("http://127.0.0.1:8081/default_policies/{}", role_id);

                    let resp = Request::put(&url)
                        .header("Content-Type", "application/json")
                        .header("X-CSRF-Token", &csrf_token)
                        .credentials(RequestCredentials::Include)
                        .body(serde_json::to_string(&payload).unwrap())
                        .expect("Erreur de body PUT")
                        .send()
                        .await;

                    if let Ok(r) = resp {
                        if r.status() == 200 {
                            info!("Default policies mises à jour");
                        } else {
                            error!("Erreur mise à jour default_policies: status {}", r.status());
                        }
                    } else {
                        error!("Erreur requête PUT default_policies");
                    }
                });
            }
        })
    };

    // 12. Créer un rôle + default policies
    let on_create_role_with_dp = {
        let create_role_with_dp_clone = create_role_with_dp.clone();
        let roles_state = roles.clone();
        Callback::from(move |_| {
            let payload = (*create_role_with_dp_clone).clone();

            if payload.role_name.trim().is_empty() {
                info!("Nom de rôle vide => on fait rien");
                return;
            }

            let roles_inner = roles_state.clone();
            spawn_local(async move {
                let cookies = get_cookies().unwrap_or_default();
                let csrf_token = extract_csrf(&cookies);

                let resp = Request::post("http://127.0.0.1:8081/roles_with_default_policies")
                    .header("Content-Type", "application/json")
                    .header("X-CSRF-Token", &csrf_token)
                    .credentials(RequestCredentials::Include)
                    .body(serde_json::to_string(&payload).unwrap())
                    .expect("Erreur de body POST role+DP")
                    .send()
                    .await;

                if let Ok(r) = resp {
                    if r.status() == 200 {
                        info!("Rôle + default policies créés");
                        // Recharger la liste des rôles
                        let cookies2 = get_cookies().unwrap_or_default();
                        let csrf_token2 = extract_csrf(&cookies2);
                        let resp2 = Request::get("http://127.0.0.1:8081/roles")
                            .header("X-CSRF-Token", &csrf_token2)
                            .credentials(RequestCredentials::Include)
                            .send()
                            .await;
                        if let Ok(r2) = resp2 {
                            if r2.status() == 200 {
                                if let Ok(role_list) = r2.json::<Vec<Role>>().await {
                                    roles_inner.set(role_list);
                                }
                            }
                        }
                    } else {
                        error!("Erreur creation rôle+DP: status {}", r.status());
                    }
                } else {
                    error!("Erreur requête POST rôle+DP");
                }
            });
        })
    };

    // 13. Rendu
    html! {
        <div class="container">
        {
            match *auth_status {
                AuthStatus::Loading => html! { <p>{ "Chargement..." }</p> },
                AuthStatus::Invalid => html! { <p style="font-weight: bold;">{ "403 : Accès refusé" }</p> },
                AuthStatus::Valid => html! {
                    <div class="columns">
                        // ================= COLONNE 1 : LISTE DES RÔLES =================
                        <div class="column" style="border:1px solid #ccc; padding:1rem;">
                            <h3>{ "Liste des rôles" }</h3>
                            <ul>
                                {
                                    for (*roles).iter().cloned().map(|role| {
                                        let callback = on_select_role_cloned.clone();
                                        let role_clone = role.clone();
                                        html! {
                                            <li
                                                onclick={Callback::from({
                                                    let role_for_emit = role_clone.clone();
                                                    move |_| {
                                                        callback.emit(role_for_emit.clone());
                                                    }
                                                })}
                                                class={if let Some(selected) = &*selected_role {
                                                    if selected.role_id == role_clone.role_id { "selected-role" } else { "" }
                                                } else { "" }}
                                                style="cursor: pointer; margin-bottom:0.3rem;"
                                            >
                                                { role_clone.role_name.clone() }
                                            </li>
                                        }
                                    })
                                }
                            </ul>
                        </div>

                        // ================= COLONNE 2 : DÉTAILS DU RÔLE =================
                        <div class="column" style="border:1px solid #ccc; padding:1rem; margin-left:1rem;">
                            {
                                if let Some(role) = &*selected_role {
                                    html! {
                                        <div>
                                            <h3>{ format!("Détails du rôle : {}", role.role_name) }</h3>
                                            <button onclick={on_delete_role.clone()} class="btn-danger role-delete-btn" style="margin-bottom:1rem;">
                                                { "Supprimer le rôle" }
                                            </button>

                                            <h4>{ "Permissions (cliquez pour ajouter/retirer)" }</h4>
                                            <ul>
                                                { for all_permissions().into_iter().map(|p| {
                                                    let assigned = (*permissions).iter().any(|perm| perm.permission_id == p.permission_id);
                                                    let toggle_cb = on_toggle_permission.clone();
                                                    html! {
                                                        <li
                                                            onclick={Callback::from({
                                                                let p_clone = p.clone();
                                                                move |_| {
                                                                    toggle_cb.emit(p_clone.clone());
                                                                }
                                                            })}
                                                            class={if assigned { "assigned-permission" } else { "unassigned-permission" }}
                                                            style="cursor: pointer; margin-bottom:0.2rem;"
                                                        >
                                                            { p.permission_name.clone() }
                                                        </li>
                                                    }
                                                }) }
                                            </ul>

                                            // Default Policies avec le style des inputs de la colonne de droite
                                            <h4 style="margin-top:1.5rem; font-weight:bold;">{ "Default Policies" }</h4>
                                            <div class="box" style="margin-top:1rem;">
                                                <div class="form-group">
                                                    <label>{ "default_ro" }</label>
                                                    <input
                                                        type="text"
                                                        value={dp_data.default_ro.clone()}
                                                        oninput={Callback::from({
                                                            let dp_state = dp_data.clone();
                                                            move |e: InputEvent| {
                                                                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                                    let mut dp = (*dp_state).clone();
                                                                    dp.default_ro = input.value();
                                                                    dp_state.set(dp);
                                                                }
                                                            }
                                                        })}
                                                    />
                                                </div>
                                                <div class="form-group" style="margin-top:0.5rem;">
                                                    <label>{ "default_rw" }</label>
                                                    <input
                                                        type="text"
                                                        value={dp_data.default_rw.clone()}
                                                        oninput={Callback::from({
                                                            let dp_state = dp_data.clone();
                                                            move |e: InputEvent| {
                                                                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                                    let mut dp = (*dp_state).clone();
                                                                    dp.default_rw = input.value();
                                                                    dp_state.set(dp);
                                                                }
                                                            }
                                                        })}
                                                    />
                                                </div>
                                                <div class="form-group" style="margin-top:0.5rem;">
                                                    <label>{ "tcp_bind" }</label>
                                                    <input
                                                        type="text"
                                                        value={dp_data.tcp_bind.clone()}
                                                        oninput={Callback::from({
                                                            let dp_state = dp_data.clone();
                                                            move |e: InputEvent| {
                                                                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                                    let mut dp = (*dp_state).clone();
                                                                    dp.tcp_bind = input.value();
                                                                    dp_state.set(dp);
                                                                }
                                                            }
                                                        })}
                                                    />
                                                </div>
                                                <div class="form-group" style="margin-top:0.5rem;">
                                                    <label>{ "tcp_connect" }</label>
                                                    <input
                                                        type="text"
                                                        value={dp_data.tcp_connect.clone()}
                                                        oninput={Callback::from({
                                                            let dp_state = dp_data.clone();
                                                            move |e: InputEvent| {
                                                                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                                    let mut dp = (*dp_state).clone();
                                                                    dp.tcp_connect = input.value();
                                                                    dp_state.set(dp);
                                                                }
                                                            }
                                                        })}
                                                    />
                                                </div>
                                                <div class="form-group" style="margin-top:0.5rem;">
                                                    <label>{ "allowed_ips" }</label>
                                                    <input
                                                        type="text"
                                                        value={dp_data.allowed_ips.clone()}
                                                        oninput={Callback::from({
                                                            let dp_state = dp_data.clone();
                                                            move |e: InputEvent| {
                                                                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                                    let mut dp = (*dp_state).clone();
                                                                    dp.allowed_ips = input.value();
                                                                    dp_state.set(dp);
                                                                }
                                                            }
                                                        })}
                                                    />
                                                </div>
                                                <div class="form-group" style="margin-top:0.5rem;">
                                                    <label>{ "allowed_domains" }</label>
                                                    <input
                                                        type="text"
                                                        value={dp_data.allowed_domains.clone()}
                                                        oninput={Callback::from({
                                                            let dp_state = dp_data.clone();
                                                            move |e: InputEvent| {
                                                                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                                    let mut dp = (*dp_state).clone();
                                                                    dp.allowed_domains = input.value();
                                                                    dp_state.set(dp);
                                                                }
                                                            }
                                                        })}
                                                    />
                                                </div>
                                            </div>
                                            <button onclick={on_update_dp} style="margin-top:0.8rem;">
                                                { "Mettre à jour" }
                                            </button>
                                        </div>
                                    }
                                } else {
                                    html! { <p>{ "Sélectionnez un rôle pour voir les détails." }</p> }
                                }
                            }
                        </div>

                        // ================= COLONNE 3 : CRÉER RÔLE + DEFAULT POLICIES =================
                        <div class="column" style="border:1px solid #ccc; padding:1rem; margin-left:1rem;">
                            <h3>{ "Créer un nouveau rôle + default policies" }</h3>
                            <div class="box" style="margin-top:1rem;">
                                <div class="form-group">
                                    <label>{ "Nom du rôle" }</label>
                                    <input
                                        type="text"
                                        placeholder="Nom du rôle"
                                        value={create_role_with_dp.role_name.clone()}
                                        oninput={Callback::from({
                                            let st = create_role_with_dp.clone();
                                            move |e: InputEvent| {
                                                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                    let mut data = (*st).clone();
                                                    data.role_name = input.value();
                                                    st.set(data);
                                                }
                                            }
                                        })}
                                    />
                                </div>
                                <div class="form-group" style="margin-top:0.5rem;">
                                    <label>{ "default_ro" }</label>
                                    <input
                                        type="text"
                                        placeholder="/var/lib:/usr/bin..."
                                        value={create_role_with_dp.default_ro.clone()}
                                        oninput={Callback::from({
                                            let st = create_role_with_dp.clone();
                                            move |e: InputEvent| {
                                                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                    let mut data = (*st).clone();
                                                    data.default_ro = input.value();
                                                    st.set(data);
                                                }
                                            }
                                        })}
                                    />
                                </div>
                                <div class="form-group" style="margin-top:0.5rem;">
                                    <label>{ "default_rw" }</label>
                                    <input
                                        type="text"
                                        placeholder="/var/lib:/usr/bin..."
                                        value={create_role_with_dp.default_rw.clone()}
                                        oninput={Callback::from({
                                            let st = create_role_with_dp.clone();
                                            move |e: InputEvent| {
                                                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                    let mut data = (*st).clone();
                                                    data.default_rw = input.value();
                                                    st.set(data);
                                                }
                                            }
                                        })}
                                    />
                                </div>
                                <div class="form-group" style="margin-top:0.5rem;">
                                    <label>{ "tcp_bind" }</label>
                                    <input
                                        type="text"
                                        placeholder="9418"
                                        value={create_role_with_dp.tcp_bind.clone()}
                                        oninput={Callback::from({
                                            let st = create_role_with_dp.clone();
                                            move |e: InputEvent| {
                                                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                    let mut data = (*st).clone();
                                                    data.tcp_bind = input.value();
                                                    st.set(data);
                                                }
                                            }
                                        })}
                                    />
                                </div>
                                <div class="form-group" style="margin-top:0.5rem;">
                                    <label>{ "tcp_connect" }</label>
                                    <input
                                        type="text"
                                        placeholder="80:443"
                                        value={create_role_with_dp.tcp_connect.clone()}
                                        oninput={Callback::from({
                                            let st = create_role_with_dp.clone();
                                            move |e: InputEvent| {
                                                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                    let mut data = (*st).clone();
                                                    data.tcp_connect = input.value();
                                                    st.set(data);
                                                }
                                            }
                                        })}
                                    />
                                </div>
                                <div class="form-group" style="margin-top:0.5rem;">
                                    <label>{ "allowed_ips" }</label>
                                    <input
                                        type="text"
                                        placeholder="192.168.1.1,192.168.1.2"
                                        value={create_role_with_dp.allowed_ips.clone()}
                                        oninput={Callback::from({
                                            let st = create_role_with_dp.clone();
                                            move |e: InputEvent| {
                                                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                    let mut data = (*st).clone();
                                                    data.allowed_ips = input.value();
                                                    st.set(data);
                                                }
                                            }
                                        })}
                                    />
                                </div>
                                <div class="form-group" style="margin-top:0.5rem;">
                                    <label>{ "allowed_domains" }</label>
                                    <input
                                        type="text"
                                        placeholder="example.com,example.org"
                                        value={create_role_with_dp.allowed_domains.clone()}
                                        oninput={Callback::from({
                                            let st = create_role_with_dp.clone();
                                            move |e: InputEvent| {
                                                if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                                    let mut data = (*st).clone();
                                                    data.allowed_domains = input.value();
                                                    st.set(data);
                                                }
                                            }
                                        })}
                                    />
                                </div>
                                <button onclick={on_create_role_with_dp} style="margin-top:1rem;">
                                    { "Créer Rôle + Default Policies" }
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
