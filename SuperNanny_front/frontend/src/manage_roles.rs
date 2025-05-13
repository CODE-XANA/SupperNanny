use gloo_net::http::Method;
use serde::{Deserialize, Serialize};
use yew::platform::spawn_local;
use yew::prelude::*;
use web_sys::{HtmlInputElement, InputEvent};

use crate::{
    api::{fetch_empty, fetch_json},
    session::use_session,
};

/* -------------------------------------------------------------------------- */
/*                              Structures                                    */
/* -------------------------------------------------------------------------- */

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
struct Role {
    role_id:   i32,
    role_name: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
struct Permission {
    permission_id:   i32,
    permission_name: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Default, Debug)]
struct DefaultPolicyData {
    default_ro:      String,
    default_rw:      String,
    tcp_bind:        String,
    tcp_connect:     String,
    allowed_ips:     String,
    allowed_domains: String,
}

/* -------------------------------------------------------------------------- */
/*                           Composant principal                               */
/* -------------------------------------------------------------------------- */

#[function_component(ManageRoles)]
pub fn manage_roles() -> Html {
    /* -------- session -------- */
    if use_session().is_none() {
        return html!(<p>{ "Chargement…" }</p>);
    }

    /* -------- states globaux -------- */
    let roles          = use_state(Vec::<Role>::new);
    let selected_role  = use_state(|| None::<Role>);
    let permissions    = use_state(Vec::<Permission>::new);
    let dp_state       = use_state(DefaultPolicyData::default);
    let all_perms      = use_state(Vec::<Permission>::new);

    /* -------- states création -------- */
    let new_role_name  = use_state(String::new);
    let new_dp         = use_state(DefaultPolicyData::default);

    /* ------------------------------------------------------------------ */
    /* 1. charge tous les rôles et toutes les permissions au montage      */
    /* ------------------------------------------------------------------ */
    {
        let roles = roles.clone();
        let all_perms = all_perms.clone();
        use_effect_with((), move |_| {
            // Chargement des rôles
            spawn_local(async move {
                if let Ok(list) = fetch_json::<(), Vec<Role>>(Method::GET, "/roles", None::<&()>).await {
                    roles.set(list);
                }
            });
            
            // Chargement de toutes les permissions disponibles
            let all_perms_clone = all_perms.clone();
            spawn_local(async move {
                match fetch_json::<(), Vec<Permission>>(Method::GET, "/roles/permissions", None::<&()>).await {
                    Ok(list) => all_perms_clone.set(list),
                    Err(err) => {
                        web_sys::console::log_1(&format!("Erreur lors du chargement des permissions: {:?}", err).into());
                        
                        all_perms_clone.set(Vec::new());
                    }
                }
            });
            
            || ()
        });
    }

    /* ------------------------------------------------------------------ */
    /* 2. lorsqu'on (dé)sélectionne un rôle -> charge perms & policies      */
    /* ------------------------------------------------------------------ */
    {
        let perms = permissions.clone();
        let dp    = dp_state.clone();
        use_effect_with(selected_role.clone(), move |sel| {
            if let Some(r) = &**sel {
                let rid = r.role_id;

                // permissions du rôle
                let perms_handle = perms.clone();
                spawn_local(async move {
                    let path = format!("/roles/{}/permissions", rid);
                    if let Ok(v) = fetch_json::<(), Vec<Permission>>(Method::GET, &path, None::<&()>).await {
                        perms_handle.set(v);
                    } else {
                        // En cas d'erreur, log pour debug
                        web_sys::console::log_1(&"Error loading permissions".into());
                        // Réinitialiser pour éviter d'afficher des données périmées
                        perms_handle.set(Vec::new());
                    }
                });

                // default policies
                let dp_handle = dp.clone();
                spawn_local(async move {
                    let path = format!("/roles/default_policies/{}", rid);
                    match fetch_json::<(), DefaultPolicyData>(Method::GET, &path, None::<&()>).await {
                        Ok(d)  => dp_handle.set(d),
                        Err(_) => dp_handle.set(DefaultPolicyData::default()),
                    }
                });
            } else {
                perms.set(Vec::new());
                dp.set(DefaultPolicyData::default());
            }
            || ()
        });
    }

    /* ------------------------------------------------------------------ */
    /* 3. callbacks helpers                                               */
    /* ------------------------------------------------------------------ */

    /* Sélection / désélection */
    let on_select_role = {
        let sel = selected_role.clone();
        Callback::from(move |role: Role| sel.set(Some(role)))
    };

    /* --- suppression rôle ------------------------------------------- */
    let on_delete_role = {
        let roles = roles.clone();
        let sel   = selected_role.clone();

        Callback::from(move |_| {
            if let Some(r) = &*sel {
                if !web_sys::window().unwrap()
                        .confirm_with_message("Supprimer ce rôle ?").unwrap_or(false) {
                    return;
                }

                let rid   = r.role_id;
                let roles2= roles.clone();
                let sel2  = sel.clone();

                spawn_local(async move {
                    if fetch_empty(Method::DELETE, &format!("/roles/{}", rid), None::<&()>).await.is_ok() {
                        // recharge liste + désélection
                        if let Ok(v) = fetch_json::<(), Vec<Role>>(Method::GET, "/roles", None::<&()>).await {
                            roles2.set(v);
                            sel2.set(None);
                        }
                    }
                });
            }
        })
    };

    /* --- toggle permission ------------------------------------------ */
    let on_toggle_perm = {
        let sel   = selected_role.clone();
        let perms = permissions.clone();

        Callback::from(move |perm: Permission| {
            if let Some(r) = &*sel {
                let rid    = r.role_id;
                let pid    = perm.permission_id;
                let perms2 = perms.clone();
                
                // Check if we're adding or removing
                let is_removing = perms2.iter().any(|p| p.permission_id == pid);
                
                // IMPORTANT: Do immediate UI update before API call
                if !is_removing {
                    let mut updated_perms = (*perms2).clone();
                    updated_perms.push(Permission {
                        permission_id: pid,
                        permission_name: perm.permission_name.clone(),
                    });
                    perms2.set(updated_perms);
                } else {
                    let updated_perms = perms2.iter()
                        .filter(|p| p.permission_id != pid)
                        .cloned()
                        .collect::<Vec<Permission>>();
                    perms2.set(updated_perms);
                }

                // Now do the API call in the background
                spawn_local(async move {
                    let res = if is_removing {
                        // DELETE permission
                        fetch_empty(
                            Method::DELETE,
                            &format!("/roles/{}/permissions/{}", rid, pid),
                            None::<&()>
                        )
                        .await
                    } else {
                        // POST to add permission
                        let body = serde_json::json!({
                            "permission_id": pid,
                        });
                        fetch_empty(
                            Method::POST,
                            &format!("/roles/{}/permissions", rid),
                            Some(&body),
                        )
                        .await
                    };
                    
                    // If API call failed, refresh from server to sync
                    if res.is_err() {
                        if let Ok(new_list) = fetch_json::<(), Vec<Permission>>(
                            Method::GET,
                            &format!("/roles/{}/permissions", rid),
                            None::<&()>, 
                        )
                        .await
                        {
                            perms2.set(new_list);
                        }
                    }
                });
            }
        })
    };

    /* --- update des default policies --------------------------------- */
    let on_update_dp = {
        let sel = selected_role.clone();
        let dp  = dp_state.clone();

        Callback::from(move |_| {
            if let Some(r) = &*sel {
                let rid  = r.role_id;
                let body = (*dp).clone();
                spawn_local(async move {
                    let _ = fetch_empty(Method::PUT, &format!("/roles/default_policies/{}", rid), Some(&body)).await;
                });
            }
        })
    };

    /* --- création rôle + policies ----------------------------------- */
    let on_create_role = {
        let roles = roles.clone();
        let n     = new_role_name.clone();
        let ndp   = new_dp.clone();

        Callback::from(move |_| {
            let name = n.trim();
            if name.is_empty() { return; }

            let body = serde_json::json!({
                "role_name":       name,
                "default_ro":      ndp.default_ro,
                "default_rw":      ndp.default_rw,
                "tcp_bind":        ndp.tcp_bind,
                "tcp_connect":     ndp.tcp_connect,
                "allowed_ips":     ndp.allowed_ips,
                "allowed_domains": ndp.allowed_domains,
            });

            let roles2 = roles.clone();
            let n2     = n.clone();

            spawn_local(async move {
                if fetch_empty(Method::POST, "/roles/create_with_default", Some(&body)).await.is_ok() {
                    if let Ok(v) = fetch_json::<(), Vec<Role>>(Method::GET, "/roles", None::<&()>).await {
                        roles2.set(v);
                        n2.set(String::new());
                    }
                }
            });
        })
    };

    /* ------------------------------------------------------------------ */
    /* helpers binding simplifiés                                         */
    /* ------------------------------------------------------------------ */

    let bind_string = |state: UseStateHandle<String>| {
        Callback::from(move |e: InputEvent| {
            state.set(e.target_unchecked_into::<HtmlInputElement>().value());
        })
    };

    let bind_dp_field = |field: &'static str, handle: UseStateHandle<DefaultPolicyData>| {
        Callback::from(move |e: InputEvent| {
            let mut d = (*handle).clone();
            let v = e.target_unchecked_into::<HtmlInputElement>().value();
            match field {
                "ro"  => d.default_ro       = v,
                "rw"  => d.default_rw       = v,
                "bind"=> d.tcp_bind         = v,
                "conn"=> d.tcp_connect      = v,
                "ips" => d.allowed_ips      = v,
                "dom" => d.allowed_domains  = v,
                _ => {}
            }
            handle.set(d);
        })
    };

    /* ------------------------------------------------------------------ */
    /*                               UI                                   */
    /* ------------------------------------------------------------------ */
    
    html! {
    <div class="container">
        <div class="columns">
            /* ----------------- COLONNE RÔLES ---------------- */
            <div class="column">
                <h3 style="border-bottom: 1px solid #ddd; padding-bottom: 0.5rem; margin-bottom: 1rem; font-weight: 500; color: #333;">{ "Rôles" }</h3>
                <ul style="list-style: none; padding: 0; margin: 0;">
                    { for roles.iter().map(|r|{
                        let cb   = on_select_role.clone();
                        let role = r.clone();
                        let active = selected_role.as_ref().map(|x| x.role_id) == Some(r.role_id);
                        html!{
                            <li
                                style={format!(
                                    "padding: 0.75rem; border-bottom: 1px solid #ddd; cursor: pointer; transition: background-color 0.3s, padding-left 0.3s; {}",
                                    if active { "background-color: #f0f4ff; padding-left: 1rem;" } else { "" }
                                )}
                                onclick={Callback::from(move |_| cb.emit(role.clone()))}
                            >
                                { &r.role_name }
                            </li>
                        }
                    })}
                </ul>
            </div>

            /* ----------------- COLONNE DÉTAILS --------------- */
            <div class="column" style="position: relative;">
                {
                    if let Some(r) = &*selected_role {
                        html!{
                            <div class="role-details-container">
                                <div class="role-details-header" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                                    <h3 style="margin: 0; padding: 0; border: none;">{ format!("Rôle : {}", r.role_name) }</h3>
                                    <button 
                                        onclick={on_delete_role.clone()}
                                        style="
                                            border: 1px solid #e74c3c;
                                            background: transparent;
                                            color: #e74c3c;
                                            padding: 0.25rem 0.5rem;
                                            font-size: 0.875rem;
                                            border-radius: 4px;
                                            cursor: pointer;
                                            position: absolute;
                                            top: 1rem;
                                            right: 1rem;
                                        "
                                    >
                                        { "Supprimer" }
                                    </button>
                                </div>

                                /* ---- Permissions ---- */
                                <h4 style="font-weight: 500; margin-top: 2rem; margin-bottom: 0.75rem; border-bottom: 1px solid #eee; padding-bottom: 0.5rem;">{ "Permissions" }</h4>
                                <ul style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.5rem; padding: 0; list-style: none;">
                                    { for all_perms.iter().map(|perm| {
                                        let toggle = on_toggle_perm.clone();
                                        let assigned = permissions.iter().any(|p| p.permission_id == perm.permission_id);

                                        let view_label = perm.permission_name.clone();
                                        let cb_perm = perm.clone();

                                        html!{
                                            <li
                                                style={format!(
                                                    "padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; transition: all 0.2s ease; {}",
                                                    if assigned {
                                                        "background-color: #4caf50; color: white; font-weight: 500;"
                                                    } else {
                                                        "background-color: #f5f5f5; color: #555; border: 1px solid #ddd;"
                                                    }
                                                )}
                                                onclick={Callback::from(move |_| toggle.emit(cb_perm.clone()))}
                                            >
                                                { view_label }
                                            </li>
                                        }
                                    })}
                                </ul>

                                /* ---- Default policies ---- */
                                <h4 style="font-weight: 500; margin-top: 2rem; margin-bottom: 0.75rem; border-bottom: 1px solid #eee; padding-bottom: 0.5rem;">{ "Default policies" }</h4>
                                <div style="padding: .5rem;">
                                    <div class="form-group">
                                        <label>{"default_ro"}</label>
                                        <input 
                                            type="text"
                                            value={dp_state.default_ro.clone()}
                                            oninput={bind_dp_field("ro", dp_state.clone())}
                                            style="
                                                width: 100%;
                                                padding: 0.75rem;
                                                background-color: #fff;
                                                border: 1px solid #ccc;
                                                border-radius: 4px;
                                                color: #333;
                                                box-sizing: border-box;
                                                transition: border-color 0.3s, box-shadow 0.3s;
                                            "
                                        />
                                    </div>
                                    <div class="form-group">
                                        <label>{"default_rw"}</label>
                                        <input 
                                            type="text"
                                            value={dp_state.default_rw.clone()}
                                            oninput={bind_dp_field("rw", dp_state.clone())}
                                            style="
                                                width: 100%;
                                                padding: 0.75rem;
                                                background-color: #fff;
                                                border: 1px solid #ccc;
                                                border-radius: 4px;
                                                color: #333;
                                                box-sizing: border-box;
                                                transition: border-color 0.3s, box-shadow 0.3s;
                                            "
                                        />
                                    </div>
                                    <div class="form-group">
                                        <label>{"tcp_bind"}</label>
                                        <input 
                                            type="text"
                                            value={dp_state.tcp_bind.clone()}
                                            oninput={bind_dp_field("bind", dp_state.clone())}
                                            style="
                                                width: 100%;
                                                padding: 0.75rem;
                                                background-color: #fff;
                                                border: 1px solid #ccc;
                                                border-radius: 4px;
                                                color: #333;
                                                box-sizing: border-box;
                                                transition: border-color 0.3s, box-shadow 0.3s;
                                            "
                                        />
                                    </div>
                                    <div class="form-group">
                                        <label>{"tcp_connect"}</label>
                                        <input 
                                            type="text"
                                            value={dp_state.tcp_connect.clone()}
                                            oninput={bind_dp_field("conn", dp_state.clone())}
                                            style="
                                                width: 100%;
                                                padding: 0.75rem;
                                                background-color: #fff;
                                                border: 1px solid #ccc;
                                                border-radius: 4px;
                                                color: #333;
                                                box-sizing: border-box;
                                                transition: border-color 0.3s, box-shadow 0.3s;
                                            "
                                        />
                                    </div>
                                    <div class="form-group">
                                        <label>{"allowed_ips"}</label>
                                        <input 
                                            type="text"
                                            value={dp_state.allowed_ips.clone()}
                                            oninput={bind_dp_field("ips", dp_state.clone())}
                                            style="
                                                width: 100%;
                                                padding: 0.75rem;
                                                background-color: #fff;
                                                border: 1px solid #ccc;
                                                border-radius: 4px;
                                                color: #333;
                                                box-sizing: border-box;
                                                transition: border-color 0.3s, box-shadow 0.3s;
                                            "
                                        />
                                    </div>
                                    <div class="form-group" style="margin-bottom: 0;">
                                        <label>{"allowed_domains"}</label>
                                        <input 
                                            type="text"
                                            value={dp_state.allowed_domains.clone()}
                                            oninput={bind_dp_field("dom", dp_state.clone())}
                                            style="
                                                width: 100%;
                                                padding: 0.75rem;
                                                background-color: #fff;
                                                border: 1px solid #ccc;
                                                border-radius: 4px;
                                                color: #333;
                                                box-sizing: border-box;
                                                transition: border-color 0.3s, box-shadow 0.3s;
                                            "
                                        />
                                    </div>

                                    <button 
                                        onclick={on_update_dp}
                                        style="
                                            background-color: #3f51b5;
                                            color: #fff;
                                            border: none;
                                            border-radius: 4px;
                                            padding: 0.75rem 1.25rem;
                                            font-size: 1rem;
                                            margin-top: 1.5rem;
                                            cursor: pointer;
                                            transition: background-color 0.3s, transform 0.2s;
                                            width: 100%;
                                        "
                                    >
                                        { "Enregistrer" }
                                    </button>
                                </div>
                            </div>
                        }
                    } else {
                        html!(
                            <div style="display: flex; justify-content: center; align-items: center; height: 100%; color: #888;">
                                <p>{ "Sélectionnez un rôle pour voir les détails." }</p>
                            </div>
                        )
                    }
                }
            </div>

            /* ----------------- COLONNE CRÉATION -------------- */
            <div class="column">
                <h3 style="border-bottom: 1px solid #ddd; padding-bottom: 0.5rem; margin-bottom: 1rem; font-weight: 500; color: #333;">{ "Créer un nouveau rôle" }</h3>
                
                <div style="padding: .5rem;">
                    <div class="form-group">
                        <label style="display: block; margin-bottom: 0.5rem; font-weight: 500; color: #333;">{"Nom du rôle"}</label>
                        <input 
                            type="text"
                            value={(*new_role_name).clone()}
                            oninput={bind_string(new_role_name.clone())}
                            style="
                                width: 100%;
                                padding: 0.75rem;
                                background-color: #fff;
                                border: 1px solid #ccc;
                                border-radius: 4px;
                                color: #333;
                                box-sizing: border-box;
                                transition: border-color 0.3s, box-shadow 0.3s;
                            "
                            placeholder="Nom du nouveau rôle"
                        />
                    </div>

                    <h4 style="font-weight: 500; margin-top: 1.5rem; margin-bottom: 1rem; border-bottom: 1px solid #eee; padding-bottom: 0.5rem;">{ "Default policies" }</h4>
                    
                    <div class="form-group">
                        <label>{"default_ro"}</label>
                        <input 
                            type="text"
                            value={new_dp.default_ro.clone()}
                            oninput={bind_dp_field("ro", new_dp.clone())}
                            style="
                                width: 100%;
                                padding: 0.75rem;
                                background-color: #fff;
                                border: 1px solid #ccc;
                                border-radius: 4px;
                                color: #333;
                                box-sizing: border-box;
                                transition: border-color 0.3s, box-shadow 0.3s;
                            "
                        />
                    </div>
                    <div class="form-group">
                        <label>{"default_rw"}</label>
                        <input 
                            type="text"
                            value={new_dp.default_rw.clone()}
                            oninput={bind_dp_field("rw", new_dp.clone())}
                            style="
                                width: 100%;
                                padding: 0.75rem;
                                background-color: #fff;
                                border: 1px solid #ccc;
                                border-radius: 4px;
                                color: #333;
                                box-sizing: border-box;
                                transition: border-color 0.3s, box-shadow 0.3s;
                            "
                        />
                    </div>
                    <div class="form-group">
                        <label>{"tcp_bind"}</label>
                        <input 
                            type="text"
                            value={new_dp.tcp_bind.clone()}
                            oninput={bind_dp_field("bind", new_dp.clone())}
                            style="
                                width: 100%;
                                padding: 0.75rem;
                                background-color: #fff;
                                border: 1px solid #ccc;
                                border-radius: 4px;
                                color: #333;
                                box-sizing: border-box;
                                transition: border-color 0.3s, box-shadow 0.3s;
                            "
                        />
                    </div>
                    <div class="form-group">
                        <label>{"tcp_connect"}</label>
                        <input 
                            type="text"
                            value={new_dp.tcp_connect.clone()}
                            oninput={bind_dp_field("conn", new_dp.clone())}
                            style="
                                width: 100%;
                                padding: 0.75rem;
                                background-color: #fff;
                                border: 1px solid #ccc;
                                border-radius: 4px;
                                color: #333;
                                box-sizing: border-box;
                                transition: border-color 0.3s, box-shadow 0.3s;
                            "
                        />
                    </div>
                    <div class="form-group">
                        <label>{"allowed_ips"}</label>
                        <input 
                            type="text"
                            value={new_dp.allowed_ips.clone()}
                            oninput={bind_dp_field("ips", new_dp.clone())}
                            style="
                                width: 100%;
                                padding: 0.75rem;
                                background-color: #fff;
                                border: 1px solid #ccc;
                                border-radius: 4px;
                                color: #333;
                                box-sizing: border-box;
                                transition: border-color 0.3s, box-shadow 0.3s;
                            "
                        />
                    </div>
                    <div class="form-group" style="margin-bottom: 0;">
                        <label>{"allowed_domains"}</label>
                        <input 
                            type="text"
                            value={new_dp.allowed_domains.clone()}
                            oninput={bind_dp_field("dom", new_dp.clone())}
                            style="
                                width: 100%;
                                padding: 0.75rem;
                                background-color: #fff;
                                border: 1px solid #ccc;
                                border-radius: 4px;
                                color: #333;
                                box-sizing: border-box;
                                transition: border-color 0.3s, box-shadow 0.3s;
                            "
                        />
                    </div>

                    <button 
                        onclick={on_create_role}
                        style="
                            background-color: #3f51b5;
                            color: #fff;
                            border: none;
                            border-radius: 4px;
                            padding: 0.75rem 1.25rem;
                            font-size: 1rem;
                            margin-top: 1.5rem;
                            cursor: pointer;
                            transition: background-color 0.3s, transform 0.2s;
                            width: 100%;
                        "
                    >
                        { "Créer le rôle + policies" }
                    </button>
                </div>
            </div>
        </div>
        
        <style>
            {r#"
            .form-group {
                margin-bottom: 1rem;
            }
            .form-group label {
                display: block;
                margin-bottom: 0.5rem;
                font-weight: 500;
                color: #333;
            }
            .columns {
                display: grid;
                grid-template-columns: 1fr 2fr 1fr;
                gap: 1.5rem;
            }
            .column {
                background-color: #fff;
                border-radius: 4px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                padding: 1.5rem;
                height: fit-content;
            }
            "#}
        </style>
    </div>
}
}