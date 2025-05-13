use gloo_dialogs::confirm;
use gloo_net::http::Method;
use log::{error, info};
use serde::{Deserialize, Serialize};
use web_sys::{HtmlInputElement, HtmlSelectElement, InputEvent};
use yew::platform::spawn_local;
use yew::prelude::*;

use crate::api::{fetch_json, fetch_empty};


/* -------------------------------------------------------------------------- */
/*                                structures                                  */
/* -------------------------------------------------------------------------- */

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
struct Role {
    role_id: i32,
    role_name: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct AppPolicy {
    policy_id: i32,
    app_name: String,
    role_id: i32,
    default_ro: String,
    default_rw: String,
    tcp_bind: String,
    tcp_connect: String,
    allowed_ips: String,
    allowed_domains: String,
    updated_at: String, // NaiveDateTime → string côté back
}

/* -------------------------------------------------------------------------- */
/*                          helpers front / UI                                */
/* -------------------------------------------------------------------------- */

fn role_name_of(rid: i32, roles: &[Role]) -> String {
    roles
        .iter()
        .find(|r| r.role_id == rid)
        .map(|r| r.role_name.clone())
        .unwrap_or_else(|| format!("id={rid}"))
}

/* -------------------------------------------------------------------------- */
/*                    API request structures                                   */
/* -------------------------------------------------------------------------- */

// Updated field names to match what the backend expects
#[derive(Serialize, Debug)]
struct UpdateEnvPayload {
    ll_fs_ro: String,
    ll_fs_rw: String,
    ll_tcp_bind: String,
    ll_tcp_connect: String,
    allowed_ips: String,
    allowed_domains: String,
}

// Updated field names to match what the backend expects
#[derive(Serialize, Debug)]
struct CreateEnvPayload {
    app_name:       String,
    role_id:        i32,
    default_ro:     String,
    default_rw:     String,
    tcp_bind:       String,
    tcp_connect:    String,
    allowed_ips:    String,
    allowed_domains:String,
}

/* -------------------------------------------------------------------------- */
/*                         composant Configurations                           */
/* -------------------------------------------------------------------------- */

#[function_component(Configurations)]
pub fn configurations() -> Html {
    /* ---------------- states ---------------- */
    let roles = use_state(Vec::<Role>::new);
    let envs = use_state(Vec::<AppPolicy>::new);
    let selected_role = use_state(|| -1);
    let selected_env = use_state(|| None::<AppPolicy>);

    /* form – création */
    let f_app = use_state(String::new);
    let f_ro = use_state(String::new);
    let f_rw = use_state(String::new);
    let f_bind = use_state(String::new);
    let f_conn = use_state(String::new);
    let f_ips = use_state(String::new);
    let f_dom = use_state(String::new);

    /* ------------------------------------------------------------------ */
    /* 1) charge les rôles et toutes les configs au montage               */
    /* ------------------------------------------------------------------ */
    {
        let r = roles.clone();
        let e = envs.clone();
        use_effect_with((), move |_| {
            // Fetch roles (using /rules/roles as specified)
            spawn_local(async move {
                match fetch_json::<(), Vec<Role>>(Method::GET, "/rules/roles", None::<&()>).await {
                    Ok(v) => {
                        info!("Roles fetched successfully: {:?}", v);
                        r.set(v);
                    },
                    Err(e) => error!("Error fetching roles: {:?}", e),
                }
                
                // Fetch all configurations
                match fetch_json::<(), Vec<AppPolicy>>(Method::GET, "/rules/envs", None::<&()>).await {
                    Ok(v) => {
                        info!("Configurations fetched successfully: {:?}", v);
                        e.set(v);
                    },
                    Err(e) => error!("Error fetching configurations: {:?}", e),
                }
            });
            || ()
        });
    }

    /* ------------------------------------------------------------------ */
    /* 3) filtrage des envs par rôle                                       */
    /* ------------------------------------------------------------------ */
    let envs_filtered = {
        let rid = *selected_role;
        envs
            .iter()
            .filter(|p| rid != -1 && p.role_id == rid)
            .cloned()
            .collect::<Vec<_>>()
    };

    /* ------------------------------------------------------------------ */
    /* 5) handlers UI                                                     */
    /* ------------------------------------------------------------------ */
    let on_role_change = {
        let sel_role = selected_role.clone();
        let sel_env = selected_env.clone();
        Callback::from(move |e: Event| {
            let sel: HtmlSelectElement = e.target_unchecked_into();
            let role_id = sel.value().parse().unwrap_or(-1);
            sel_role.set(role_id);
            sel_env.set(None); // Reset selected environment when role changes
        })
    };

    let on_select_env = {
        let sel_env = selected_env.clone();
        Callback::from(move |pid: i32| {
            let sel_env = sel_env.clone();
            spawn_local(async move {
                let path = format!("/rules/env_id/{pid}");
                match fetch_json::<(), AppPolicy>(Method::GET, &path, None::<&()>).await {
                    Ok(env) => sel_env.set(Some(env)),
                    Err(e) => error!("Error fetching environment details: {:?}", e),
                }
            });
        })
    };

    /* ----------- mise à jour d'une config ---------------- */
    let on_update_env = {
        let sel_env = selected_env.clone();
        let envs_st = envs.clone();
        Callback::from(move |_| {
            if let Some(env) = (*sel_env).clone() {
                // Updated payload structure with correct field names
                let body = UpdateEnvPayload {
                    ll_fs_ro: env.default_ro.clone(),
                    ll_fs_rw: env.default_rw.clone(),
                    ll_tcp_bind: env.tcp_bind.clone(),
                    ll_tcp_connect: env.tcp_connect.clone(),
                    allowed_ips: env.allowed_ips.clone(),
                    allowed_domains: env.allowed_domains.clone(),
                };
                
                info!("Updating environment with payload: {:?}", &body);
                
                let sel_env2 = sel_env.clone();
                let envs_st2 = envs_st.clone();
                let path = format!("/rules/env_id/{}", env.policy_id);
                spawn_local(async move {
                    match fetch_json::<_, ()>(Method::PUT, &path, Some(&body)).await {
                        Ok(_) => {
                            info!("Configuration updated successfully");
                            // Immediately update the local env
                            let updated_env = AppPolicy {
                                default_ro: body.ll_fs_ro.clone(),
                                default_rw: body.ll_fs_rw.clone(),
                                tcp_bind: body.ll_tcp_bind.clone(),
                                tcp_connect: body.ll_tcp_connect.clone(),
                                allowed_ips: body.allowed_ips.clone(),
                                allowed_domains: body.allowed_domains.clone(),
                                ..env.clone()
                            };
                            
                            // Update the list
                            let mut updated_envs = (*envs_st2).clone();
                            for e in &mut updated_envs {
                                if e.policy_id == env.policy_id {
                                    *e = updated_env.clone();
                                    break;
                                }
                            }
                            envs_st2.set(updated_envs);
                            
                            // Update selected env
                            sel_env2.set(Some(updated_env));
                        },
                        Err(e) => error!("Update failed: {:?}", e),
                    }
                });
            }
        })
    };

// ------------------------------------------------------------------
// 9) Supprimer la config sélectionnée avec confirmation
// ------------------------------------------------------------------
let on_delete_env = {
    let envs_state         = envs.clone();        // liste dans la colonne de gauche
    let selected_env_state = selected_env.clone(); // détail au centre

    Callback::from(move |_| {
        if let Some(env) = (*selected_env_state).clone() {
            if !confirm("Confirmer la suppression de cette configuration ?") {
                return;
            }

            let pid                 = env.policy_id;
            let envs_after_delete   = envs_state.clone();
            let selected_env_clear  = selected_env_state.clone();

            spawn_local(async move {
                // DELETE /rules/env_id/{pid}
                let path = format!("/rules/env_id/{pid}");
                match fetch_empty(Method::DELETE, &path, None::<&()>).await {
                    Ok(_) => {
                        // 1) retrait immédiat de la liste
                        envs_after_delete.set(
                            envs_after_delete
                                .iter()
                                .filter(|p| p.policy_id != pid)
                                .cloned()
                                .collect::<Vec<_>>()
                        );
                        // 2) panneau central vidé
                        selected_env_clear.set(None);
                        info!("Suppression réussie");
                    }
                    Err(e) => error!("Suppression KO : {:?}", e),
                }
            });
        }
    })
};

// ------------------------------------------------------------------
// 10) Créer une nouvelle config (POST /rules/env → GET /rules/env/{app})
// ------------------------------------------------------------------
let on_create_env = {
    // handles qu’on va capturer
    let envs_state   = envs.clone();
    let sel_env      = selected_env.clone();
    let role_id_st   = selected_role.clone();

    let f_app  = f_app.clone();
    let f_ro   = f_ro.clone();
    let f_rw   = f_rw.clone();
    let f_bind = f_bind.clone();
    let f_conn = f_conn.clone();
    let f_ips  = f_ips.clone();
    let f_dom  = f_dom.clone();

    // remise à zéro du formulaire
    let reset_form = {
        let f_app  = f_app.clone();
        let f_ro   = f_ro.clone();
        let f_rw   = f_rw.clone();
        let f_bind = f_bind.clone();
        let f_conn = f_conn.clone();
        let f_ips  = f_ips.clone();
        let f_dom  = f_dom.clone();
        move || {
            f_app.set(String::new());
            f_ro.set(String::new());
            f_rw.set(String::new());
            f_bind.set(String::new());
            f_conn.set(String::new());
            f_ips.set(String::new());
            f_dom.set(String::new());
        }
    };

    Callback::from(move |_| {
        let rid = *role_id_st;
        if rid == -1 {
            error!("Sélectionnez d’abord un rôle");
            return;
        }

        // on clone les valeurs pour pouvoir les bouger dans l’async
        let app  = (*f_app).clone();
        if app.trim().is_empty() {
            error!("Le nom de l’application est requis");
            return;
        }

        let payload = serde_json::json!({
            "app_name":        app,
            "role_id":         rid,
            "default_ro":      (*f_ro).clone(),
            "default_rw":      (*f_rw).clone(),
            "tcp_bind":        (*f_bind).clone(),
            "tcp_connect":     (*f_conn).clone(),
            "allowed_ips":     (*f_ips).clone(),
            "allowed_domains": (*f_dom).clone(),
        });

        let envs_after = envs_state.clone();
        let sel_env2   = sel_env.clone();
        let reset      = reset_form.clone();

        spawn_local(async move {
            // 1) POST sans attendre de JSON
            if let Err(e) = fetch_empty(Method::POST, "/rules/env", Some(&payload)).await {
                error!("Création KO : {e:?}");
                return;
            }

            // 2) GET /rules/env/{app_name} pour récupérer la conf complète
            let path = format!("/rules/env/{app}");
            match fetch_json::<(), AppPolicy>(Method::GET, &path, None::<&()>).await {
                Err(e)        => error!("Impossible de récupérer la config créée : {e:?}"),
                Ok(new_env) => {
                    // 2.a) l’insère dans la liste
                    let mut list = (*envs_after).clone();
                    list.push(new_env.clone());
                    envs_after.set(list);

                    // 2.b) l’affiche dans la colonne centrale
                    sel_env2.set(Some(new_env));

                    // 3) nettoie le formulaire
                    reset();
                    info!("Création OK");
                }
            }
        });
    })
};

    /* ----------- helpers input binding -------------------------------- */
    let bind_input = |st: UseStateHandle<String>| {
        Callback::from(move |e: InputEvent| {
            let value = e.target_unchecked_into::<HtmlInputElement>().value();
            st.set(value);
        })
    };

    // Input binding for environment editing
    let bind_env_input = |field: &'static str, se: UseStateHandle<Option<AppPolicy>>| {
        Callback::from(move |e: InputEvent| {
            let value = e.target_unchecked_into::<HtmlInputElement>().value();
            if let Some(mut env) = (*se).clone() {
                match field {
                    "default_ro" => env.default_ro = value,
                    "default_rw" => env.default_rw = value,
                    "tcp_bind" => env.tcp_bind = value,
                    "tcp_connect" => env.tcp_connect = value,
                    "allowed_ips" => env.allowed_ips = value,
                    "allowed_domains" => env.allowed_domains = value,
                    _ => {}
                }
                se.set(Some(env));
            }
        })
    };

    /* ------------------------------------------------------------------ */
    /* UI                                                                 */
    /* ------------------------------------------------------------------ */
    html! {
        <div class="container">
            <h2 style="margin-bottom: 2rem; font-size: 1.5rem; font-weight: 600; color: #2c3e50;">{"Gestion des Configurations"}</h2>
            // Colonne 1
            <div style="display: flex; gap: 1.5rem;">
                <div style="flex: 1; background: white; border-radius: 8px; padding: 1.5rem; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
                    <h3 style="font-size: 1.1rem; margin-bottom: 1rem; font-weight: 500; border-bottom: 1px solid #eee; padding-bottom: 0.75rem;">{"Sélection du Rôle"}</h3>
                    <div style="margin-bottom: 1.5rem;">
                        <select 
                            value={selected_role.to_string()}
                            onchange={on_role_change.clone()}
                            style="
                                width: 100%;
                                padding: 0.75rem;
                                background-color: #fff;
                                border: 1px solid #ccc;
                                border-radius: 4px;
                                color: #333;
                                box-sizing: border-box;
                            "
                        >
                            <option value="-1" selected={*selected_role == -1}>
                                {"Choisir un rôle"}
                            </option>
                            { for roles.iter().map(|role| html! {
                                <option value={role.role_id.to_string()}>
                                    { &role.role_name }
                                </option>
                            }) }
                        </select>
                    </div>

                    <h4 style="font-size: 1rem; font-weight: 500; margin-top: 2rem; margin-bottom: 1rem; border-bottom: 1px solid #eee; padding-bottom: 0.5rem;">{"Configurations"}</h4>
                    {
                        if envs_filtered.is_empty() && *selected_role != -1 {
                            html! {
                                <p style="color: #888; text-align: center; padding: 1rem 0;">{"Aucune configuration pour ce rôle."}</p>
                            }
                        } else if *selected_role == -1 {
                            html! {
                                <p style="color: #888; text-align: center; padding: 1rem 0;">{"Veuillez sélectionner un rôle."}</p>
                            }
                        } else {
                            html! {
                                <ul style="list-style: none; padding: 0; margin: 0;">
                                    { for envs_filtered.iter().map(|p| {
                                        let is_selected = selected_env.as_ref().map_or(false, |e| e.policy_id == p.policy_id);
                                        html!{
                                            <li
                                                onclick={{
                                                    let cb = on_select_env.clone();
                                                    let id = p.policy_id;
                                                    Callback::from(move |_| cb.emit(id))
                                                }}
                                                style={format!(
                                                    "padding: 0.75rem 1rem; border-radius: 4px; margin-bottom: 0.5rem; cursor: pointer; transition: all 0.2s ease; {}",
                                                    if is_selected {
                                                        "background-color: #3f51b5; color: white; font-weight: 500;"
                                                    } else {
                                                        "background-color: #f5f5f5; color: #555; border: 1px solid #ddd;"
                                                    }
                                                )}
                                            >
                                                { &p.app_name }
                                            </li>
                                        }
                                    })}
                                </ul>
                            }
                        }
                    }
                </div>

                // Colonne 2: Détails / Édition
                <div style="flex: 1.5; background: white; border-radius: 8px; padding: 1.5rem; box-shadow: 0 2px 10px rgba(0,0,0,0.05); position: relative;">
                    {
                        if let Some(env) = &*selected_env {
                            html!{
                                <div class="role-details-container">
                                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                                        <h3 style="margin: 0; padding: 0; font-size: 1.1rem; font-weight: 500;">
                                            { format!("{} ({})", env.app_name, role_name_of(env.role_id, &roles)) }
                                        </h3>
                                        <button 
                                            onclick={on_delete_env.clone()}
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
                                    <p style="font-size: 0.8rem; color: #888; margin-bottom: 1.5rem;">
                                        { format!("ID: {}, Dernière mise à jour: {}", env.policy_id, env.updated_at) }
                                    </p>

                                    <div style="padding: .5rem;">
                                        <div style="margin-bottom: 1rem;">
                                            <label style="display: block; margin-bottom: 0.3rem; font-weight: 500;">{"LL_FS_RO"}</label>
                                            <input 
                                                type="text" 
                                                value={env.default_ro.clone()}
                                                oninput={bind_env_input("default_ro", selected_env.clone())}
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
                                            <p style="margin-top: 0.3rem; color: #888; font-size: 0.8rem;">{"Chemins accessibles en lecture seule"}</p>
                                        </div>

                                        <div style="margin-bottom: 1rem;">
                                            <label style="display: block; margin-bottom: 0.3rem; font-weight: 500;">{"LL_FS_RW"}</label>
                                            <input 
                                                type="text" 
                                                value={env.default_rw.clone()}
                                                oninput={bind_env_input("default_rw", selected_env.clone())}
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
                                            <p style="margin-top: 0.3rem; color: #888; font-size: 0.8rem;">{"Chemins accessibles en lecture/écriture"}</p>
                                        </div>

                                        <div style="margin-bottom: 1rem;">
                                            <label style="display: block; margin-bottom: 0.3rem; font-weight: 500;">{"TCP_BIND"}</label>
                                            <input 
                                                type="text" 
                                                value={env.tcp_bind.clone()}
                                                oninput={bind_env_input("tcp_bind", selected_env.clone())}
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
                                            <p style="margin-top: 0.3rem; color: #888; font-size: 0.8rem;">{"Ports pour les connexions entrantes"}</p>
                                        </div>

                                        <div style="margin-bottom: 1rem;">
                                            <label style="display: block; margin-bottom: 0.3rem; font-weight: 500;">{"TCP_CONNECT"}</label>
                                            <input 
                                                type="text" 
                                                value={env.tcp_connect.clone()}
                                                oninput={bind_env_input("tcp_connect", selected_env.clone())}
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
                                            <p style="margin-top: 0.3rem; color: #888; font-size: 0.8rem;">{"Ports pour les connexions sortantes"}</p>
                                        </div>

                                        <div style="margin-bottom: 1rem;">
                                            <label style="display: block; margin-bottom: 0.3rem; font-weight: 500;">{"Allowed IPs"}</label>
                                            <input 
                                                type="text" 
                                                value={env.allowed_ips.clone()}
                                                oninput={bind_env_input("allowed_ips", selected_env.clone())}
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

                                        <div style="margin-bottom: 1rem;">
                                            <label style="display: block; margin-bottom: 0.3rem; font-weight: 500;">{"Allowed Domains"}</label>
                                            <input 
                                                type="text" 
                                                value={env.allowed_domains.clone()}
                                                oninput={bind_env_input("allowed_domains", selected_env.clone())}
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
                                            onclick={on_update_env.clone()}
                                            style="
                                                background-color: #3f51b5;
                                                color: #fff;
                                                border: none;
                                                border-radius: 4px;
                                                padding: 0.75rem 1.25rem;
                                                font-size: 1rem;
                                                margin-top: 1rem;
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
                            html!{ 
                                <div style="display: flex; justify-content: center; align-items: center; height: 100%; color: #888;">
                                    <p>{ "Sélectionnez une configuration pour afficher ses détails." }</p>
                                </div>
                            }
                        }
                    }
                </div>

                // Colonne 3: Création
                <div style="flex: 1.5; background: white; border-radius: 8px; padding: 1.5rem; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
                    <h3 style="font-size: 1.1rem; margin-bottom: 1rem; font-weight: 500; border-bottom: 1px solid #eee; padding-bottom: 0.75rem;">{"Nouvelle Configuration"}</h3>
                    <p style="font-size: 0.8rem; color: #888; margin-bottom: 1.5rem;">
                        { 
                            if *selected_role == -1 {
                                "Veuillez d'abord sélectionner un rôle" 
                            } else {
                                "Configuration pour le rôle sélectionné"
                            }
                        }
                    </p>

                    <div style="padding: .5rem;">
                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.3rem; font-weight: 500;">{"Nom de l'application"}</label>
                            <input 
                                type="text" 
                                placeholder="Nom unique de l'application"
                                value={(*f_app).clone()} 
                                oninput={bind_input(f_app.clone())} 
                                disabled={*selected_role == -1}
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

                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.3rem; font-weight: 500;">{"LL_FS_RO"}</label>
                            <input 
                                type="text" 
                                placeholder="/usr:/lib"
                                value={(*f_ro).clone()} 
                                oninput={bind_input(f_ro.clone())} 
                                disabled={*selected_role == -1}
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
                            <p style="margin-top: 0.3rem; color: #888; font-size: 0.8rem;">{"Chemins accessibles en lecture seule (séparés par des ':')"}</p>
                        </div>

                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.3rem; font-weight: 500;">{"LL_FS_RW"}</label>
                            <input 
                                type="text" 
                                placeholder="/tmp:/var/tmp"
                                value={(*f_rw).clone()} 
                                oninput={bind_input(f_rw.clone())} 
                                disabled={*selected_role == -1}
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
                            <p style="margin-top: 0.3rem; color: #888; font-size: 0.8rem;">{"Chemins accessibles en lecture/écriture (séparés par des ':')"}</p>
                        </div>

                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.3rem; font-weight: 500;">{"TCP_BIND"}</label>
                            <input 
                                type="text" 
                                placeholder="9418"
                                value={(*f_bind).clone()} 
                                oninput={bind_input(f_bind.clone())} 
                                disabled={*selected_role == -1}
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

                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.3rem; font-weight: 500;">{"TCP_CONNECT"}</label>
                            <input 
                                type="text" 
                                placeholder="80:443"
                                value={(*f_conn).clone()} 
                                oninput={bind_input(f_conn.clone())} 
                                disabled={*selected_role == -1}
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

                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.3rem; font-weight: 500;">{"IPs autorisées"}</label>
                            <input 
                                type="text" 
                                placeholder="192.168.1.0/24"
                                value={(*f_ips).clone()} 
                                oninput={bind_input(f_ips.clone())} 
                                disabled={*selected_role == -1}
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

                        <div style="margin-bottom: 1rem;">
                            <label style="display: block; margin-bottom: 0.3rem; font-weight: 500;">{"Domaines autorisés"}</label>
                            <input 
                                type="text" 
                                placeholder="example.com,domain.org"
                                value={(*f_dom).clone()} 
                                oninput={bind_input(f_dom.clone())} 
                                disabled={*selected_role == -1}
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
                            onclick={on_create_env}
                            disabled={*selected_role == -1}
                            style={format!(
                                "
                                background-color: {};
                                color: #fff;
                                border: none;
                                border-radius: 4px;
                                padding: 0.75rem 1.25rem;
                                font-size: 1rem;
                                margin-top: 1rem;
                                cursor: {};
                                transition: background-color 0.3s, transform 0.2s;
                                width: 100%;
                                ",
                                if *selected_role == -1 { "#cecece" } else { "#3f51b5" },
                                if *selected_role == -1 { "not-allowed" } else { "pointer" }
                            )}
                        >
                            { "Créer la configuration" }
                        </button>
                    </div>
                </div>
            </div>
        </div>
    }
}