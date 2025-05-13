use gloo_dialogs::confirm;
use gloo_net::http::Method;
use log::{error, info};
use serde::{Deserialize, Serialize};
use web_sys::{HtmlInputElement, HtmlSelectElement, InputEvent};
use yew::platform::spawn_local;
use yew::prelude::*;

use crate::api::fetch_json;

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

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct SandboxEvent {
    event_id: i32,
    timestamp: String,
    hostname: String,
    app_name: String,
    denied_path: Option<String>,
    operation: String,
    result: String,
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
    let events = use_state(Vec::<SandboxEvent>::new);
    let view_mode = use_state(|| "edit".to_string()); // "edit" or "events"

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
    /* 4) charge les events quand selected_env change                      */
    /* ------------------------------------------------------------------ */
    {
        let ev_state = events.clone();
        use_effect_with(selected_env.clone(), move |env_opt| {
            if let Some(env) = &**env_opt {
                let path = format!("/logs/events/{}", env.app_name);
                let ev_state = ev_state.clone();
                spawn_local(async move {
                    match fetch_json::<(), Vec<SandboxEvent>>(Method::GET, &path, None::<&()>).await {
                        Ok(v) => ev_state.set(v),
                        Err(e) => error!("Error fetching events: {:?}", e),
                    }
                });
            } else {
                ev_state.set(Vec::new());
            }
            || ()
        });
    }

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
        let view_mode_state = view_mode.clone();
        Callback::from(move |pid: i32| {
            let sel_env = sel_env.clone();
            view_mode_state.set("edit".to_string()); // Reset to edit mode when selecting a new env
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
                            // Refresh list
                            match fetch_json::<(), Vec<AppPolicy>>(Method::GET, "/rules/envs", None::<&()>).await {
                                Ok(v) => {
                                    envs_st2.set(v);
                                    // Keep the updated version
                                    match fetch_json::<(), AppPolicy>(Method::GET, &path, None::<&()>).await {
                                        Ok(new_env) => sel_env2.set(Some(new_env)),
                                        Err(e) => error!("Error refreshing env details: {:?}", e),
                                    }
                                },
                                Err(e) => error!("Error refreshing envs list: {:?}", e),
                            }
                        },
                        Err(e) => error!("Update failed: {:?}", e),
                    }
                });
            }
        })
    };

    /* ----------- suppression ------------------------------------------ */
    let on_delete_env = {
        let sel_env = selected_env.clone();
        let envs_st = envs.clone();
        Callback::from(move |_| {
            if let Some(env) = (*sel_env).clone() {
                if confirm("Êtes-vous sûr de vouloir supprimer cette configuration ?") {
                    let path = format!("/rules/env_id/{}", env.policy_id);
                    let sel_env2 = sel_env.clone();
                    let envs_st2 = envs_st.clone();
                    spawn_local(async move {
                        match fetch_json::<(), ()>(Method::DELETE, &path, None::<&()>).await {
                            Ok(_) => {
                                info!("Configuration deleted successfully");
                                sel_env2.set(None);
                                match fetch_json::<(), Vec<AppPolicy>>(Method::GET, "/rules/envs", None::<&()>).await {
                                    Ok(v) => envs_st2.set(v),
                                    Err(e) => error!("Error refreshing envs list: {:?}", e),
                                }
                            },
                            Err(e) => error!("Delete failed: {:?}", e),
                        }
                    });
                }
            }
        })
    };

    // -------------------- création d’une nouvelle configuration ---------------
let on_create_env = {
    // --- states à cloner pour qu’ils vivent dans le callback ---------------
    let envs_st    = envs.clone();          // liste affichée dans la colonne de gauche
    let sel_env    = selected_env.clone();  // env actuellement ouverte au centre
    let rid_st     = selected_role.clone(); // rôle sélectionné

    // champs du formulaire
    let n_app  = f_app.clone();
    let n_ro   = f_ro.clone();
    let n_rw   = f_rw.clone();
    let n_bind = f_bind.clone();
    let n_conn = f_conn.clone();
    let n_ips  = f_ips.clone();
    let n_dom  = f_dom.clone();

    // --- petit helper pour vider le formulaire après succès ---------------
    let reset_form = {
        let app  = f_app.clone();
        let ro   = f_ro.clone();
        let rw   = f_rw.clone();
        let bind = f_bind.clone();
        let conn = f_conn.clone();
        let ips  = f_ips.clone();
        let dom  = f_dom.clone();

        move || {
            app.set(String::new());
            ro.set(String::new());
            rw.set(String::new());
            bind.set(String::new());
            conn.set(String::new());
            ips.set(String::new());
            dom.set(String::new());
        }
    };

    // --------------------------- callback UI ------------------------------
    Callback::from(move |_| {
        let rid = *rid_st;
        if rid == -1 {
            error!("Veuillez d’abord sélectionner un rôle");
            return;
        }
        if n_app.is_empty() {
            error!("Le nom de l’application est requis");
            return;
        }

        // payload que le back / POST /rules/env attend
        let body = CreateEnvPayload {
            app_name:        (*n_app).clone(),
            role_id:         rid,
            default_ro:      (*n_ro).clone(),
            default_rw:      (*n_rw).clone(),
            tcp_bind:        (*n_bind).clone(),
            tcp_connect:     (*n_conn).clone(),
            allowed_ips:     (*n_ips).clone(),
            allowed_domains: (*n_dom).clone(),
        };

        info!("Creating environment with payload: {:?}", &body);

        // clones pour l’async
        let envs_st2 = envs_st.clone();
        let sel_env2 = sel_env.clone();
        let reset    = reset_form.clone();
        let app_name = (*n_app).clone();   // pour la requête GET juste après

        spawn_local(async move {
            // 1) création ---------------------------------------------------
            match fetch_json::<_, ()>(Method::POST, "/rules/env", Some(&body)).await {
                Err(e) => error!("Creation failed: {:?}", e),
                Ok(_)  => {
                    info!("Configuration created successfully");

                    // 2) récupération de la ligne nouvellement créée ----------
                    let path = format!("/rules/env/{}", app_name);
                    match fetch_json::<(), AppPolicy>(Method::GET, &path, None::<&()>).await {
                        Err(e) => error!("Unable to fetch newly created env: {:?}", e),
                        Ok(new_env) => {
                            // 3) mise à jour instantanée du state --------------
                            let mut list = (*envs_st2).clone();
                            list.push(new_env.clone());
                            envs_st2.set(list);

                            // 4) on l’affiche aussitôt au centre --------------
                            sel_env2.set(Some(new_env));

                            // 5) on vide le formulaire ------------------------
                            reset();
                        }
                    }
                }
            }
        });
    })
};


    /* ----------- toggle view mode ----------------------------------- */
    let toggle_view_mode = {
        let vm = view_mode.clone();
        Callback::from(move |_| {
            let current = (*vm).clone();
            vm.set(if current == "edit" { "events".to_string() } else { "edit".to_string() });
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
        <div class="container mt-4">
            <h2 class="title is-4 mb-4">{"Gestion des Configurations"}</h2>
            
            <div class="columns">
                /* ----- colonne 1 : rôles et envs ----- */
                <div class="column is-one-quarter box">
                    <h3 class="subtitle is-5 mb-3">{ "Sélection du Rôle" }</h3>
                    <div class="field">
                        <div class="control">
                            <div class="select is-fullwidth">
                                <select onchange={on_role_change}>
                                    <option value="-1">{ "-- Sélectionner un rôle --" }</option>
                                    { for roles.iter().map(|r| html!{
                                        <option value={r.role_id.to_string()}>{ &r.role_name }</option>
                                    })}
                                </select>
                            </div>
                        </div>
                    </div>

                    <h4 class="subtitle is-6 mt-4 mb-2">{ "Configurations" }</h4>
                    {
                        if envs_filtered.is_empty() && *selected_role != -1 {
                            html! {
                                <p class="has-text-grey">{ "Aucune configuration pour ce rôle." }</p>
                            }
                        } else if *selected_role == -1 {
                            html! {
                                <p class="has-text-grey">{ "Veuillez sélectionner un rôle." }</p>
                            }
                        } else {
                            html! {
                                <div class="menu">
                                    <ul class="menu-list">
                                        { for envs_filtered.iter().map(|p| {
                                            let is_selected = selected_env.as_ref().map_or(false, |e| e.policy_id == p.policy_id);
                                            html!{
                                                <li
                                                    class={if is_selected { "is-active" } else { "" }}
                                                    onclick={{
                                                        let cb = on_select_env.clone();
                                                        let id = p.policy_id;
                                                        Callback::from(move |_| cb.emit(id))
                                                    }}
                                                >
                                                    { &p.app_name }
                                                </li>

                                            }
                                        })}
                                    </ul>
                                </div>
                            }
                        }
                    }
                </div>

                /* ----- colonne 2 : détails / édition ----- */
                <div class="column is-one-third box ml-3">
                {
                    if let Some(env) = &*selected_env {
                        html!{
                            <>
                                <div class="is-flex is-justify-content-space-between is-align-items-center mb-3">
                                    <h3 class="subtitle is-5 mb-0">
                                        { format!("{} ({})", env.app_name, role_name_of(env.role_id, &roles)) }
                                    </h3>
                                    <button 
                                        class="button is-small" 
                                        onclick={toggle_view_mode}
                                    >
                                        { if *view_mode == "edit" { "Voir les événements" } else { "Modifier" } }
                                    </button>
                                </div>
                                <p class="is-size-7 mb-4">{ format!("ID: {}, Dernière mise à jour: {}", env.policy_id, env.updated_at) }</p>

                                {
                                    if *view_mode == "edit" {
                                        html!{
                                            <div class="mt-3">
                                                <div class="field">
                                                    <label class="label">{ "LL_FS_RO" }</label>
                                                    <div class="control">
                                                        <input 
                                                            class="input" 
                                                            type="text" 
                                                            value={env.default_ro.clone()}
                                                            oninput={bind_env_input("default_ro", selected_env.clone())}
                                                        />
                                                    </div>
                                                    <p class="help">{"Chemins accessibles en lecture seule"}</p>
                                                </div>

                                                <div class="field">
                                                    <label class="label">{ "LL_FS_RW" }</label>
                                                    <div class="control">
                                                        <input 
                                                            class="input" 
                                                            type="text" 
                                                            value={env.default_rw.clone()}
                                                            oninput={bind_env_input("default_rw", selected_env.clone())}
                                                        />
                                                    </div>
                                                    <p class="help">{"Chemins accessibles en lecture/écriture"}</p>
                                                </div>

                                                <div class="field">
                                                    <label class="label">{ "TCP_BIND" }</label>
                                                    <div class="control">
                                                        <input 
                                                            class="input" 
                                                            type="text" 
                                                            value={env.tcp_bind.clone()}
                                                            oninput={bind_env_input("tcp_bind", selected_env.clone())}
                                                        />
                                                    </div>
                                                    <p class="help">{"Ports pour les connexions entrantes"}</p>
                                                </div>

                                                <div class="field">
                                                    <label class="label">{ "TCP_CONNECT" }</label>
                                                    <div class="control">
                                                        <input 
                                                            class="input" 
                                                            type="text" 
                                                            value={env.tcp_connect.clone()}
                                                            oninput={bind_env_input("tcp_connect", selected_env.clone())}
                                                        />
                                                    </div>
                                                    <p class="help">{"Ports pour les connexions sortantes"}</p>
                                                </div>

                                                <div class="field">
                                                    <label class="label">{ "Allowed IPs" }</label>
                                                    <div class="control">
                                                        <input 
                                                            class="input" 
                                                            type="text" 
                                                            value={env.allowed_ips.clone()}
                                                            oninput={bind_env_input("allowed_ips", selected_env.clone())}
                                                        />
                                                    </div>
                                                </div>

                                                <div class="field">
                                                    <label class="label">{ "Allowed Domains" }</label>
                                                    <div class="control">
                                                        <input 
                                                            class="input" 
                                                            type="text" 
                                                            value={env.allowed_domains.clone()}
                                                            oninput={bind_env_input("allowed_domains", selected_env.clone())}
                                                        />
                                                    </div>
                                                </div>

                                                <div class="field is-grouped mt-4">
                                                    <div class="control">
                                                        <button class="button is-primary" onclick={on_update_env.clone()}>
                                                            { "Enregistrer" }
                                                        </button>
                                                    </div>
                                                    <div class="control">
                                                        <button class="button is-danger" onclick={on_delete_env.clone()}>
                                                            { "Supprimer" }
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        }
                                    } else {
                                        html!{
                                            <div class="mt-3">
                                                <h4 class="subtitle is-6 mb-2">{ "Événements" }</h4>
                                                {
                                                    if events.is_empty() {
                                                        html! {
                                                            <p class="has-text-grey">{ "Aucun événement trouvé." }</p>
                                                        }
                                                    } else {
                                                        html! {
                                                            <div class="table-container">
                                                                <table class="table is-fullwidth is-striped is-hoverable">
                                                                    <thead>
                                                                        <tr>
                                                                            <th>{"Date"}</th>
                                                                            <th>{"Opération"}</th>
                                                                            <th>{"Résultat"}</th>
                                                                        </tr>
                                                                    </thead>
                                                                    <tbody>
                                                                        { for events.iter().map(|ev| html!{
                                                                            <tr>
                                                                                <td>{ &ev.timestamp }</td>
                                                                                <td>{ &ev.operation }</td>
                                                                                <td>{ &ev.result }</td>
                                                                            </tr>
                                                                        }) }
                                                                    </tbody>
                                                                </table>
                                                            </div>
                                                        }
                                                    }
                                                }
                                            </div>
                                        }
                                    }
                                }
                            </>
                        }
                    } else {
                        html!{ 
                            <div class="has-text-centered my-6">
                                <p class="has-text-grey">{ "Sélectionnez une configuration pour afficher ses détails." }</p>
                            </div> 
                        }
                    }
                }
                </div>

                /* ----- colonne 3 : création ----- */
                <div class="column box ml-3">
                    <h3 class="subtitle is-5 mb-3">{ "Nouvelle Configuration" }</h3>
                    <p class="is-size-7 mb-4">{ 
                        if *selected_role == -1 {
                            "Veuillez d'abord sélectionner un rôle" 
                        } else {
                            "Configuration pour le rôle sélectionné"
                        }
                    }</p>

                    <div class="field">
                        <label class="label">{ "Nom de l'application" }</label>
                        <div class="control">
                            <input 
                                class="input" 
                                type="text" 
                                placeholder="Nom unique de l'application" 
                                value={(*f_app).clone()} 
                                oninput={bind_input(f_app.clone())} 
                                disabled={*selected_role == -1}
                            />
                        </div>
                    </div>

                    <div class="field">
                        <label class="label">{ "LL_FS_RO" }</label>
                        <div class="control">
                            <input 
                                class="input" 
                                type="text" 
                                placeholder="/usr:/lib" 
                                value={(*f_ro).clone()} 
                                oninput={bind_input(f_ro.clone())} 
                                disabled={*selected_role == -1}
                            />
                        </div>
                        <p class="help">{"Chemins accessibles en lecture seule (séparés par des ':')"}</p>
                    </div>

                    <div class="field">
                        <label class="label">{ "LL_FS_RW" }</label>
                        <div class="control">
                            <input 
                                class="input" 
                                type="text" 
                                placeholder="/tmp:/var/tmp" 
                                value={(*f_rw).clone()} 
                                oninput={bind_input(f_rw.clone())} 
                                disabled={*selected_role == -1}
                            />
                        </div>
                        <p class="help">{"Chemins accessibles en lecture/écriture (séparés par des ':')"}</p>
                    </div>

                    <div class="field">
                        <label class="label">{ "TCP_BIND" }</label>
                        <div class="control">
                            <input 
                                class="input" 
                                type="text" 
                                placeholder="9418" 
                                value={(*f_bind).clone()} 
                                oninput={bind_input(f_bind.clone())} 
                                disabled={*selected_role == -1}
                            />
                        </div>
                    </div>

                    <div class="field">
                        <label class="label">{ "TCP_CONNECT" }</label>
                        <div class="control">
                            <input 
                                class="input" 
                                type="text" 
                                placeholder="80:443" 
                                value={(*f_conn).clone()} 
                                oninput={bind_input(f_conn.clone())} 
                                disabled={*selected_role == -1}
                            />
                        </div>
                    </div>

                    <div class="field">
                        <label class="label">{ "IPs autorisées" }</label>
                        <div class="control">
                            <input 
                                class="input" 
                                type="text" 
                                placeholder="192.168.1.0/24" 
                                value={(*f_ips).clone()} 
                                oninput={bind_input(f_ips.clone())} 
                                disabled={*selected_role == -1}
                            />
                        </div>
                    </div>

                    <div class="field">
                        <label class="label">{ "Domaines autorisés" }</label>
                        <div class="control">
                            <input 
                                class="input" 
                                type="text" 
                                placeholder="example.com,domain.org" 
                                value={(*f_dom).clone()} 
                                oninput={bind_input(f_dom.clone())} 
                                disabled={*selected_role == -1}
                            />
                        </div>
                    </div>

                    <div class="field mt-4">
                        <div class="control">
                            <button 
                                class="button is-primary is-fullwidth" 
                                onclick={on_create_env}
                                disabled={*selected_role == -1}
                            >
                                { "Créer la configuration" }
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    }
}