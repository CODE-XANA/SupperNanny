use std::collections::HashMap;

use gloo_net::http::Method;
use log::{error, info};
use serde::{Deserialize, Serialize};
use yew::platform::spawn_local;
use yew::prelude::*;
use web_sys::{HtmlInputElement, HtmlSelectElement, InputEvent};

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
    updated_at: String,           // NaiveDateTime → string côté back
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
/*                          helpers front / UI                                */
/* -------------------------------------------------------------------------- */

fn role_name_of(rid: i32, roles: &[Role]) -> String {
    roles
        .iter()
        .find(|r| r.role_id == rid)
        .map(|r| r.role_name.clone())
        .unwrap_or_else(|| format!("id={rid}"))
}

/* -------------------------------------------------------------------------- */
/*                         composant Configurations                           */
/* -------------------------------------------------------------------------- */

#[function_component(Configurations)]
pub fn configurations() -> Html {
    /* ---------------- states ---------------- */
    let roles          = use_state(Vec::<Role>::new);
    let envs           = use_state(Vec::<AppPolicy>::new);

    let selected_role  = use_state(|| -1);
    let role_select    = use_node_ref();

    let selected_env   = use_state(|| None::<AppPolicy>);
    let events         = use_state(Vec::<SandboxEvent>::new);
    let edit_mode      = use_state(|| true);

    /* form – création */
    let f_app          = use_state(String::new);
    let f_ro           = use_state(String::new);
    let f_rw           = use_state(String::new);
    let f_bind         = use_state(String::new);
    let f_conn         = use_state(String::new);
    let f_ips          = use_state(String::new);
    let f_dom          = use_state(String::new);

    /* ------------------------------------------------------------------ */
    /* 1) charge les rôles et toutes les configs au montage               */
    /* ------------------------------------------------------------------ */
    {
        let r = roles.clone();
        let e = envs.clone();
        use_effect_with((), move |_| {
            spawn_local(async move {
                if let Ok(v) = fetch_json::<(), Vec<Role>>(Method::GET, "/users/roles", None::<&()>).await {
                    r.set(v);
                }
                if let Ok(v) = fetch_json::<(), Vec<AppPolicy>>(Method::GET, "/rules/envs", None::<&()>).await {
                    e.set(v);
                }
            });
            || ()
        });
    }

    /* ------------------------------------------------------------------ */
    /* 2) remet la valeur du <select> après render                        */
    /* ------------------------------------------------------------------ */
    {
        let sel = role_select.clone();
        let dep = (*selected_role).to_string();
        use_effect_with(dep.clone(), move |_| {
            if let Some(sel_el) = sel.cast::<HtmlSelectElement>() {
                sel_el.set_value(&dep);
            }
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
                let path = format!("/logs/events/{}", env.app_name); // j’imagine l’endpoint
                let ev_state = ev_state.clone();
                spawn_local(async move {
                    if let Ok(v) = fetch_json::<(), Vec<SandboxEvent>>(Method::GET, &path, None::<&()>).await {
                        ev_state.set(v);
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
        Callback::from(move |e: Event| {
            let sel: HtmlSelectElement = e.target_unchecked_into();
            sel_role.set(sel.value().parse().unwrap_or(-1));
        })
    };

    let on_select_env = {
        let sel_env = selected_env.clone();
        Callback::from(move |pid: i32| {
            let sel_env = sel_env.clone();
            spawn_local(async move {
                let path = format!("/rules/env_id/{pid}");
                if let Ok(env) = fetch_json::<(), AppPolicy>(Method::GET, &path, None::<&()>).await {
                    sel_env.set(Some(env));
                }
            });
        })
    };

    /* ----------- mise à jour d’une config ---------------- */
    let on_update_env = {
        let sel_env = selected_env.clone();
        let envs_st = envs.clone();
        Callback::from(move |_| {
            if let Some(env) = (*sel_env).clone() {
                let body = serde_json::json!({
                    "ll_fs_ro":       env.default_ro.split(':').collect::<Vec<_>>(),
                    "ll_fs_rw":       env.default_rw.split(':').collect::<Vec<_>>(),
                    "ll_tcp_bind":    env.tcp_bind,
                    "ll_tcp_connect": env.tcp_connect,
                    "allowed_ips":    env.allowed_ips,
                    "allowed_domains":env.allowed_domains,
                });
                let sel_env2 = sel_env.clone();
                let envs_st2 = envs_st.clone();
                let path = format!("/rules/env_id/{}", env.policy_id);
                spawn_local(async move {
                    match fetch_json::<_, ()>(Method::PUT, &path, Some(&body)).await {
                        Ok(_) => {
                            info!("update ok");
                            // refresh list
                            if let Ok(v) = fetch_json::<(), Vec<AppPolicy>>(Method::GET, "/rules/envs", None::<&()>).await {
                                envs_st2.set(v);
                                // garder la version à jour
                                if let Ok(new_env) = fetch_json::<(), AppPolicy>(Method::GET, &path, None::<&()>).await {
                                    sel_env2.set(Some(new_env));
                                }
                            }
                        }
                        Err(e) => error!("update: {e:?}"),
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
                if web_sys::window().unwrap().confirm_with_message("Supprimer ?").unwrap_or(false) {
                    let path = format!("/rules/env_id/{}", env.policy_id);
                    let sel_env2 = sel_env.clone();
                    let envs_st2 = envs_st.clone();
                    spawn_local(async move {
                        match fetch_json::<(), ()>(Method::DELETE, &path, None::<&()>).await {
                            Ok(_) => {
                                info!("deleted");
                                sel_env2.set(None);
                                if let Ok(v) = fetch_json::<(), Vec<AppPolicy>>(Method::GET, "/rules/envs", None::<&()>).await {
                                    envs_st2.set(v);
                                }
                            }
                            Err(e) => error!("delete: {e:?}"),
                        }
                    });
                }
            }
        })
    };

    /* ----------- création --------------------------------------------- */
    let on_create_env = {
        let envs_st = envs.clone();
        let rid_st  = selected_role.clone();
        let n_app   = f_app.clone();
        let n_ro    = f_ro.clone();
        let n_rw    = f_rw.clone();
        let n_bind  = f_bind.clone();
        let n_conn  = f_conn.clone();
        let n_ips   = f_ips.clone();
        let n_dom   = f_dom.clone();

        Callback::from(move |_| {
            let rid = *rid_st;
            if rid == -1 {
                error!("choisir un rôle");
                return;
            }
            let body = serde_json::json!({
                "app_name":       (*n_app).clone(),
                "role_id":        rid,
                "default_ro":     (*n_ro).clone(),
                "default_rw":     (*n_rw).clone(),
                "tcp_bind":       (*n_bind).clone(),
                "tcp_connect":    (*n_conn).clone(),
                "allowed_ips":    (*n_ips).clone(),
                "allowed_domains":(*n_dom).clone(),
            });
            let envs_st2 = envs_st.clone();
            spawn_local(async move {
                match fetch_json::<_, ()>(Method::POST, "/rules/env", Some(&body)).await {
                    Ok(_) => {
                        info!("créé");
                        if let Ok(v) = fetch_json::<(), Vec<AppPolicy>>(Method::GET, "/rules/envs", None::<&()>).await {
                            envs_st2.set(v);
                        }
                    }
                    Err(e) => error!("create: {e:?}"),
                }
            });
        })
    };

    /* ----------- helpers input binding -------------------------------- */
    let bind_input = |st: UseStateHandle<String>| {
        Callback::from(move |e: InputEvent| {
            let v = e.target_unchecked_into::<HtmlInputElement>().value();
            st.set(v);
        })
    };

    /* ------------------------------------------------------------------ */
    /* UI                                                                 */
    /* ------------------------------------------------------------------ */
    html! {
        <div class="container">
            <div class="columns">
                /* ----- colonne 1 : rôles et envs ----- */
                <div class="column" style="border:1px solid #ccc;padding:1rem;">
                    <h3>{ "Rôle" }</h3>
                    <select ref={role_select.clone()} onchange={on_role_change}>
                        <option value="-1">{ "sélectionner…" }</option>
                        { for roles.iter().map(|r| html!{
                            <option value={r.role_id.to_string()}>{ &r.role_name }</option>
                        })}
                    </select>

                    <h4 class="mt-3">{ "Configurations" }</h4>
                    <ul>
                        { for envs_filtered.iter().map(|p| {
                            html!{
                                <li
                                    style="cursor:pointer;"
                                    onclick={{
                                        let cb=on_select_env.clone(); let id=p.policy_id;
                                        Callback::from(move |_| cb.emit(id))
                                    }}
                                >
                                    { &p.app_name }
                                </li>
                            }
                        })}
                    </ul>
                </div>

                /* ----- colonne 2 : détails / édition ----- */
                <div class="column" style="border:1px solid #ccc;padding:1rem;margin-left:1rem;">
                {
                    if let Some(env) = &*selected_env {
                        html!{
                            <>
                                <h3>{ format!("{} ({})", env.app_name, role_name_of(env.role_id,&roles)) }</h3>
                                <small>{ format!("id={}, updated={}", env.policy_id, env.updated_at) }</small>
                                <button class="ml-2" onclick={{
                                    let em=edit_mode.clone();
                                    Callback::from(move |_| em.set(!*em))
                                }}>
                                    { if *edit_mode { "Voir events" } else { "Éditer" } }
                                </button>

                                {
                                    if *edit_mode {
                                        html!{
                                            <div class="mt-3">
                                                <label>{ "LL_FS_RO" }<input
                                                    type="text" value={env.default_ro.clone()}
                                                    oninput={{
                                                        let se=selected_env.clone();
                                                        Callback::from(move |e:InputEvent|{
                                                            let mut env=(*se).clone().unwrap();
                                                            env.default_ro=e.target_unchecked_into::<HtmlInputElement>().value();
                                                            se.set(Some(env));
                                                        })
                                                    }}
                                                /></label>

                                                <label class="mt-1">{ "LL_FS_RW" }<input
                                                    type="text" value={env.default_rw.clone()}
                                                    oninput={{
                                                        let se=selected_env.clone();
                                                        Callback::from(move |e:InputEvent|{
                                                            let mut env=(*se).clone().unwrap();
                                                            env.default_rw=e.target_unchecked_into::<HtmlInputElement>().value();
                                                            se.set(Some(env));
                                                        })
                                                    }}
                                                /></label>

                                                <label class="mt-1">{ "TCP_BIND" }<input
                                                    type="text" value={env.tcp_bind.clone()}
                                                    oninput={{
                                                        let se=selected_env.clone();
                                                        Callback::from(move |e:InputEvent|{
                                                            let mut env=(*se).clone().unwrap();
                                                            env.tcp_bind=e.target_unchecked_into::<HtmlInputElement>().value();
                                                            se.set(Some(env));
                                                        })
                                                    }}
                                                /></label>

                                                <label class="mt-1">{ "TCP_CONNECT" }<input
                                                    type="text" value={env.tcp_connect.clone()}
                                                    oninput={{
                                                        let se=selected_env.clone();
                                                        Callback::from(move |e:InputEvent|{
                                                            let mut env=(*se).clone().unwrap();
                                                            env.tcp_connect=e.target_unchecked_into::<HtmlInputElement>().value();
                                                            se.set(Some(env));
                                                        })
                                                    }}
                                                /></label>

                                                <label class="mt-1">{ "allowed_ips" }<input
                                                    type="text" value={env.allowed_ips.clone()}
                                                    oninput={{
                                                        let se=selected_env.clone();
                                                        Callback::from(move |e:InputEvent|{
                                                            let mut env=(*se).clone().unwrap();
                                                            env.allowed_ips=e.target_unchecked_into::<HtmlInputElement>().value();
                                                            se.set(Some(env));
                                                        })
                                                    }}
                                                /></label>

                                                <label class="mt-1">{ "allowed_domains" }<input
                                                    type="text" value={env.allowed_domains.clone()}
                                                    oninput={{
                                                        let se=selected_env.clone();
                                                        Callback::from(move |e:InputEvent|{
                                                            let mut env=(*se).clone().unwrap();
                                                            env.allowed_domains=e.target_unchecked_into::<HtmlInputElement>().value();
                                                            se.set(Some(env));
                                                        })
                                                    }}
                                                /></label>

                                                <button class="button is-primary mt-2" onclick={on_update_env.clone()}>{ "Enregistrer" }</button>
                                                <button class="button is-danger mt-2 ml-2" onclick={on_delete_env.clone()}>{ "Supprimer" }</button>
                                            </div>
                                        }
                                    } else {
                                        html!{
                                            <div class="mt-3">
                                                <h4>{ "Events" }</h4>
                                                <ul>
                                                    { for events.iter().map(|ev| html!{
                                                        <li>{ format!("{} {} {}", ev.timestamp, ev.operation, ev.result) }</li>
                                                    }) }
                                                </ul>
                                            </div>
                                        }
                                    }
                                }
                            </>
                        }
                    } else {
                        html!{ <p>{ "Sélectionnez une configuration." }</p> }
                    }
                }
                </div>

                /* ----- colonne 3 : création ----- */
                <div class="column" style="border:1px solid #ccc;padding:1rem;margin-left:1rem;">
                    <h3>{ "Nouvelle configuration" }</h3>
                    <small>{ "liée au rôle sélectionné" }</small>

                    <label>{ "app_name" }<input type="text" value={(*f_app).clone()} oninput={bind_input(f_app.clone())} /></label>
                    <label class="mt-1">{ "default_ro" }<input type="text" value={(*f_ro).clone()}  oninput={bind_input(f_ro.clone())} /></label>
                    <label class="mt-1">{ "default_rw" }<input type="text" value={(*f_rw).clone()}  oninput={bind_input(f_rw.clone())} /></label>
                    <label class="mt-1">{ "tcp_bind" }<input type="text" value={(*f_bind).clone()} oninput={bind_input(f_bind.clone())} /></label>
                    <label class="mt-1">{ "tcp_connect" }<input type="text" value={(*f_conn).clone()} oninput={bind_input(f_conn.clone())} /></label>
                    <label class="mt-1">{ "allowed_ips" }<input type="text" value={(*f_ips).clone()} oninput={bind_input(f_ips.clone())} /></label>
                    <label class="mt-1">{ "allowed_domains" }<input type="text" value={(*f_dom).clone()} oninput={bind_input(f_dom.clone())} /></label>

                    <button class="button is-primary mt-2" onclick={on_create_env}>{ "Créer" }</button>
                </div>
            </div>
        </div>
    }
}
