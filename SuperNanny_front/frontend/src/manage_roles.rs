use gloo_net::http::Method;
use serde::{Deserialize, Serialize};
use yew::platform::spawn_local;
use yew::prelude::*;
use web_sys::{HtmlInputElement, InputEvent};

use crate::api::fetch_json;
use crate::session::use_session;

/* -------------------------------------------------------------------------- */
/*                               structures                                   */
/* -------------------------------------------------------------------------- */

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
struct Role {
    role_id: i32,
    role_name: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
struct Permission {
    permission_id: i32,
    permission_name: String,
}

fn all_permissions() -> Vec<Permission> {
    vec![
        Permission { permission_id: 1, permission_name: "manage_policies".into() },
        Permission { permission_id: 2, permission_name: "view_events".into() },
        Permission { permission_id: 3, permission_name: "execute_apps".into() },
        Permission { permission_id: 4, permission_name: "view_policies".into() },
    ]
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Default)]
struct DefaultPolicyData {
    default_ro: String,
    default_rw: String,
    tcp_bind: String,
    tcp_connect: String,
    allowed_ips: String,
    allowed_domains: String,
}

/* -------------------------------------------------------------------------- */
/*                         composant ManageRoles                              */
/* -------------------------------------------------------------------------- */

#[function_component(ManageRoles)]
pub fn manage_roles() -> Html {
    /* -------- session -------- */
    let _session = use_session();
    if _session.is_none() {
        return html!(<p>{ "Chargement…" }</p>);
    }

    /* -------- state -------- */
    let roles          = use_state(Vec::<Role>::new);
    let selected_role  = use_state(|| None::<Role>);
    let role_perms     = use_state(Vec::<Permission>::new);
    let dp_state       = use_state(DefaultPolicyData::default);

    /* form création */
    let new_role_name  = use_state(String::new);
    let new_dp         = use_state(DefaultPolicyData::default);

    /* ------------------------------------------------------------------ */
    /* 1) charge rôles au montage                                         */
    /* ------------------------------------------------------------------ */
    {
        let roles = roles.clone();
        use_effect_with((), move |_| {
            spawn_local(async move {
                if let Ok(v) = fetch_json::<(), Vec<Role>>(Method::GET, "/roles", None::<&()>).await {
                    roles.set(v);
                }
            });
            || ()
        });
    }

    /* ------------------------------------------------------------------ */
    /* 2) lorsque rôle sélectionné → charge permissions + default_policy   */
    /* ------------------------------------------------------------------ */
    {
        let perms = role_perms.clone();
        let dp    = dp_state.clone();
        use_effect_with(selected_role.clone(), move |sel| {
            if let Some(r) = &**sel {
                let rid = r.role_id;

                // permissions
                let p_handle = perms.clone();
                spawn_local(async move {
                    let path = format!("/roles/{rid}/permissions");
                    if let Ok(v) = fetch_json::<(), Vec<Permission>>(Method::GET, &path, None::<&()>).await {
                        p_handle.set(v);
                    }
                });

                // default policy
                let dp_handle = dp.clone();
                spawn_local(async move {
                    let path = format!("/roles/{rid}/default_policy");
                    match fetch_json::<(), DefaultPolicyData>(Method::GET, &path, None::<&()>).await {
                        Ok(d) => dp_handle.set(d),
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
    /* 3) helpers                                                         */
    /* ------------------------------------------------------------------ */

    // sélection
    let on_select_role = {
        let sel = selected_role.clone();
        Callback::from(move |r: Role| sel.set(Some(r)))
    };

    // suppression
    let on_delete_role = {
        let roles = roles.clone();
        let sel   = selected_role.clone();
        Callback::from(move |_| {
            if let Some(r) = &*sel {
                if !web_sys::window().unwrap().confirm_with_message("Supprimer ce rôle ?").unwrap_or(false) { return; }
                let rid = r.role_id;
                let roles2 = roles.clone();
                let sel2   = sel.clone();
                spawn_local(async move {
                    if fetch_json::<(), ()>(Method::DELETE, &format!("/roles/{rid}"), None::<&()>).await.is_ok() {
                        if let Ok(v) = fetch_json::<(), Vec<Role>>(Method::GET, "/roles", None::<&()>).await {
                            roles2.set(v);
                            sel2.set(None);
                        }
                    }
                });
            }
        })
    };

    // toggle permission
    let on_toggle_perm = {
        let sel   = selected_role.clone();
        let perms = role_perms.clone();
        Callback::from(move |perm: Permission| {
            if let Some(r) = &*sel {
                let rid = r.role_id;
                let pid = perm.permission_id;
                let perms2 = perms.clone();
                spawn_local(async move {
                    let already = perms2.iter().any(|p| p.permission_id == pid);
                    let res = if already {
                        fetch_json::<(), ()>(Method::DELETE, &format!("/roles/{rid}/permissions/{pid}"), None::<&()>).await
                    } else {
                        let body = serde_json::json!({ "permission_id": pid });
                        fetch_json::<_, ()>(Method::POST, &format!("/roles/{rid}/permissions"), Some(&body)).await
                    };
                    if res.is_ok() {
                        if let Ok(v) = fetch_json::<(), Vec<Permission>>(Method::GET, &format!("/roles/{rid}/permissions"), None::<&()>).await {
                            perms2.set(v);
                        }
                    }
                });
            }
        })
    };

    // mise à jour default_policy
    let on_update_dp = {
        let sel = selected_role.clone();
        let dp  = dp_state.clone();
        Callback::from(move |_| {
            if let Some(r) = &*sel {
                let rid  = r.role_id;
                let body = (*dp).clone();
                spawn_local(async move {
                    let _ = fetch_json::<_, ()>(Method::PUT, &format!("/roles/{rid}/default_policy"), Some(&body)).await;
                });
            }
        })
    };

    // création rôle + dp
    let on_create_role = {
        let roles = roles.clone();
        let n_name = new_role_name.clone();
        let ndp    = new_dp.clone();
        Callback::from(move |_| {
            let name = n_name.trim();
            if name.is_empty() { return; }
            let body = serde_json::json!({
                "role_name":      name,
                "default_ro":     ndp.default_ro,
                "default_rw":     ndp.default_rw,
                "tcp_bind":       ndp.tcp_bind,
                "tcp_connect":    ndp.tcp_connect,
                "allowed_ips":    ndp.allowed_ips,
                "allowed_domains":ndp.allowed_domains,
            });
            let roles2 = roles.clone();
            let n_name2 = n_name.clone();
            spawn_local(async move {
                if fetch_json::<_, ()>(Method::POST, "/roles", Some(&body)).await.is_ok() {
                    if let Ok(v) = fetch_json::<(), Vec<Role>>(Method::GET, "/roles", None::<&()>).await {
                        roles2.set(v);
                        n_name2.set(String::new());
                    }
                }
            });
        })
    };

    /* binding helpers --------------------------------------------------- */

    let bind_string = |st: UseStateHandle<String>| {
        Callback::from(move |e: InputEvent| {
            st.set(e.target_unchecked_into::<HtmlInputElement>().value());
        })
    };

    let bind_dp_field = |field: &'static str, h: UseStateHandle<DefaultPolicyData>| {
        Callback::from(move |e: InputEvent| {
            let mut dp = (*h).clone();
            let v = e.target_unchecked_into::<HtmlInputElement>().value();
            match field {
                "ro"  => dp.default_ro       = v,
                "rw"  => dp.default_rw       = v,
                "bind"=> dp.tcp_bind         = v,
                "conn"=> dp.tcp_connect      = v,
                "ips" => dp.allowed_ips      = v,
                "dom" => dp.allowed_domains  = v,
                _ => {}
            };
            h.set(dp);
        })
    };

    /* ------------------------------------------------------------------ */
    /* UI                                                                 */
    /* ------------------------------------------------------------------ */
    html! {
        <div class="container">
            <div class="columns">
                /* ---------- rôles ---------- */
                <div class="column" style="border:1px solid #ccc;padding:1rem;">
                    <h3>{ "Rôles" }</h3>
                    <ul>
                        { for roles.iter().map(|r|{
                            let sel_cb = on_select_role.clone();
                            let me = r.clone();
                            let active = selected_role.as_ref().map(|x| x.role_id)==Some(r.role_id);
                            html!{
                                <li style="cursor:pointer;margin-bottom:0.3rem;"
                                    class={ if active { "selected-role" } else { "" } }
                                    onclick={Callback::from(move |_| sel_cb.emit(me.clone()))}
                                >
                                    { &r.role_name }
                                </li>
                            }
                        })}
                    </ul>
                </div>

                /* ---------- détails ---------- */
                <div class="column" style="border:1px solid #ccc;padding:1rem;margin-left:1rem;">
                {
                    if let Some(r) = &*selected_role {
                        html!{
                            <>
                                <h3>{ format!("Rôle : {}", r.role_name) }</h3>
                                <button class="button is-danger is-small" onclick={on_delete_role.clone()}>{ "Supprimer" }</button>

                                <h4 class="mt-3">{ "Permissions" }</h4>
                                <ul>
                                { for all_permissions().into_iter().map(|perm| {
                                    let togg        = on_toggle_perm.clone();
                                    let assigned    = role_perms.iter().any(|x| x.permission_id == perm.permission_id);

                                    // deux copies distinctes :
                                    let label_view  = perm.permission_name.clone();
                                    let label_cb    = perm.permission_name;
                                    let pid         = perm.permission_id;

                                    html! {
                                        <li
                                            style="cursor:pointer;"
                                            class={ if assigned { "assigned-permission" } else { "unassigned-permission" } }
                                            onclick={Callback::from(move |_| {
                                                togg.emit(Permission {
                                                    permission_id: pid,
                                                    permission_name: label_cb.clone(),
                                                })
                                            })}
                                        >
                                            { label_view }
                                        </li>
                                    }
                                })}
                                </ul>
                                <h4 class="mt-3">{ "Default policy" }</h4>
                                <div class="box">
                                    <label>{"default_ro"}<input type="text" value={dp_state.default_ro.clone()} oninput={bind_dp_field("ro",dp_state.clone())}/></label>
                                    <label class="mt-1">{"default_rw"}<input type="text" value={dp_state.default_rw.clone()} oninput={bind_dp_field("rw",dp_state.clone())}/></label>
                                    <label class="mt-1">{"tcp_bind"}  <input type="text" value={dp_state.tcp_bind.clone()}   oninput={bind_dp_field("bind",dp_state.clone())}/></label>
                                    <label class="mt-1">{"tcp_connect"}<input type="text" value={dp_state.tcp_connect.clone()} oninput={bind_dp_field("conn",dp_state.clone())}/></label>
                                    <label class="mt-1">{"allowed_ips"}<input type="text" value={dp_state.allowed_ips.clone()} oninput={bind_dp_field("ips",dp_state.clone())}/></label>
                                    <label class="mt-1">{"allowed_domains"}<input type="text" value={dp_state.allowed_domains.clone()} oninput={bind_dp_field("dom",dp_state.clone())}/></label>
                                    <button class="button is-primary mt-2" onclick={on_update_dp}>{ "Enregistrer" }</button>
                                </div>
                            </>
                        }
                    } else {
                        html!(<p>{ "Sélectionnez un rôle." }</p>)
                    }
                }
                </div>

                /* ---------- création ---------- */
                <div class="column" style="border:1px solid #ccc;padding:1rem;margin-left:1rem;">
                    <h3>{ "Nouveau rôle" }</h3>
                    <label>{ "Nom" }<input type="text" value={(*new_role_name).clone()} oninput={bind_string(new_role_name.clone())}/></label>
                    <button class="button is-primary mt-2" onclick={on_create_role}>{ "Créer" }</button>
                </div>
            </div>
        </div>
    }
}
