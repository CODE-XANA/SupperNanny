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
pub struct User {
    pub user_id: i32,
    pub username: String,
    pub password_hash: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Role {
    pub role_id: i32,
    pub role_name: String,
}

/* -------------------------------------------------------------------------- */
/*                      états partagés & helpers front                        */
/* -------------------------------------------------------------------------- */

/// Récupère le libellé du rôle à partir des maps déjà chargées.
fn role_name_of(user_id: i32, user_roles: &HashMap<i32, i32>, roles: &[Role]) -> String {
    match user_roles.get(&user_id).and_then(|rid| roles.iter().find(|r| r.role_id == *rid)) {
        Some(r) => r.role_name.clone(),
        None => "No role".into(),
    }
}

/* -------------------------------------------------------------------------- */
/*                          chargement des données                            */
/* -------------------------------------------------------------------------- */

async fn reload_all_data(
    roles_state: UseStateHandle<Vec<Role>>,
    users_state: UseStateHandle<Vec<User>>,
    user_roles_state: UseStateHandle<HashMap<i32, i32>>,
) {
    /* 1) catalogue rôles */
    match fetch_json::<(), Vec<Role>>(Method::GET, "/users/roles", None::<&()>).await {
        Ok(r) => roles_state.set(r),
        Err(e) => error!("roles: {e:?}"),
    }

    /* 2) liste utilisateurs */
    match fetch_json::<(), Vec<User>>(Method::GET, "/users", None::<&()>).await {
        Ok(u) => {
            users_state.set(u.clone());

            /* 3) pour chaque user → rôle principal */
            let futures = u.into_iter().map(|u| async move {
                let path = format!("/users/{}/roles", u.user_id);
                let rid = fetch_json::<(), Vec<Role>>(Method::GET, &path, None::<&()>)
                    .await
                    .ok()
                    .and_then(|v| v.first().map(|r| r.role_id))
                    .unwrap_or(0);
                (u.user_id, rid)
            });

            let results = futures::future::join_all(futures).await;
            user_roles_state.set(results.into_iter().collect());
        }
        Err(e) => error!("users: {e:?}"),
    }
}

/* -------------------------------------------------------------------------- */
/*                             composant principal                            */
/* -------------------------------------------------------------------------- */

#[function_component(ManageUsers)]
pub fn manage_users() -> Html {
    /* ---------------- states ---------------- */
    let roles        = use_state(Vec::<Role>::new);
    let users        = use_state(Vec::<User>::new);
    let user_roles   = use_state(HashMap::<i32, i32>::new);

    /* form states */
    let new_username = use_state(|| "".to_string());
    let new_password = use_state(|| "".to_string());
    let new_role     = use_state(|| -1);          // id rôle choisi
    let select_ref   = use_node_ref();

    /* -------------- chargement initial -------------- */
    {
        let r = roles.clone();
        let u = users.clone();
        let ur = user_roles.clone();
        use_effect_with((), move |_| {
            spawn_local(async move { reload_all_data(r, u, ur).await });
            || ()
        });
    }

    /* -------------- forcer le <select> sur new_role -------------- */
    {
        let select_ref = select_ref.clone();
        let dep = (*new_role).to_string();
        use_effect_with(dep.clone(), move |_| {
            if let Some(sel) = select_ref.cast::<HtmlSelectElement>() {
                sel.set_value(&dep);
            }
            || ()
        });
    }

    /* -------------- handlers -------------- */

    // changement de rôle dans le form
    let on_change_role = {
        let new_role = new_role.clone();
        Callback::from(move |e: Event| {
            let select: HtmlSelectElement = e.target_unchecked_into();
            new_role.set(select.value().parse().unwrap_or(-1));
        })
    };

    // création utilisateur + rôle
    let on_create_user = {
        let roles   = roles.clone();
        let users   = users.clone();
        let uroles  = user_roles.clone();

        let uname   = new_username.clone();
        let pwd     = new_password.clone();
        let role_id = new_role.clone();

        Callback::from(move |_| {
            let username = (*uname).clone();
            let password = (*pwd).clone();
            let role     = *role_id;

            if username.is_empty() || password.is_empty() || role == -1 {
                error!("Tous les champs sont obligatoires.");
                return;
            }

            let roles   = roles.clone();
            let users   = users.clone();
            let uroles  = uroles.clone();
            let uname   = uname.clone();
            let pwd     = pwd.clone();
            let role_id = role_id.clone();

            spawn_local(async move {
                let body = serde_json::json!({
                    "username": username,
                    "password": password,
                    "role_id":  role,
                });

                let res = fetch_json::<_, serde_json::Value>(
                    Method::POST,
                    "/users/create_with_role",
                    Some(&body),
                )
                .await;

                match res {
                    Ok(_) => {
                        info!("Utilisateur créé");
                        reload_all_data(roles, users, uroles).await;
                        uname.set("".into());
                        pwd.set("".into());
                        role_id.set(-1);
                    }
                    Err(e) => error!("create: {e:?}"),
                }
            });
        })
    };

    // suppression utilisateur
    let on_delete_user = {
        let roles   = roles.clone();
        let users   = users.clone();
        let uroles  = user_roles.clone();

        Callback::from(move |uid: i32| {
            let roles   = roles.clone();
            let users   = users.clone();
            let uroles  = uroles.clone();

            spawn_local(async move {
                if web_sys::window()
                    .unwrap()
                    .confirm_with_message("Confirmer la suppression ?")
                    .unwrap_or(false)
                {
                    let path = format!("/users/{uid}");
                    match fetch_json::<(), ()>(Method::DELETE, &path, None::<&()>).await {
                        Ok(_) => {
                            info!("Utilisateur supprimé");
                            reload_all_data(roles, users, uroles).await;
                        }
                        Err(e) => error!("delete: {e:?}"),
                    }
                }
            });
        })
    };

    /* ---------------------- rendu ---------------------- */
    html! {
        <div class="container" style="margin-top:2rem;">
            <div class="columns" style="gap: 2rem;">
                /* ------------ colonne gauche : users ----------- */
                <div class="column">
                    <h2 class="title is-4 has-text-centered">{ "Utilisateurs" }</h2>
                    <ul>
                        { for (*users).iter().map(|u| {
                            let role_name = role_name_of(u.user_id, &user_roles, &roles);
                            html! {
                                <li class="box" style="margin-bottom:0.5rem;">
                                    <b>{ &u.username }</b>{ " → " }<i>{ role_name }</i>
                                    <button
                                        class="button is-danger is-small"
                                        style="margin-left:1rem;"
                                        onclick={{
                                            let on_del = on_delete_user.clone();
                                            let id = u.user_id;
                                            Callback::from(move |_| on_del.emit(id))
                                        }}
                                    >
                                        { "Supprimer" }
                                    </button>
                                </li>
                            }
                        }) }
                    </ul>
                </div>

                /* ------------ colonne droite : création -------- */
                <div class="column" style="max-width:450px;margin:0 auto;">
                    <h2 class="title is-4 has-text-centered">{ "Créer un utilisateur" }</h2>
                    <div class="box">
                        <label>{ "Nom d'utilisateur" }</label>
                        <input
                            type="text"
                            value={(*new_username).clone()}
                            oninput={{
                                let st = new_username.clone();
                                Callback::from(move |e: InputEvent| {
                                    let v = e.target_unchecked_into::<HtmlInputElement>().value();
                                    st.set(v);
                                })
                            }}
                        />

                        <label class="mt-2">{ "Mot de passe" }</label>
                        <input
                            type="password"
                            value={(*new_password).clone()}
                            oninput={{
                                let st = new_password.clone();
                                Callback::from(move |e: InputEvent| {
                                    let v = e.target_unchecked_into::<HtmlInputElement>().value();
                                    st.set(v);
                                })
                            }}
                        />

                        <label class="mt-2">{ "Rôle" }</label>
                        <select ref={select_ref.clone()} onchange={on_change_role}>
                            <option value="-1">{ "Sélectionner…" }</option>
                            { for (*roles).iter().map(|r| html! {
                                <option value={r.role_id.to_string()}>{ &r.role_name }</option>
                            })}
                        </select>

                        <button class="button is-primary mt-3" onclick={on_create_user}>
                            { "Créer l'utilisateur" }
                        </button>
                    </div>
                </div>
            </div>
        </div>
    }
}
