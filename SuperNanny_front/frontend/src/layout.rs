use yew::prelude::*;
use yew_router::prelude::*;
use wasm_bindgen_futures::spawn_local;
use gloo_net::http::Request;
use web_sys::RequestCredentials;

use crate::{Route, utils::get_cookies};
use crate::logout;          /* le composant Logout existe toujours */

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

#[derive(Properties, PartialEq)]
pub struct MainLayoutProps {
    #[prop_or_default]
    pub children: Children,
}

#[function_component(MainLayout)]
pub fn main_layout(props: &MainLayoutProps) -> Html {
    let auth_status = use_state(|| AuthStatus::Loading);

    /* ------------ vérification auth (au montage) ------------------------- */
    {
        let auth_status = auth_status.clone();
        use_effect_with_deps(
            move |_| {
                spawn_local(async move {
                    let cookies = get_cookies().unwrap_or_default();
                    let csrf    = extract_csrf(&cookies);

                    let resp = Request::get("https://127.0.0.1:8443/admin/me")
                        .header("X-CSRF-Token", &csrf)
                        .credentials(RequestCredentials::Include)
                        .send()
                        .await;

                    match resp {
                        Ok(r) if r.status() == 200 => auth_status.set(AuthStatus::Valid),
                        _ => auth_status.set(AuthStatus::Invalid),
                    }
                });
                || ()
            },
            (),
        );
    }

    /* ---------------- rendu conditionnel ------------------------------- */
    match *auth_status {
        AuthStatus::Loading => html!(<p>{"Chargement…"}</p>),
        AuthStatus::Invalid => html!(<p style="font-weight:bold;">{"403 : accès refusé"}</p>),
        AuthStatus::Valid => html! {
            <>
                <header class="header">
                    <div class="header-left">
                        <img src="/SuperNanny.png" alt="Logo SuperNanny" class="header-logo" />
                    </div>
                    <div class="header-title">{"SuperNanny"}</div>
                    <div class="header-logout">
                        <logout::Logout />
                    </div>
                </header>

                <nav class="nav">
                    <ul class="nav-list">
                        <li class="nav-item"><Link<Route> to={Route::Dashboard}>{"Dashboard"}</Link<Route>></li>
                        <li class="nav-item"><Link<Route> to={Route::Configurations}>{"Configurations"}</Link<Route>></li>
                        <li class="nav-item"><Link<Route> to={Route::ManageUsers}>{"Gestion utilisateurs"}</Link<Route>></li>
                        <li class="nav-item"><Link<Route> to={Route::ManageRoles}>{"Gestion rôles"}</Link<Route>></li>
                    </ul>
                </nav>

                <main class="main-content">
                    { for props.children.iter() }
                </main>
            </>
        },
    }
}
