use yew::prelude::*;
use yew_router::prelude::*;
use wasm_bindgen_futures::spawn_local;
use gloo_net::http::Request;
use web_sys::RequestCredentials;
use crate::logout;
use crate::Route;
use crate::utils::get_cookies;
use log::{error, info};

// Fonction helper pour extraire le CSRF depuis les cookies
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
    pub children: Children, // Contenu spécifique de chaque page
}

#[function_component(MainLayout)]
pub fn main_layout(props: &MainLayoutProps) -> Html {
    let auth_status = use_state(|| AuthStatus::Loading);

    {
        let auth_status = auth_status.clone();
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
                    if let Ok(r) = resp {
                        if r.status() == 200 {
                            auth_status.set(AuthStatus::Valid);
                        } else {
                            auth_status.set(AuthStatus::Invalid);
                        }
                    } else {
                        auth_status.set(AuthStatus::Invalid);
                    }
                });
                || ()
            },
            (), // pas de dépendances particulières
        );
    }

    // Affichage conditionnel selon l'état d'authentification
    match *auth_status {
        AuthStatus::Loading => html! { <p>{ "Chargement..." }</p> },
        AuthStatus::Invalid => html! { <p style="font-weight: bold;">{ "403 : Accès refusé" }</p> },
        AuthStatus::Valid => html! {
            <>
                <header class="header">
                    <div class="header-left">
                        <img src="/SuperNanny.png" alt="Logo SuperNanny" class="header-logo" />
                    </div>
                    <div class="header-title">{ "SuperNanny" }</div>
                    <div class="header-logout">
                        <logout::Logout />
                    </div>
                </header>

                <nav class="nav">
                    <ul class="nav-list">
                        <li class="nav-item">
                            <Link<Route> to={Route::Dashboard}>{ "Dashboard" }</Link<Route>>
                        </li>
                        <li class="nav-item">
                            <Link<Route> to={Route::Configurations}>{ "Configurations" }</Link<Route>>
                        </li>
                        <li class="nav-item">
                            <Link<Route> to={Route::ManageUsers}>{ "Gestion des utilisateurs" }</Link<Route>>
                        </li>
                        <li class="nav-item">
                            <Link<Route> to={Route::ManageRoles}>{ "Gestion des rôles" }</Link<Route>>
                        </li>
                    </ul>
                </nav>

                <main class="main-content">
                    { for props.children.iter() }
                </main>
            </>
        },
    }
}
