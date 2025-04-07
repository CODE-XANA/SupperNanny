use yew::prelude::*;
use wasm_bindgen_futures::spawn_local;
use gloo_net::http::Request;
use web_sys::RequestCredentials;
use gloo_timers::callback::Interval;
use crate::utils::get_cookies;
use log::{error, info};

/// Extraction du CSRF depuis la chaîne de cookies
fn extract_csrf(cookies: &str) -> String {
    cookies
        .split("; ")
        .find(|c| c.starts_with("csrf_token="))
        .map(|c| c.trim_start_matches("csrf_token=").to_string())
        .unwrap_or_default()
}

/// État d'authentification
#[derive(Clone, PartialEq)]
enum AuthStatus {
    Loading,
    Valid,
    Invalid,
}

#[function_component(Dashboard)]
pub fn dashboard() -> Html {
    let auth_status = use_state(|| AuthStatus::Loading);

    // Vérification initiale de l'authentification, lancée une seule fois lors du montage
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

    // Vérification périodique toutes les 10 secondes, lancée une seule fois lors du montage
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
                // Nettoyage : l'intervalle est annulé lors du démontage
                || drop(interval)
            },
            (),
        );
    }

    // Rendu conditionnel en fonction de l'état d'authentification
    match *auth_status {
        AuthStatus::Loading => html! { <p>{ "Chargement..." }</p> },
        AuthStatus::Invalid => html! { <p style="font-weight: bold;">{ "403 : Accès refusé" }</p> },
        AuthStatus::Valid => html! {
            <div>
                <div style="text-align: center;">
                    <h1>{ "Dashboard" }</h1>
                    <p>{ "Visualisation en temps réel des logs du système" }</p>
                </div>
                <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; padding: 20px; width: 80%; margin: 0 auto;">
                    <iframe 
                        src="http://localhost/grafana/d-solo/aehxjdg8g1hq8f/supernanny-denied?orgId=1&panelId=5&refresh=5s" 
                        style="width: 100%; height: 300px; border: 0;">
                    </iframe>
                    <iframe
                        src="http://localhost/grafana/d-solo/aehxjdg8g1hq8f/supernanny-denied?orgId=1&panelId=2&refresh=5s" 
                        style="width: 100%; height: 300px; border: 0;">
                    </iframe>
                    <iframe 
                        src="http://localhost/grafana/d-solo/aehxjdg8g1hq8f/supernanny-denied?orgId=1&panelId=4&refresh=5s" 
                        style="width: 100%; height: 300px; border: 0;">
                    </iframe>
                    <iframe 
                        src="http://localhost/grafana/d-solo/aehxjdg8g1hq8f/supernanny-denied?orgId=1&panelId=3&refresh=5s" 
                        style="width: 100%; height: 300px; border: 0;">
                    </iframe>
                </div>
            </div>
        },
    }
}
