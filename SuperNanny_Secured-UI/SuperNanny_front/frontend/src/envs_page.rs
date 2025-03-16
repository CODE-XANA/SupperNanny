use yew::prelude::*;
use wasm_bindgen_futures::spawn_local;
use gloo::console::log;
use gloo_net::http::Request;
use web_sys::RequestCredentials;
use crate::utils::get_cookies;
use crate::models::AppPolicy;
use crate::logout::Logout;

#[function_component(EnvsPage)]
pub fn envs_page() -> Html {
    let envs = use_state(|| Vec::<AppPolicy>::new());

    {
        let envs = envs.clone();
        use_effect_with_deps(move |_| {
            spawn_local(async move {
                let cookies = get_cookies().unwrap_or_default();
                // Extraction du cookie csrf_token depuis la chaîne
                let csrf_token = cookies
                    .split("; ")
                    .find(|c| c.starts_with("csrf_token="))
                    .map(|c| c.trim_start_matches("csrf_token=").to_string())
                    .unwrap_or_default();

                let result = Request::get("http://127.0.0.1:8081/envs")
                    .credentials(RequestCredentials::Include)
                    .header("X-CSRF-Token", &csrf_token)
                    .send()
                    .await;

                match result {
                    Ok(resp) if resp.status() == 200 => {
                        match resp.json::<Vec<AppPolicy>>().await {
                            Ok(json) => envs.set(json),
                            Err(err) => log!(format!("Erreur lors de la désérialisation: {:?}", err)),
                        }
                    }
                    Ok(resp) => {
                        log!(format!("Erreur: statut {}", resp.status()));
                    }
                    Err(err) => {
                        log!(format!("Erreur lors de la requête /envs: {:?}", err));
                    }
                }
            });
            || ()
        }, ());
    }

    html! {
        <>
            <header>
                <Logout />
            </header>
            <h2>{ "Configurations" }</h2>
            <ul>
                { for envs.iter().map(|env| html! {
                    <li>
                        { format!("App: {}, RO: {}, RW: {}", env.app_name, env.default_ro, env.default_rw) }
                    </li>
                }) }
            </ul>
        </>
    }
}
