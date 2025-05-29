use yew::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{WebSocket, MessageEvent, ErrorEvent};
use serde::Deserialize;

use crate::session::use_session;

/* -------------------------------------------------------------------------- */
/*                              Types JSON Grafana                            */
/* -------------------------------------------------------------------------- */

#[derive(Deserialize)]
struct Webhook {
    alerts: Vec<Alert>,
}

#[derive(Deserialize)]
struct Alert {
    status: String,
    labels: std::collections::HashMap<String, String>,
    annotations: std::collections::HashMap<String, String>,
    #[serde(default)]
    values: std::collections::HashMap<String, i64>,
}


/* -------------------------------------------------------------------------- */
/*                              Composant Dashboard                           */
/* -------------------------------------------------------------------------- */

#[function_component(Dashboard)]
pub fn dashboard() -> Html {
    // session == None tant que /admin/me n'a pas répondu
    let session = use_session();

    // ---- État : pile de messages d'alerte ---------------------------------
    let alerts = use_state(|| Vec::<String>::new());
    let alerts_ws = alerts.clone();

    // ---- WebSocket d'abonnement Nchan -------------------------------------
    {
        let alerts_cl = alerts.clone();
        use_effect_with((), move |_| {
            let ws = WebSocket::new("wss://127.0.0.1:8445/alerts-sub").expect("ws");

            // onmessage
            let on_msg = Closure::<dyn FnMut(MessageEvent)>::wrap(Box::new(move |e: MessageEvent| {
                if let Some(txt) = e.data().as_string() {
                    if let Ok(webhook) = serde_json::from_str::<Webhook>(&txt) {
                        let mut list = (*alerts_cl).clone();

                        for a in webhook.alerts {
                            if a.status != "firing" { continue; }
                            if a.labels.get("alertname") == Some(&"DatasourceNoData".into()) { continue; }

                            // 1️⃣ Message déjà fourni par Grafana
                            if let Some(msg) = a.annotations.get("message") {
                                list.push(msg.clone());
                                continue;
                            }

                            // 2️⃣ Sinon, on le compose nous-mêmes
                            let host = a.labels.get("hostname").cloned().unwrap_or_else(|| "?".into());
                            let count = a.values.get("A").cloned().unwrap_or(0);
                            list.push(format!("{host} a eu {count} denied dans les 10 dernières minutes."));
                        }

                        if !list.is_empty() { alerts_cl.set(list); }
                    }
                }
            }));

            ws.set_onmessage(Some(on_msg.as_ref().unchecked_ref()));
            on_msg.forget();

            // onerror
            let on_err = Closure::<dyn FnMut(ErrorEvent)>::wrap(Box::new(|e: ErrorEvent| {
                web_sys::console::error_1(&e);
            }));
            ws.set_onerror(Some(on_err.as_ref().unchecked_ref()));
            on_err.forget();

            // cleanup
            move || { ws.close().ok(); }
        });
    }

    /* ------------------------------ Rendu UI ------------------------------ */
    html! {
        <>
        {
            match &*session {
                None => html!(<p>{ "Chargement…" }</p>),
                Some(_sess) => html! {
                    <div>
                        // ─── Entête ──────────────────────────────────────
                        <div class="text-center">
                            <h1 class="text-3xl font-bold mb-2">{ "Dashboard" }</h1>
                            <p class="text-gray-600 mb-6">{ "Visualisation en temps réel des logs système" }</p>
                        </div>
                        // ─── Grille des panels Grafana ───────────────────
                        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:20px;padding:20px;width:80%;margin:0 auto;">
                            <iframe src="https://127.0.0.1:8445/grafana/d-solo/92939631-8517-46f0-a6fc-f22b2cf51028/supernanny-denied?orgId=1&panelId=1&refresh=5s" style="width:100%;height:300px;border:0;"/>
                            <iframe src="https://127.0.0.1:8445/grafana/d-solo/92939631-8517-46f0-a6fc-f22b2cf51028/supernanny-denied?orgId=1&panelId=2&refresh=5s" style="width:100%;height:300px;border:0;"/>
                            <iframe src="https://127.0.0.1:8445/grafana/d-solo/92939631-8517-46f0-a6fc-f22b2cf51028/supernanny-denied?orgId=1&panelId=3&refresh=5s" style="width:100%;height:300px;border:0;"/>
                            <iframe src="https://127.0.0.1:8445/grafana/d-solo/92939631-8517-46f0-a6fc-f22b2cf51028/supernanny-denied?orgId=1&panelId=4&refresh=5s" style="width:100%;height:300px;border:0;"/>
                        </div>
                    </div>
                },
            }
        }
        // ─── Toasts --------------------------------------------------------
        {
            alerts.iter().enumerate().map(|(idx, msg)| {
                let top_position = 90 + idx * 140;
                html! {
                    <div key={idx} class="alert-notification" style={format!("top: {}px;", top_position)}>
                        <p class="alert-title">{ "Alerte Grafana" }</p>
                        <p class="alert-message">{ msg }</p>
                        <button class="alert-close" onclick={{
                            let alerts = alerts_ws.clone();
                            let msg = msg.clone();
                            Callback::from(move |_| {
                                let mut v = (*alerts).clone();
                                v.retain(|m| m != &msg);
                                alerts.set(v);
                            })
                        }}>{ "Fermer" }</button>
                    </div>
                }
            }).collect::<Html>()
        }
        </>
    }
}
