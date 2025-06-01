use yew::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{WebSocket, MessageEvent, ErrorEvent};
use serde::Deserialize;
use gloo_timers::callback::Interval;

use crate::session::use_session;
use crate::api::fetch_json;
use yew::platform::spawn_local;
use gloo_net::http::Method;

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
/*                           Types JSON /logs/security                        */
/* -------------------------------------------------------------------------- */

#[derive(Clone, PartialEq, Deserialize, Debug)]
pub struct LogEntry {
    pub log_id:    i32,
    pub timestamp: String,             // ISO-8601 string from backend
    pub username:  Option<String>,
    pub ip_address: Option<String>,
    pub action:     String,
    pub detail:     Option<String>,
    pub severity:   String,
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

                            // Message déjà fourni par Grafana
                            if let Some(msg) = a.annotations.get("message") {
                                list.push(msg.clone());
                                continue;
                            }

                            // Sinon, on le compose nous-mêmes
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

    // ---- État : security logs et toggle de visibilité ---------------------
    let logs = use_state(|| Vec::<LogEntry>::new());
    let logs_visible = use_state(|| false);

    // ---- Fonction pour charger les logs -----------------------------------
    let load_logs = {
        let logs = logs.clone();
        Callback::from(move |_| {
            let logs = logs.clone();
            spawn_local(async move {
                match fetch_json::<(), Vec<LogEntry>>(Method::GET, "/logs/security", None::<&()>).await {
                    Ok(rows) => logs.set(rows),
                    Err(err) => {
                        web_sys::console::error_1(&format!("Failed to load security logs: {:?}", err).into());
                    }
                }
            });
        })
    };

    // ---- Chargement initial des logs --------------------------------------
    {
        let load_logs = load_logs.clone();
        let session = session.clone();
        use_effect_with((*session).clone(), move |sess| {
            if sess.is_some() {
                // Charge les logs une première fois
                load_logs.emit(());
            }
            || ()
        });
    }

    // ---- Timer pour refresh automatique -----------------------------------
    {
        let load_logs = load_logs.clone();
        let session = session.clone();
        let logs_visible = logs_visible.clone();
        
        use_effect_with(((*session).clone(), *logs_visible), move |(sess, visible)| {
            let cleanup: Box<dyn FnOnce()> = if sess.is_some() && *visible {
                // Démarre un timer qui refresh les logs toutes les 5 secondes quand ils sont visibles
                let interval = Interval::new(5000, move || {
                    load_logs.emit(());
                });
                
                Box::new(move || drop(interval))
            } else {
                Box::new(|| {})
            };
            
            cleanup
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
                        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:20px;
                                    padding:20px;width:80%;margin:0 auto;">
                            <iframe
                                src="https://127.0.0.1:8445/grafana/d-solo/92939631-8517-46f0-a6fc-f22b2cf51028/supernanny-denied?orgId=1&panelId=1&refresh=5s"
                                style="width:100%;height:300px;border:0;"
                            />
                            <iframe
                                src="https://127.0.0.1:8445/grafana/d-solo/92939631-8517-46f0-a6fc-f22b2cf51028/supernanny-denied?orgId=1&panelId=2&refresh=5s"
                                style="width:100%;height:300px;border:0;"
                            />
                            <iframe
                                src="https://127.0.0.1:8445/grafana/d-solo/92939631-8517-46f0-a6fc-f22b2cf51028/supernanny-denied?orgId=1&panelId=3&refresh=5s"
                                style="width:100%;height:300px;border:0;"
                            />
                            <iframe
                                src="https://127.0.0.1:8445/grafana/d-solo/92939631-8517-46f0-a6fc-f22b2cf51028/supernanny-denied?orgId=1&panelId=4&refresh=5s"
                                style="width:100%;height:300px;border:0;"
                            />
                        </div>

                        // ─── Boutons pour security logs ─────────────────────────────
                        <div style="width:80%; margin:20px auto; text-align:center; display:flex; gap:10px; justify-content:center;">
                            <button
                                onclick={
                                    let vis = logs_visible.clone();
                                    Callback::from(move |_| vis.set(!*vis))
                                }
                                style="
                                    background-color:#3f51b5;color:#fff;border:none;border-radius:4px;
                                    padding:0.75rem 1.25rem;font-size:1rem;cursor:pointer;
                                "
                            >
                                { if *logs_visible { "Hide security logs" } else { "Show security logs" } }
                            </button>
                            
                            // Bouton refresh manuel
                            if *logs_visible {
                                <button
                                    onclick={{
                                        let load_logs = load_logs.clone();
                                        Callback::from(move |_| load_logs.emit(()))
                                    }}
                                    style="
                                        background-color:#4caf50;color:#fff;border:none;border-radius:4px;
                                        padding:0.75rem 1.25rem;font-size:1rem;cursor:pointer;
                                    "
                                >
                                    { "Refresh now" }
                                </button>
                            }
                        </div>

                        // ─── Bloc déroulable pour security logs ─────────────────────────
                        if *logs_visible {
                            <div style="width:80%; margin:0 auto; max-height:400px; overflow:auto;
                                         border:1px solid #ddd; border-radius:4px; padding:1rem;">
                                <div style="margin-bottom:10px; font-size:0.9em; color:#666;">
                                    { format!("📊 {} logs • Auto-refresh: 5s", (*logs).len()) }
                                </div>
                                <table style="width:100%; border-collapse:collapse;">
                                    <thead>
                                        <tr style="background:#f5f5f5;">
                                            <th style="border-bottom:1px solid #ccc; padding:8px;">{ "ID" }</th>
                                            <th style="border-bottom:1px solid #ccc; padding:8px;">{ "Timestamp" }</th>
                                            <th style="border-bottom:1px solid #ccc; padding:8px;">{ "User" }</th>
                                            <th style="border-bottom:1px solid #ccc; padding:8px;">{ "IP" }</th>
                                            <th style="border-bottom:1px solid #ccc; padding:8px;">{ "Action" }</th>
                                            <th style="border-bottom:1px solid #ccc; padding:8px;">{ "Detail" }</th>
                                            <th style="border-bottom:1px solid #ccc; padding:8px;">{ "Severity" }</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        { for (*logs).iter().map(|entry| {
                                            // Coloration basée sur la sévérité
                                            let severity_color = match entry.severity.as_str() {
                                                "HIGH" => "#ffebee",
                                                "MEDIUM" => "#fff3e0", 
                                                "LOW" => "#e8f5e8",
                                                _ => "#ffffff"
                                            };
                                            
                                            html! {
                                                <tr style={format!("background-color: {};", severity_color)}>
                                                    <td style="border-bottom:1px solid #eee; padding:6px;">{ entry.log_id }</td>
                                                    <td style="border-bottom:1px solid #eee; padding:6px;">
                                                        { &entry.timestamp }
                                                    </td>
                                                    <td style="border-bottom:1px solid #eee; padding:6px;">
                                                        { entry.username.as_deref().unwrap_or("-") }
                                                    </td>
                                                    <td style="border-bottom:1px solid #eee; padding:6px;">
                                                        { entry.ip_address.as_deref().unwrap_or("-") }
                                                    </td>
                                                    <td style="border-bottom:1px solid #eee; padding:6px;">
                                                        { &entry.action }
                                                    </td>
                                                    <td style="border-bottom:1px solid #eee; padding:6px;">
                                                        { entry.detail.as_deref().unwrap_or("-") }
                                                    </td>
                                                    <td style="border-bottom:1px solid #eee; padding:6px;">
                                                        <span style={format!("
                                                            padding: 2px 6px;
                                                            border-radius: 3px;
                                                            font-size: 0.8em;
                                                            font-weight: bold;
                                                            color: {};
                                                        ", match entry.severity.as_str() {
                                                            "HIGH" => "#d32f2f",
                                                            "MEDIUM" => "#f57c00",
                                                            "LOW" => "#388e3c",
                                                            _ => "#666"
                                                        })}>
                                                            { &entry.severity }
                                                        </span>
                                                    </td>
                                                </tr>
                                            }
                                        }) }
                                    </tbody>
                                </table>
                            </div>
                        }
                    </div>
                }
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