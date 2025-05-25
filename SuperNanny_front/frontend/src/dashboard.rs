use yew::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{WebSocket, MessageEvent, ErrorEvent};
use crate::session::use_session;

/* -------------------------------------------------------------------------- */
/*                          composant Dashboard                               */
/* -------------------------------------------------------------------------- */

#[function_component(Dashboard)]
pub fn dashboard() -> Html {
    // session == None tant que /admin/me n'a pas répondu
    let session = use_session();

    // ---- État pour la dernière alerte reçue --------------------------------
    let alert = use_state(|| Option::<String>::None);
    let alert_clone = alert.clone();

    // ---- WebSocket d'abonnement Nchan --------------------------------------
    use_effect_with((), move |_| {
        // URL du WS Nchan
        let ws = match WebSocket::new("wss://127.0.0.1:8445/alerts-sub") {
            Ok(ws) => ws,
            Err(err) => {
                web_sys::console::error_1(&err);
                return Box::new(|| {}) as Box<dyn FnOnce()>;
            }
        };

        // --- onmessage: mettre à jour l'état 'alert' avec le contenu texte ---
        let onmessage_callback = Closure::<dyn FnMut(MessageEvent)>::wrap(Box::new(move |event: MessageEvent| {
            if let Some(text) = event.data().as_string() {
                alert_clone.set(Some(text));
            }
        }));
        ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
        onmessage_callback.forget();

        // --- onerror: log ----------------------------------------------------
        let onerror_callback = Closure::<dyn FnMut(ErrorEvent)>::wrap(Box::new(|e: ErrorEvent| {
            web_sys::console::error_1(&e);
        }));
        ws.set_onerror(Some(onerror_callback.as_ref().unchecked_ref()));
        onerror_callback.forget();

        // Clean‑up: fermer le WS à l'unmount
        Box::new(move || {
            ws.close().ok();
        }) as Box<dyn FnOnce()>
    });

    // ---- UI principal ------------------------------------------------------
    html! {
        <>
        {
            match &*session {
                None => html!(<p>{ "Chargement…" }</p>),
                Some(_sess) => html! {
                    <div>
                        // ─── Entête ────────────────────────────────────────
                        <div class="text-center">
                            <h1 class="text-3xl font-bold mb-2">{ "Dashboard" }</h1>
                            <p class="text-gray-600 mb-6">{ "Visualisation en temps réel des logs système" }</p>
                        </div>

                        // ─── Grille des panels Grafana ─────────────────────
                        <div style="
                            display:grid;
                            grid-template-columns:repeat(2,1fr);
                            gap:20px;
                            padding:20px;
                            width:80%;
                            margin:0 auto;">
                            // Panels 1‑4
                            <iframe src="https://127.0.0.1:8445/grafana/d-solo/92939631-8517-46f0-a6fc-f22b2cf51028/supernanny-denied?orgId=1&panelId=1&refresh=5s" style="width:100%;height:300px;border:0;"/>
                            <iframe src="https://127.0.0.1:8445/grafana/d-solo/92939631-8517-46f0-a6fc-f22b2cf51028/supernanny-denied?orgId=1&panelId=2&refresh=5s" style="width:100%;height:300px;border:0;"/>
                            <iframe src="https://127.0.0.1:8445/grafana/d-solo/92939631-8517-46f0-a6fc-f22b2cf51028/supernanny-denied?orgId=1&panelId=3&refresh=5s" style="width:100%;height:300px;border:0;"/>
                            <iframe src="https://127.0.0.1:8445/grafana/d-solo/92939631-8517-46f0-a6fc-f22b2cf51028/supernanny-denied?orgId=1&panelId=4&refresh=5s" style="width:100%;height:300px;border:0;"/>
                        </div>
                    </div>
                },
            }
        }
        // ─── Toast de notification d'alerte ─────────────────────────────────
        {
            if let Some(message) = &*alert {
                html! {
                    <div class="alert-notification">
                        <p class="alert-title">{ "Alerte Grafana" }</p>
                        <p class="alert-message">{ message }</p>
                        <button class="alert-close" onclick={
                            let alert = alert.clone();
                            Callback::from(move |_| alert.set(None))
                        }>{ "Fermer" }</button>
                    </div>
                }
            } else {
                html!{}
            }
        }
        </>
    }
}
