use yew::prelude::*;
use crate::session::use_session;

/* -------------------------------------------------------------------------- */
/*                          composant Dashboard                               */
/* -------------------------------------------------------------------------- */

#[function_component(Dashboard)]
pub fn dashboard() -> Html {
    // session == None tant que /admin/me n’a pas répondu
    let session = use_session();

    html! {
        <>
        {
            match &*session {
                None        => html!(<p>{ "Chargement…" }</p>),
                Some(_sess) => html! {
                    <div>
                        <div style="text-align:center;">
                            <h1>{ "Dashboard" }</h1>
                            <p>{ "Visualisation en temps réel des logs système" }</p>
                        </div>

                        <div style="
                            display:grid;
                            grid-template-columns:repeat(2,1fr);
                            gap:20px;
                            padding:20px;
                            width:80%;
                            margin:0 auto;
                        ">
                            <iframe
                                src="http://localhost/grafana/d-solo/aehxjdg8g1hq8f/supernanny-denied?orgId=1&panelId=5&refresh=5s"
                                style="width:100%;height:300px;border:0;"
                            />
                            <iframe
                                src="http://localhost/grafana/d-solo/aehxjdg8g1hq8f/supernanny-denied?orgId=1&panelId=2&refresh=5s"
                                style="width:100%;height:300px;border:0;"
                            />
                            <iframe
                                src="http://localhost/grafana/d-solo/aehxjdg8g1hq8f/supernanny-denied?orgId=1&panelId=4&refresh=5s"
                                style="width:100%;height:300px;border:0;"
                            />
                            <iframe
                                src="http://localhost/grafana/d-solo/aehxjdg8g1hq8f/supernanny-denied?orgId=1&panelId=3&refresh=5s"
                                style="width:100%;height:300px;border:0;"
                            />
                        </div>
                    </div>
                },
            }
        }
        </>
    }
}
