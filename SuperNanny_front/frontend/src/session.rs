use std::collections::HashSet;
use yew::prelude::*;
use yew::platform::spawn_local;
use gloo_net::http::Method;
use serde::Deserialize;

use crate::api::fetch_json;

/* ---------------- structure session ---------------- */
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Session {
    pub username: String,
    pub perms:    HashSet<String>,
}

/* ---------------- hook pratique -------------------- */
#[hook]
pub fn use_session() -> UseStateHandle<Option<Session>> {
    use_context::<UseStateHandle<Option<Session>>>()
        .expect("SessionProvider manquant")
}

/* -------------- props du provider ----------------- */
#[derive(Properties, PartialEq)]
pub struct SessionProviderProps {
    #[prop_or_default]
    pub children: Children,
}

/* -------------- provider global ------------------- */
#[function_component(SessionProvider)]
pub fn session_provider(props: &SessionProviderProps) -> Html {
    let session = use_state(|| None);

    {
        let session = session.clone();
        use_effect_with(                 // deps d'abord
            (),                          // aucune dépendance
            move |_| {                   // closure reçoit ()
                spawn_local(async move {
                    let resp = fetch_json::<(), Session>(Method::GET, "/admin/me", None::<&()>).await;
                    session.set(resp.ok());
                });
                || ()
            },
        );
    }

    html! {
        <ContextProvider<UseStateHandle<Option<Session>>> context={session}>
            { for props.children.iter() }
        </ContextProvider<UseStateHandle<Option<Session>>>>
    }
}
