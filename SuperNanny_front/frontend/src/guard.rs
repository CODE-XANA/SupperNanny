use yew::prelude::*;
use crate::session::use_session;

#[derive(Properties, PartialEq)]
pub struct GuardProps {
    pub need: &'static str,
    #[prop_or_default]
    pub children: Children,
}

#[function_component(Guard)]
pub fn guard(props: &GuardProps) -> Html {
    match &*use_session() {
        None => html!(<p>{"Chargement…"}</p>),
        Some(s) if s.perms.contains(props.need) => html! { for props.children.iter() },
        _ => html!(<h1>{"403 – pas la permission"}</h1>),
    }
}
