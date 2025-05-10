use yew::prelude::*;
use crate::logout;
use crate::session::use_session;

#[derive(Properties, PartialEq)]
pub struct MainLayoutProps {
    #[prop_or_default]
    pub children: Children,
}

#[function_component(MainLayout)]
pub fn main_layout(props: &MainLayoutProps) -> Html {
    let session = use_session();

    let Some(_sess) = &*session else {
        return html!(<p>{"Chargement…"}</p>);
    };

    html! {
    <>
        <header class="header">
            <img src="/SuperNanny.png" alt="Logo SuperNanny" class="header-logo" />
            <h1 class="header-title">{ "SuperNanny" }</h1>
            <div class="header-logout">
                <logout::Logout />
            </div>
        </header>

        <main class="main-content">
            { for props.children.iter() }
        </main>
    </>
}

}
