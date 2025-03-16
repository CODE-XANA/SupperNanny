use yew::prelude::*;
use yew_router::prelude::*;
mod auth;
mod envs_page;
mod models;
mod utils;
mod logout;

#[derive(Clone, Routable, PartialEq)]
pub enum Route {
    #[at("/")]
    Login,
    #[at("/envs")]
    Envs,
}

#[function_component(App)]
pub fn app() -> Html {
    html! {
        <BrowserRouter>
            <Switch<Route> render={switch} />
        </BrowserRouter>
    }
}

fn switch(route: Route) -> Html {
    match route {
        Route::Login => html! { <auth::LoginForm /> },
        Route::Envs  => html! { <envs_page::EnvsPage /> },
    }
}


fn main() {
    yew::Renderer::<App>::new().render();
}
