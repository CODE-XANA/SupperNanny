use yew::prelude::*;
use yew_router::prelude::*;
mod auth;
mod home;
mod models;
mod utils;
mod logout;

#[derive(Clone, Routable, PartialEq)]
pub enum Route {
    #[at("/")]
    Login,
    #[at("/home")]
    Home,
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
        Route::Home  => html! { <home::Home /> },
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
