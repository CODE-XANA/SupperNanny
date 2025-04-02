use yew::prelude::*;
use yew_router::prelude::*;

mod auth;
mod home;
mod manage_users;
mod manage_roles;
mod layout;
mod models;
mod utils;
mod logout;

#[derive(Routable, Clone, PartialEq)]
pub enum Route {
    #[at("/")]
    Login,
    #[at("/home")]
    Home,
    #[at("/users")]
    ManageUsers,
    #[at("/roles")]
    ManageRoles,
    #[not_found]
    #[at("/404")]
    NotFound,
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
        Route::Login => html! {
            <auth::LoginForm />
        },
        Route::Home => html! {
            <layout::MainLayout>
                <home::Home />
            </layout::MainLayout>
        },
        Route::ManageUsers => html! {
            <layout::MainLayout>
                <manage_users::ManageUsers />
            </layout::MainLayout>
        },
        Route::ManageRoles => html! {
            <layout::MainLayout>
                <manage_roles::ManageRoles />
            </layout::MainLayout>
        },
        Route::NotFound => html! { <h1>{ "404 - Not Found" }</h1> },
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
