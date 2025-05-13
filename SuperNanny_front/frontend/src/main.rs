use yew::prelude::*;
use yew_router::prelude::*;

mod api;            // helpers HTTP/CSRF
mod auth;           // formulaire Login
mod session;        // SessionProvider + use_session
mod guard;          // Guard need="perm"
mod logout;         // bouton Déconnexion

mod dashboard;
mod configurations;
mod manage_users;
mod manage_roles;
mod layout;

/* -------------------- routing -------------------- */

#[derive(Routable, Clone, PartialEq)]
pub enum Route {
    #[at("/")]
    Login,
    #[at("/dashboard")]
    Dashboard,
    #[at("/configurations")]
    Configurations,
    #[at("/users")]
    ManageUsers,
    #[at("/roles")]
    ManageRoles,
    #[not_found]
    #[at("/404")]
    NotFound,
}

fn switch(route: Route) -> Html {
    match route {
        Route::Login => html!(<auth::LoginForm />),

        Route::Dashboard => html!(
            <layout::MainLayout>
                <dashboard::Dashboard />
            </layout::MainLayout>
        ),

        Route::Configurations => html!(
            <layout::MainLayout>
                <guard::Guard need="manage_rules">
                    <configurations::Configurations />
                </guard::Guard>
            </layout::MainLayout>
        ),

        Route::ManageUsers => html!(
            <layout::MainLayout>
                <guard::Guard need="manage_users">
                    <manage_users::ManageUsers />
                </guard::Guard>
            </layout::MainLayout>
        ),

        Route::ManageRoles => html!(
            <layout::MainLayout>
                <guard::Guard need="manage_roles">
                    <manage_roles::ManageRoles />
                </guard::Guard>
            </layout::MainLayout>
        ),

        Route::NotFound => html!(<h1>{ "404 – Not Found" }</h1>),
    }
}

/* -------------------- entry point ---------------- */

#[function_component(App)]
fn app() -> Html {
    html! {
        <BrowserRouter>
            <session::SessionProvider>
                <Switch<Route> render={switch} />
            </session::SessionProvider>
        </BrowserRouter>
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
