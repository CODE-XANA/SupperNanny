use yew::prelude::*;
use yew_router::prelude::*;

mod auth;
mod utils;
mod logout;          // ← ajouté pour corriger l’import dans layout

// Pages déjà existantes
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
        Route::Dashboard => html!(<layout::MainLayout><dashboard::Dashboard /></layout::MainLayout>),
        Route::Configurations => html!(<layout::MainLayout><configurations::Configurations /></layout::MainLayout>),
        Route::ManageUsers => html!(<layout::MainLayout><manage_users::ManageUsers /></layout::MainLayout>),
        Route::ManageRoles => html!(<layout::MainLayout><manage_roles::ManageRoles /></layout::MainLayout>),
        Route::NotFound => html!(<h1>{"404 – Not Found"}</h1>),
    }
}

/* -------------------- entry point ---------------- */

#[function_component(App)]
fn app() -> Html {
    html! {
        <BrowserRouter>
            <Switch<Route> render={switch} />
        </BrowserRouter>
    }
}

fn main() {
    yew::Renderer::<App>::new().render();
}
