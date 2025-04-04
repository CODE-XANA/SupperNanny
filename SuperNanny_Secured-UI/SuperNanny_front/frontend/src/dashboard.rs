// dashboard.rs
use yew::prelude::*;

#[function_component(Dashboard)]
pub fn dashboard() -> Html {
    html! {
        <div>
            <h1>{ "Dashboard" }</h1>
            <p>{ "Bienvenue sur votre tableau de bord !" }</p>
            // Ajoutez ici le contenu spécifique du dashboard
        </div>
    }
}
