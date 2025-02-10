use dioxus::prelude::*;
use dioxus_desktop::{Config, LogicalSize, launch_with_props, WindowBuilder};
use reqwest::Client;
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Clone)]
struct Rule {
    id: String,
    description: String,
    pattern: String,
    action: String,
    enabled: bool,
}

fn main() {
    let window_builder = WindowBuilder::new()
        .with_title("SuperNanny")
        .with_inner_size(LogicalSize::new(1000.0, 700.0));

    let config = Config::new().with_window(window_builder);

    launch_with_props(app, (), config);
}

fn app(cx: Scope) -> Element {
    let styles = include_str!("../assets/styles.css");

    let applications = use_state(&cx, || vec![]);
    let selected_app = use_state(&cx, || String::new());
    let active_tab = use_state(&cx, || "Règles".to_string());
    let show_modal = use_state(&cx, || false);
    let new_app_name = use_state(&cx, || String::new());
    let new_app_path = use_state(&cx, || String::new());
    let rules = use_state(&cx, || vec![]);
    let logs = use_state(&cx, || vec![]);
    let app_path = use_state(&cx, || String::new());
    let user_name = use_state(&cx, || String::new());
    let network_blacklist = use_state(&cx, || vec![]);
    let file_blacklist = use_state(&cx, || vec![]);
    let new_network_rule_input = use_state(&cx, || String::new());
    let new_file_rule_input = use_state(&cx, || String::new());
    let show_confirmation = use_state(&cx, || false);

    // Charger les applications au montage
    use_future(&cx, (), |_| {
        let applications = applications.clone();
        async move {
            match fetch_applications().await {
                Ok(apps) => {
                    applications.set(apps);
                }
                Err(err) => eprintln!("Erreur lors du chargement des applications : {err}"),
            }
        }
    });
    

    // Charger les règles et blacklists lors de la sélection d'une application
    use_future(&cx, (selected_app,), move |_| {
        let selected_app = selected_app.get().clone();
        let rules = rules.clone();
        let logs = logs.clone();
        let app_path = app_path.clone();
        let user_name = user_name.clone();
        let network_blacklist = network_blacklist.clone();
        let file_blacklist = file_blacklist.clone();
        async move {
            logs.set(vec![]);
            if !selected_app.is_empty() {
                if let Ok(rule_data) = fetch_rules_for_application(&selected_app).await {
                    rules.set(rule_data);
                }
                if let Ok(log_data) = fetch_logs_for_application(&selected_app).await {
                    logs.set(log_data);
                }
                if let Ok(network_data) = fetch_blacklist_for_application(&selected_app, "network_blacklist").await {
                    network_blacklist.set(network_data);
                }
                if let Ok(file_data) = fetch_blacklist_for_application(&selected_app, "file_blacklist").await {
                    file_blacklist.set(file_data);
                }
                if let Ok(path) = fetch_path_for_application(&selected_app).await {
                    app_path.set(path);
                }
                if let Ok(user) = fetch_user_for_application(&selected_app).await {
                    user_name.set(user);
                }
            }
        }
    });

    

    // Générer les éléments des règles standard
    let rule_elements = rules.iter().enumerate().map(|(index, rule)| {
        let selected_app = selected_app.clone();
        let rules = rules.clone();
        rsx! {
            div {
                style: "display: flex; justify-content: space-between; align-items: center; padding: 0px 15px 0px 15px; background-color: #f9f9f9; margin: 10px 0; border-radius: 10px;",                p { "{rule.description}" }
                div {
                    class: if rule.enabled { "toggle-button active" } else { "toggle-button" },
                    onclick: move |_| {
                        let mut new_rule = rule.clone();
                        new_rule.enabled = !rule.enabled;
                        let rules = rules.clone();
                        let selected_app_value = selected_app.get().clone();
                        cx.spawn(async move {
                            if let Err(e) = update_rule(&selected_app_value, &new_rule).await {
                                eprintln!("Erreur lors de la mise à jour de la règle : {e}");
                            } else {
                                rules.modify(|current_rules| {
                                    let mut updated_rules = current_rules.clone();
                                    if let Some(existing_rule) = updated_rules.get_mut(index) {
                                        *existing_rule = new_rule;
                                    }
                                    updated_rules
                                });
                            }
                        });
                    },
                    div { class: "toggle-button-circle" }
                }
            }
        }
    });

    let add_network_rule = {
        let selected_app = selected_app.clone();
        let new_network_rule_input = new_network_rule_input.clone();
        let network_blacklist = network_blacklist.clone();
        move |_| {
            let new_rule = new_network_rule_input.get().clone();
            let app_name = selected_app.get().clone();
            let blacklist = network_blacklist.clone();
            let input = new_network_rule_input.clone();
            cx.spawn(async move {
                if let Err(e) = add_blacklist_rule(&app_name, "network_blacklist", &new_rule).await {
                    eprintln!("Erreur lors de l'ajout de la règle réseau : {e}");
                } else {
                    blacklist.modify(|current| {
                        let mut updated = current.clone();
                        updated.push(new_rule.clone());
                        updated
                    });
                    input.set(String::new());
                }
            });
        }
    };
    
    let add_file_rule = {
        let selected_app = selected_app.clone();
        let new_file_rule_input = new_file_rule_input.clone();
        let file_blacklist = file_blacklist.clone();
        move |_| {
            let new_rule = new_file_rule_input.get().clone();
            let app_name = selected_app.get().clone();
            let blacklist = file_blacklist.clone();
            let input = new_file_rule_input.clone();
            cx.spawn(async move {
                if let Err(e) = add_blacklist_rule(&app_name, "file_blacklist", &new_rule).await {
                    eprintln!("Erreur lors de l'ajout de la règle fichier : {e}");
                } else {
                    blacklist.modify(|current| {
                        let mut updated = current.clone();
                        updated.push(new_rule.clone());
                        updated
                    });
                    input.set(String::new());
                }
            });
        }
    };
    
    let confirmation_message = use_state(&cx, || String::new());

    let delete_application = {
        let selected_app = selected_app.clone();
        let show_confirmation = show_confirmation.clone();
        let confirmation_message = confirmation_message.clone();
    
        move |_| {
            let app_name = selected_app.get().clone();
            if app_name.is_empty() {
                eprintln!("Aucune application sélectionnée pour la suppression.");
                return;
            }
    
            let confirmation_message = confirmation_message.clone();
            let show_confirmation = show_confirmation.clone();
    
            cx.spawn(async move {
                let client = reqwest::Client::new();
                let response = client
                    .post("http://127.0.0.1:8000/remove_application")
                    .json(&serde_json::json!({ "name": app_name }))
                    .send()
                    .await;
    
                match response {
                    Ok(resp) if resp.status().is_success() => {
                        let message = resp.text().await.unwrap_or_default();
                        confirmation_message.set(message);
                        show_confirmation.set(true);
                    }
                    Ok(resp) => {
                        let error = resp.text().await.unwrap_or_else(|_| "Erreur inconnue".to_string());
                        eprintln!("Erreur lors de la demande de confirmation : {}", error);
                    }
                    Err(err) => eprintln!("Erreur de requête : {}", err),
                }
            });
        }
    };
    


    let confirm_delete = {
        let selected_app = selected_app.clone();
        let applications = applications.clone();
        let show_confirmation = show_confirmation.clone();
    
        move |_| {
            let app_name = selected_app.get().clone();
            if app_name.is_empty() {
                eprintln!("Aucune application sélectionnée pour la suppression.");
                return;
            }
    
            let applications = applications.clone(); // Cloner ici
            let selected_app = selected_app.clone(); // Cloner ici
            let show_confirmation = show_confirmation.clone(); // Cloner ici
    
            cx.spawn(async move {
                let client = reqwest::Client::new();
                let response = client
                    .post("http://127.0.0.1:8000/remove_application")
                    .json(&serde_json::json!({ "name": app_name, "confirm": true }))
                    .send()
                    .await;
    
                match response {
                    Ok(resp) if resp.status().is_success() => {
                        applications.modify(|current_apps| {
                            current_apps
                                .iter()
                                .filter(|app| **app != app_name)
                                .cloned()
                                .collect()
                        });
                        selected_app.set(String::new());
                        eprintln!("L'application '{}' a été supprimée.", app_name);
                    }
                    Ok(resp) => {
                        let error = resp.text().await.unwrap_or_else(|_| "Erreur inconnue".to_string());
                        eprintln!("Erreur lors de la suppression : {}", error);
                    }
                    Err(err) => eprintln!("Erreur de requête : {}", err),
                }
                show_confirmation.set(false);
            });
        }
    };
    
    let cancel_delete = {
        let show_confirmation = show_confirmation.clone();
        move |_: dioxus::prelude::Event<dioxus::events::MouseData>| {
            show_confirmation.set(false);
        }
    };    

    // Générer les éléments pour les blacklists réseau et fichiers
    let network_blacklist_elements = network_blacklist.iter().map(|rule| {
        let selected_app = selected_app.clone();
        let network_blacklist = network_blacklist.clone();
        rsx! {
            div {
                style: "display: flex; justify-content: space-between; align-items: center; padding: 0 0 0 15px; background-color: #f9f9f9; margin: 10px 0; border-radius: 10px;",                p { style: "margin: 0;", "{rule}" }
                button {
                    class: "delete-button",
                    onclick: move |_| {
                        let rule_to_remove = rule.clone();
                        let selected_app_value = selected_app.clone();
                        let network_blacklist_value = network_blacklist.clone();
                        cx.spawn(async move {
                            if let Err(e) = remove_blacklist_rule(&selected_app_value.get(), "network_blacklist", &rule_to_remove).await {
                                eprintln!("Erreur lors de la suppression de la règle : {e}");
                            } else {
                                network_blacklist_value.modify(|current_rules| {
                                    current_rules.iter().filter(|r| *r != &rule_to_remove).cloned().collect()
                                });
                            }
                        });
                    },
                    h5 { style: "font-weight: bold;", "X" }
                }
            }
        }
    });

    let file_blacklist_elements = file_blacklist.iter().map(|rule| {
        let selected_app = selected_app.clone();
        let file_blacklist = file_blacklist.clone();
        rsx! {
            div {
                style: "display: flex; justify-content: space-between; align-items: center; padding: 0 0 0 15px; background-color: #f9f9f9; margin: 10px 0; border-radius: 10px;",
                p { style: "margin: 0;", "{rule}" }
                button {
                    class: "delete-button",
                    onclick: move |_| {
                        let rule_to_remove = rule.clone();
                        let selected_app_value = selected_app.clone();
                        let file_blacklist_value = file_blacklist.clone();
                        cx.spawn(async move {
                            if let Err(e) = remove_blacklist_rule(&selected_app_value.get(), "file_blacklist", &rule_to_remove).await {
                                eprintln!("Erreur lors de la suppression de la règle : {e}");
                            } else {
                                file_blacklist_value.modify(|current_rules| {
                                    current_rules.iter().filter(|r| *r != &rule_to_remove).cloned().collect()
                                });
                            }
                        });
                    },
                    h5 { style: "font-weight: bold;", "X" }
                }
            }
        }
    });

    let add_application = {
        let applications = applications.clone();
        let new_app_name = new_app_name.clone();
        let new_app_path = new_app_path.clone();
        let show_modal = show_modal.clone();
    
        move |_| {
            let name = new_app_name.get().clone();
            let path = new_app_path.get().clone();
    
            let apps = applications.clone();
            let modal = show_modal.clone();
    
            cx.spawn(async move {
                let response = add_application_api(&name, &path).await;
    
                match response {
                    Ok(_) => {
                        apps.modify(|current_apps| {
                            let mut updated_apps = current_apps.clone();
                            updated_apps.push(name.clone());
                            updated_apps
                        });
                        modal.set(false);
                    }
                    Err(err) => {
                        eprintln!("Erreur lors de l'ajout de l'application : {err}");
                    }
                }
            });
        }
    };
    
    let launch_script = {
        move |_| {
            cx.spawn(async move {
                match reqwest::Client::new()
                    .post("http://127.0.0.1:8000/run_script")
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => {
                        let result = resp.json::<serde_json::Value>().await.unwrap_or_else(|_| {
                            serde_json::json!({"status": "error", "message": "Erreur de parsing de la réponse"})
                        });
                        if result["status"] == "success" {
                            println!("Script exécuté avec succès !");
                        } else {
                            eprintln!("Erreur lors de l'exécution du script : {}", result["message"]);
                        }
                    }
                    Ok(_) => eprintln!("Erreur lors de l'appel à l'API."),
                    Err(err) => eprintln!("Erreur réseau : {}", err),
                }
            });
        }
    };
    

    cx.render(rsx! {
        div {
            style { "{styles}" },
            div {
                style: "display: flex; font-family: Arial, sans-serif; height: 100vh;",
                div {
                    style: "width: 20%; border-right: 1px solid #ddd; padding: 10px;",
                    h2 { "Applications" }
                    div {
                        style: "display: flex; align-items: center; gap: 10px;",
                        button {
                            class: "add-application-button",
                            onclick: move |_| show_modal.set(true),
                            "+"
                        }       
                        button {
                            class: "refresh-button",
                            onclick: launch_script,
                            "⟳"
                        }
                    }      
                    ul {
                        style: "list-style-type: none; padding: 0;",
                        applications.iter().map(|app| {
                            let app_name = app.clone();
                            let is_active = *selected_app.get() == app_name; // Vérifie si c'est l'application sélectionnée
                            rsx! {
                                li {
                                    class: if is_active { "application-item active" } else { "application-item" },
                                    onclick: move |_| selected_app.set(app_name.clone()),
                                    "{app_name}"
                                }
                            }
                        })
                    }                                                   
                },
                div {
                    style: "width: 60%; padding: 10px; border-right: 1px solid #ddd;",
                    if selected_app.is_empty() {
                        rsx! { 
                            p { "Sélectionnez une application pour voir les détails." } 
                        }
                    } else {
                        rsx! {
                            div {
                                // Onglets pour basculer entre les règles et les logs
                                div {
                                    class: "tab-buttons",
                                    button {
                                        class: if *active_tab.get() == "Règles" { "tab-button active" } else { "tab-button" },
                                        onclick: move |_| active_tab.set("Règles".to_string()),
                                        "Règles"
                                    }
                                    button {
                                        class: if *active_tab.get() == "Logs" { "tab-button active" } else { "tab-button" },
                                        onclick: move |_| active_tab.set("Logs".to_string()),
                                        "Logs"
                                    }
                                }
                                // Contenu des onglets
                                if *active_tab.get() == "Règles" {
                                    rsx! {
                                        div {
                                            h3 { "Règles Standard" }
                                            rule_elements
                                            h3 { "Blacklist Réseau" }
                                            div {
                                                class: "add-rule-container",
                                                input {
                                                    class: "add-rule-input",
                                                    placeholder: "IP ou nom de domaine",
                                                    value: "{new_network_rule_input}",
                                                    oninput: move |event| new_network_rule_input.set(event.value.clone()),
                                                }
                                                button { class: "add-rule-button", onclick: add_network_rule, "Ajouter" }
                                            }
                                            network_blacklist_elements
                                            h3 { "Blacklist Fichiers" }
                                            div {
                                                class: "add-rule-container",
                                                input {
                                                    class: "add-rule-input",
                                                    placeholder: "Chemin de fichier",
                                                    value: "{new_file_rule_input}",
                                                    oninput: move |event| new_file_rule_input.set(event.value.clone()),
                                                }
                                                button { class: "add-rule-button", onclick: add_file_rule, "Ajouter" }
                                            }
                                            file_blacklist_elements
                                        }
                                        div {
                                            style: "position: absolute; bottom: 10px; right: 10px;",
                                            button {
                                                class: "delete-app-button",
                                                onclick: delete_application,
                                                "Supprimer l'application"
                                            }
                                        }
                                    }
                                } else if *active_tab.get() == "Logs" {
                                    rsx! {
                                        div {
                                            class: "logs-container",
                                            if logs.is_empty() {
                                                rsx! {
                                                    p { "Aucun log disponible pour cette application." }
                                                }
                                            } else {
                                                rsx! {
                                                    Fragment {
                                                        logs.iter().map(|log| {
                                                            if let Some((timestamp, message)) = log.split_once(": ") {  // ✅ Coupe une seule fois
                                                                rsx! {
                                                                    div {
                                                                        class: "log-card",
                                                                        span { class: "timestamp", "Horodatage : {timestamp}" }
                                                                        p { "Message : {message}" }
                                                                    }
                                                                }
                                                            } else {
                                                                rsx! {
                                                                    div {
                                                                        class: "log-card",
                                                                        p { "Log mal formatté : {log}" }
                                                                    }
                                                                }
                                                            }
                                                        })
                                                    }
                                                }
                                            }
                                        }

                                        div {
                                            style: "position: absolute; bottom: 10px; right: 10px;",
                                            button {
                                                class: "delete-app-button",
                                                onclick: delete_application,
                                                "Supprimer l'application"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                div {
                    style: "width: 20%; padding: 10px;",
                    if selected_app.is_empty() {
                        rsx! { p { "Aucune application sélectionnée." } }
                    } else {
                        rsx! {
                            div {
                                h2 { style: "font-weight: bold; margin-bottom: 15px;", "{selected_app}" }
                                p { "Path : {app_path}" }
                                p { "User : {user_name}" }
                                p { "Uptime : N/A" }
                                p { "Status : N/A" }
                            }
                        }
                    }
                },
                if *show_modal.get() {
                    rsx! {
                        div {
                            class: "add-modal",
                            div {
                                class: "modal-content",
                                h3 { "Ajouter une application" }
                                input {
                                    placeholder: "Nom de l'application",
                                    value: "{new_app_name}",
                                    oninput: move |e| new_app_name.set(e.value.clone()),
                                }
                                input {
                                    placeholder: "Chemin de l'application",
                                    value: "{new_app_path}",
                                    oninput: move |e| new_app_path.set(e.value.clone()),
                                }
                                button {
                                    class: "add",
                                    onclick: add_application,
                                    "Ajouter"
                                }
                                button {
                                    class: "cancel",
                                    onclick: move |_| show_modal.set(false),
                                    "Annuler"
                                }
                            }
                        }
                    }
                }
                if *show_confirmation.get() {
                    rsx! {
                        div {
                            class: "confirmation-modal",
                            div {
                                class: "modal-content",
                                h3 { "Confirmation de suppression" }
                                p { "{confirmation_message}" }
                                div {
                                    style: "display: flex; justify-content: space-between; margin-top: 10px;",
                                    button {
                                        class: "confirm-button",
                                        onclick: confirm_delete,
                                        "Confirmer"
                                    }
                                    button {
                                        class: "cancel-button",
                                        onclick: cancel_delete,
                                        "Annuler"
                                    }                                                                       
                                }
                            }
                        }
                    }
                }               
                
            }}
        }
    )
    }

async fn fetch_logs_for_application(app_name: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:8000/logs/{}", app_name))
        .send()
        .await?;
    let logs: Vec<String> = response.json().await?;
    Ok(logs)
}

async fn fetch_user_for_application(app_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:8000/user/{}", app_name))
        .send()
        .await?;
    let user = response.text().await?;
    Ok(user)
}

    
async fn fetch_path_for_application(app_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:8000/path/{}", app_name))
        .send()
        .await?;
    let path = response.text().await?;
    Ok(path)
}


async fn add_application_api(name: &str, path: &str) -> Result<(), String> {
    let client = reqwest::Client::new();

    let response = client
        .post("http://127.0.0.1:8000/add_application")
        .json(&(name.to_string(), path.to_string()))
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => {
            let error_message = resp.text().await.unwrap_or_else(|_| "Erreur inconnue".to_string());
            Err(error_message)
        }
        Err(err) => Err(format!("Erreur de requête : {err}")),
    }
}


async fn fetch_applications() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let client = Client::new();
    let response = client.get("http://127.0.0.1:8000/applications").send().await?;
    let apps: Vec<String> = response.json().await?;
    Ok(apps)
}

async fn fetch_rules_for_application(app_name: &str) -> Result<Vec<Rule>, Box<dyn std::error::Error>> {
    let client = Client::new();
    let response = client
        .get(format!("http://127.0.0.1:8000/rules/{}", app_name))
        .send()
        .await?;
    let rules: Vec<Rule> = response.json().await?;
    Ok(rules)
}


async fn fetch_blacklist_for_application(app_name: &str, rule_type: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let client = Client::new();
    let response = client
        .get(format!("http://127.0.0.1:8000/custom_rules/{}/{}", app_name, rule_type))
        .send()
        .await?;
    let rules: Vec<String> = response.json().await?;
    Ok(rules)
}

async fn add_blacklist_rule(app_name: &str, rule_type: &str, rule: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    client
        .post(format!("http://127.0.0.1:8000/custom_rules/{}/{}/add", app_name, rule_type))
        .json(&rule)
        .send()
        .await?;
    Ok(())
}

async fn remove_blacklist_rule(app_name: &str, rule_type: &str, rule: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    client
        .post(format!("http://127.0.0.1:8000/custom_rules/{}/{}/remove", app_name, rule_type))
        .json(&rule)
        .send()
        .await?;
    Ok(())
}

async fn update_rule(app_name: &str, rule: &Rule) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    client
        .post(format!("http://127.0.0.1:8000/rules/{}", app_name))
        .json(rule)
        .send()
        .await?;
    Ok(())
}