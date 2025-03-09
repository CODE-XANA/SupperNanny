use dioxus::prelude::*;
use dioxus_desktop::{Config, LogicalSize, launch_with_props, WindowBuilder};
use reqwest;
use serde::Deserialize;
use serde_json::json;

/* ==================== Structures d'API ==================== */

#[derive(Deserialize, Clone)]
struct AppPolicy {
    pub app_name: String,
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
}

#[derive(Deserialize, Clone)]
struct SandboxEvent {
    pub event_id: i32,
    pub timestamp: String,
    pub hostname: String,
    pub denied_path: Option<String>,
    pub operation: String,
    pub result: String,
}

/* ==================== Fonctions d'appel API (rules) ==================== */

// Récupère toutes les configurations
async fn fetch_env_files() -> Result<Vec<AppPolicy>, reqwest::Error> {
    let client = reqwest::Client::new();
    let response = client
        .get("http://127.0.0.1:8080/envs")
        .send()
        .await?
        .error_for_status()?;
    let policies: Vec<AppPolicy> = response.json().await?;
    Ok(policies)
}

// Récupère la configuration d'une application
async fn fetch_env_content(program: &str) -> Result<AppPolicy, reqwest::Error> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:8080/env/{}", program);
    let response = client.get(&url).send().await?.error_for_status()?;
    let policy: AppPolicy = response.json().await?;
    Ok(policy)
}

// Met à jour la configuration
async fn update_env(
    program: &str,
    ro: Vec<String>,
    rw: Vec<String>,
    tcp_bind: String,
    tcp_connect: String,
) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:8080/env/{}", program);
    let payload = json!({
        "ll_fs_ro": ro,
        "ll_fs_rw": rw,
        "ll_tcp_bind": tcp_bind,
        "ll_tcp_connect": tcp_connect,
    });
    client.put(&url).json(&payload).send().await?.error_for_status()?;
    Ok(())
}

// Supprime la configuration
async fn delete_env(program: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:8080/env/{}", program);
    client.delete(&url).send().await?.error_for_status()?;
    Ok(())
}

// Crée une configuration
async fn create_env(
    program: &str,
    default_ro: String,
    default_rw: String,
    tcp_bind: String,
    tcp_connect: String,
) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    let url = "http://127.0.0.1:8080/env";
    let payload = json!({
        "app_name": program,
        "default_ro": default_ro,
        "default_rw": default_rw,
        "tcp_bind": tcp_bind,
        "tcp_connect": tcp_connect,
    });
    client.post(url).json(&payload).send().await?.error_for_status()?;
    Ok(())
}

/* ==================== Fonction d'appel API pour Events ==================== */

async fn fetch_events(program: &str) -> Result<Vec<SandboxEvent>, reqwest::Error> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:8080/events/{}", program);
    let response = client.get(&url).send().await?.error_for_status()?;
    let events: Vec<SandboxEvent> = response.json().await?;
    Ok(events)
}

/* ========================================================================== */

/* ==================== Application Frontend ==================== */

fn main() {
    let window_builder = WindowBuilder::new()
        .with_title("SuperNanny")
        .with_inner_size(LogicalSize::new(1000.0, 700.0));
    let config = Config::new()
        .with_window(window_builder)
        .with_resource_directory("assets");
    launch_with_props(app, (), config);
}

fn app(cx: Scope) -> Element {
    // États pour les configurations (règles)
    let env_files = use_state(&cx, || Vec::<AppPolicy>::new());
    let selected_env = use_state(&cx, || String::new());
    let ro_list = use_state(&cx, || Vec::<String>::new());
    let rw_list = use_state(&cx, || Vec::<String>::new());
    let tcp_bind = use_state(&cx, || "9418".to_string());
    let tcp_connect = use_state(&cx, || "80:443".to_string());
    let new_program = use_state(&cx, || String::new());
    let new_program_ro = use_state(&cx, || String::new());
    let new_program_rw = use_state(&cx, || String::new());
    // Nouveaux états pour ajouter individuellement un chemin dans l'onglet Rules
    let new_ro_item = use_state(&cx, || String::new());
    let new_rw_item = use_state(&cx, || String::new());
    // Onglet sélectionné: "rules" ou "events"
    let selected_tab = use_state(&cx, || "rules".to_string());
    // États pour les events
    let events = use_state(&cx, || Vec::<SandboxEvent>::new());

    // Récupérer la liste des configurations via l'API
    use_future(&cx, (), |_| {
        let env_files = env_files.clone();
        async move {
            match fetch_env_files().await {
                Ok(policies) => env_files.set(policies),
                Err(e) => eprintln!("Erreur lors du fetch des configurations : {:?}", e),
            }
        }
    });

    // Lorsque l'application sélectionnée change et l'onglet "rules" est actif, récupérer sa configuration
    use_effect(&cx, selected_env.get(), move |program| {
        let ro_list = ro_list.clone();
        let rw_list = rw_list.clone();
        let tcp_bind = tcp_bind.clone();
        let tcp_connect = tcp_connect.clone();
        async move {
            if program.is_empty() {
                return;
            }
            match fetch_env_content(&program).await {
                Ok(policy) => {
                    ro_list.set(
                        policy
                            .default_ro
                            .split(':')
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect(),
                    );
                    rw_list.set(
                        policy
                            .default_rw
                            .split(':')
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect(),
                    );
                    tcp_bind.set(policy.tcp_bind);
                    tcp_connect.set(policy.tcp_connect);
                }
                Err(e) => eprintln!("Erreur lors du fetch du contenu : {:?}", e),
            }
        }
    });

    // Lorsque l'onglet "events" est sélectionné, récupérer les events pour l'application
    use_effect(&cx, (selected_env.get(), selected_tab.get()), move |(program, tab)| {
        let events = events.clone();
        async move {
            if program.is_empty() || tab != "events" {
                return;
            }
            match fetch_events(&program).await {
                Ok(ev) => events.set(ev),
                Err(e) => eprintln!("Erreur lors du fetch des events : {:?}", e),
            }
        }
    });

    cx.render(rsx! {
        link { rel: "stylesheet", href: "assets/styles.css" }
        div { class: "main-container",
            // Colonne de gauche : liste des configurations et création
            div { class: "left-column",
                div {
                    class: "left-header",
                    style: "display: flex; align-items: center; gap: 8px;",
                    h2 { "Configurations" }
                    button {
                        class: "refresh-btn",
                        title: "Refresh",
                        onclick: move |_| {
                            let env_files = env_files.clone();
                            cx.spawn(async move {
                                match fetch_env_files().await {
                                    Ok(policies) => env_files.set(policies),
                                    Err(e) => eprintln!("Erreur lors du fetch (refresh) : {:?}", e),
                                }
                            });
                        },
                        rsx! {
                            svg {
                                xmlns: "http://www.w3.org/2000/svg",
                                view_box: "0 0 24 24",
                                width: "24",
                                height: "24",
                                path { d: "M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6s-2.69 6-6 6a5.99 5.99 0 0 1-5.2-3H4.35A8 8 0 0 0 12 20c4.41 0 8-3.59 8-8s-3.59-8-8-8z" }
                            }
                        }
                    }
                }
                ul {
                    env_files.get().iter().map(|policy| {
                        let app = policy.app_name.clone();
                        rsx! {
                            li {
                                onclick: move |_| {
                                    selected_env.set(app.clone());
                                    selected_tab.set("rules".to_string());
                                },
                                "{app}"
                            }
                        }
                    })
                }
                h3 { "Créer une nouvelle configuration" }
                input {
                    placeholder: "Nom du programme",
                    value: "{new_program}",
                    oninput: move |e| new_program.set(e.value.clone())
                }
                input {
                    placeholder: "LL_FS_RO (séparé par ':')",
                    value: "{new_program_ro}",
                    oninput: move |e| new_program_ro.set(e.value.clone())
                }
                input {
                    placeholder: "LL_FS_RW (séparé par ':')",
                    value: "{new_program_rw}",
                    oninput: move |e| new_program_rw.set(e.value.clone())
                }
                button {
                    class: "submit-btn",
                    onclick: move |_| {
                        let program = new_program.get().clone();
                        let ro = new_program_ro.get().clone();
                        let rw = new_program_rw.get().clone();
                        let bind = "9418".to_string();
                        let connect = "80:443".to_string();
                        let env_files = env_files.clone();
                        cx.spawn(async move {
                            match create_env(&program, ro, rw, bind, connect).await {
                                Ok(_) => {
                                    println!("Configuration créée");
                                    match fetch_env_files().await {
                                        Ok(policies) => env_files.set(policies),
                                        Err(e) => eprintln!("Erreur lors du fetch après création : {:?}", e),
                                    }
                                },
                                Err(e) => eprintln!("Erreur lors de la création : {:?}", e),
                            }
                        });
                    },
                    "Créer la configuration"
                }
            }
            // Colonne du milieu : onglets "Rules" et "Events"
            div { class: "middle-column",
                div {
                    style: "display: flex; gap: 10px; margin-bottom: 20px;",
                    button {
                        class: "tab-btn",
                        onclick: move |_| { selected_tab.set("rules".to_string()); },
                        "Rules"
                    }
                    button {
                        class: "tab-btn",
                        onclick: move |_| { selected_tab.set("events".to_string()); },
                        "Events"
                    }
                }
                (if !selected_env.get().is_empty() {
                    match selected_tab.get().as_str() {
                        "rules" => rsx! {
                            h2 {
                                style: "display: flex; justify-content: space-between; align-items: center;",
                                span { "Éditer: {selected_env}" },
                                div {
                                    class: "icon-container",
                                    // Bouton Refresh pour recharger les règles
                                    button {
                                        class: "icon-button refresh-rules-button",
                                        title: "Refresh",
                                        onclick: move |_| {
                                            let ro_list = ro_list.clone();
                                            let rw_list = rw_list.clone();
                                            let tcp_bind = tcp_bind.clone();
                                            let tcp_connect = tcp_connect.clone();
                                            let program = selected_env.get().clone();
                                            cx.spawn(async move {
                                                if program.is_empty() { return; }
                                                match fetch_env_content(&program).await {
                                                    Ok(policy) => {
                                                        ro_list.set(policy.default_ro.split(':')
                                                            .filter(|s| !s.is_empty())
                                                            .map(|s| s.to_string())
                                                            .collect());
                                                        rw_list.set(policy.default_rw.split(':')
                                                            .filter(|s| !s.is_empty())
                                                            .map(|s| s.to_string())
                                                            .collect());
                                                        tcp_bind.set(policy.tcp_bind);
                                                        tcp_connect.set(policy.tcp_connect);
                                                    },
                                                    Err(e) => eprintln!("Erreur lors du fetch du contenu : {:?}", e),
                                                }
                                            });
                                        },
                                        rsx! {
                                            svg {
                                                xmlns: "http://www.w3.org/2000/svg",
                                                view_box: "0 0 24 24",
                                                width: "24",
                                                height: "24",
                                                path { d: "M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6s-2.69 6-6 6a5.99 5.99 0 0 1-5.2-3H4.35A8 8 0 0 0 12 20c4.41 0 8-3.59 8-8s-3.59-8-8-8z" }
                                            }
                                        }
                                    }
                                    // Bouton Update pour envoyer la mise à jour
                                    button {
                                        class: "icon-button confirm-button",
                                        title: "Mettre à jour",
                                        onclick: move |_| {
                                            let program = selected_env.get().clone();
                                            let ro = ro_list.get().clone();
                                            let rw = rw_list.get().clone();
                                            let bind = tcp_bind.get().clone();
                                            let connect = tcp_connect.get().clone();
                                            cx.spawn(async move {
                                                match update_env(&program, ro, rw, bind, connect).await {
                                                    Ok(_) => println!("Mise à jour réussie"),
                                                    Err(e) => eprintln!("Erreur lors de la mise à jour : {:?}", e),
                                                }
                                            });
                                        },
                                        rsx! {
                                            svg {
                                                xmlns: "http://www.w3.org/2000/svg",
                                                view_box: "0 0 24 24",
                                                width: "24",
                                                height: "24",
                                                path { d: "M9 16.17l-4.17-4.17-1.42 1.41L9 19l10.59-10.59-1.42-1.41z" }
                                            }
                                        }
                                    }
                                    // Bouton Delete pour supprimer la configuration
                                    button {
                                        class: "icon-button delete-button",
                                        title: "Supprimer la configuration",
                                        onclick: move |_| {
                                            let program = selected_env.get().clone();
                                            let env_files = env_files.clone();
                                            let selected_env = selected_env.clone();
                                            cx.spawn(async move {
                                                match delete_env(&program).await {
                                                    Ok(_) => {
                                                        println!("Configuration supprimée");
                                                        match fetch_env_files().await {
                                                            Ok(policies) => {
                                                                env_files.set(policies);
                                                                if *selected_env.get() == program {
                                                                    selected_env.set(String::new());
                                                                }
                                                            },
                                                            Err(e) => eprintln!("Erreur lors du fetch après suppression : {:?}", e),
                                                        }
                                                    },
                                                    Err(e) => eprintln!("Erreur lors de la suppression : {:?}", e),
                                                }
                                            });
                                        },
                                        rsx! {
                                            svg {
                                                xmlns: "http://www.w3.org/2000/svg",
                                                view_box: "0 0 24 24",
                                                width: "24",
                                                height: "24",
                                                path { d: "M3 6l3 18h12l3-18H3zm18-2H3V2h5.5l1-1h5l1 1H21v2z" }
                                            }
                                        }
                                    }
                                }
                            }
                            // Section pour LL_FS_RO
                            div { class: "section",
                                h3 { "LL_FS_RO" }
                                ul {
                                    ro_list.get().iter().enumerate().map(|(i, item)| {
                                        let item = item.clone();
                                        rsx! {
                                            li {
                                                "{item} "
                                                button {
                                                    class: "delete-btn",
                                                    onclick: move |_| {
                                                        let mut list = (*ro_list.get()).clone();
                                                        list.remove(i);
                                                        ro_list.set(list);
                                                    },
                                                    "x"
                                                }
                                            }
                                        }
                                    })
                                }
                                div {
                                    class: "add-path",
                                    input {
                                        placeholder: "Ajouter chemin RO",
                                        value: "{new_ro_item}",
                                        oninput: move |e| new_ro_item.set(e.value.clone())
                                    }
                                    button {
                                        class: "submit-btn",
                                        onclick: move |_| {
                                            if !new_ro_item.get().is_empty() {
                                                let mut list = (*ro_list.get()).clone();
                                                list.push(new_ro_item.get().clone());
                                                ro_list.set(list);
                                                new_ro_item.set("".to_string());
                                            }
                                        },
                                        "Ajouter RO"
                                    }
                                }
                            }
                            // Section pour LL_FS_RW
                            div { class: "section",
                                h3 { "LL_FS_RW" }
                                ul {
                                    rw_list.get().iter().enumerate().map(|(i, item)| {
                                        let item = item.clone();
                                        rsx! {
                                            li {
                                                "{item} "
                                                button {
                                                    class: "delete-btn",
                                                    onclick: move |_| {
                                                        let mut list = (*rw_list.get()).clone();
                                                        list.remove(i);
                                                        rw_list.set(list);
                                                    },
                                                    "x"
                                                }
                                            }
                                        }
                                    })
                                }
                                div {
                                    class: "add-path",
                                    input {
                                        placeholder: "Ajouter chemin RW",
                                        value: "{new_rw_item}",
                                        oninput: move |e| new_rw_item.set(e.value.clone())
                                    }
                                    button {
                                        class: "submit-btn",
                                        onclick: move |_| {
                                            if !new_rw_item.get().is_empty() {
                                                let mut list = (*rw_list.get()).clone();
                                                list.push(new_rw_item.get().clone());
                                                rw_list.set(list);
                                                new_rw_item.set("".to_string());
                                            }
                                        },
                                        "Ajouter RW"
                                    }
                                }
                            }
                        },
                        "events" => rsx! {
                            h2 { "Événements pour: {selected_env}" }
                            ul {
                                events.get().iter().map(|ev| {
                                    rsx! {
                                        li {
                                            p { "ID: {ev.event_id}" }
                                            p { "Date: {ev.timestamp}" }
                                            p { "Hostname: {ev.hostname}" }
                                            p { "Path: {ev.denied_path.clone().unwrap_or_default()}" }
                                            p { "Opération: {ev.operation}" }
                                            p { "Résultat: {ev.result}" }
                                        }
                                    }
                                })
                            }
                        },
                        _ => rsx! { div { "Onglet inconnu" } }
                    }
                } else {
                    rsx! { div { "Sélectionnez une configuration pour l'éditer" } }
                })
            }
            // Colonne de droite : résumé de la configuration
            div { class: "right-column",
                h2 { "Résumé" }
                (if !selected_env.get().is_empty() {
                    rsx! {
                        p { "Configuration sélectionnée: {selected_env}" }
                        p { "LL_TCP_BIND: {tcp_bind}" }
                        p { "LL_TCP_CONNECT: {tcp_connect}" }
                        p { "LL_FS_RO:" }
                        p { ro_list.get().join(":") }
                        p { "LL_FS_RW:" }
                        p { rw_list.get().join(":") }
                    }
                } else {
                    rsx! { div { "Aucune sélection" } }
                })
            }
        }
    })
}
