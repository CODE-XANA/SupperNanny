use dioxus::prelude::*;
use dioxus_desktop::{Config, LogicalSize, launch_with_props, WindowBuilder};
use reqwest;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;

/* ==================== Structures d'API ==================== */

#[derive(Deserialize, Clone)]
struct AppPolicy {
    pub app_name: String,
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
    pub updated_at: String,
}

#[derive(Deserialize, Clone)]
struct SandboxEvent {
    pub event_id: i32,
    pub timestamp: String,
    pub hostname: String,
    pub app_name: String,
    pub denied_path: Option<String>,
    pub operation: String,
    pub result: String,
}

/* ==================== Fonctions d'appel API (rules) ==================== */

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

async fn fetch_env_content(program: &str) -> Result<AppPolicy, reqwest::Error> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:8080/env/{}", program);
    let response = client.get(&url).send().await?.error_for_status()?;
    let policy: AppPolicy = response.json().await?;
    Ok(policy)
}

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

async fn delete_env(program: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:8080/env/{}", program);
    client.delete(&url).send().await?.error_for_status()?;
    Ok(())
}

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

/* ==================== Fonctions d'appel API (script prompts) ==================== */

#[derive(Deserialize, Clone)]
struct PendingPrompt {
    app: String,
    path: String,
}

async fn fetch_pending_prompts() -> Result<Vec<PendingPrompt>, reqwest::Error> {
    let client = reqwest::Client::new();
    let response = client
        .get("http://127.0.0.1:8080/pending_prompts")
        .send()
        .await?
        .error_for_status()?;
    let prompts: Vec<PendingPrompt> = response.json().await?;
    Ok(prompts)
}

async fn set_prompt_choice(app: &str, path: &str, choice: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    let url = "http://127.0.0.1:8080/set_choice";
    let payload = json!({
        "app": app,
        "path": path,
        "choice": choice,
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

/* ==================== Composant Notification ==================== */

fn Notification(cx: Scope) -> Element {
    let pending_prompts = use_state(&cx, || Vec::<PendingPrompt>::new());
    use_future(&cx, (), |_| {
        let pending_prompts = pending_prompts.clone();
        async move {
            loop {
                match fetch_pending_prompts().await {
                    Ok(prompts) => pending_prompts.set(prompts),
                    Err(e) => eprintln!("Erreur lors du fetch des prompts: {:?}", e),
                }
                async_std::task::sleep(Duration::from_secs(5)).await;
            }
        }
    });
    cx.render(rsx! {
        div {
            class: "notification-container",
            style: "position: fixed; bottom: 20px; right: 20px; z-index: 1000;",
            pending_prompts.get().iter().map(|p| {
                rsx! {
                    div {
                        class: "notification",
                        style: "background-color: #fff; border: 1px solid #ccc; padding: 10px; margin-bottom: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.2);",
                        p { "App: {p.app}" }
                        p { "Path: {p.path}" }
                        div {
                            style: "display: flex; gap: 10px; margin-top: 10px;",
                            button {
                                class: "submit-btn",
                                onclick: move |_| {
                                    let app_clone = p.app.clone();
                                    let path_clone = p.path.clone();
                                    cx.spawn(async move {
                                        if let Err(e) = set_prompt_choice(&app_clone, &path_clone, "r").await {
                                            eprintln!("Erreur lors du set_choice: {:?}", e);
                                        }
                                    });
                                },
                                "Read-only (r)"
                            }
                            button {
                                class: "submit-btn",
                                onclick: move |_| {
                                    let app_clone = p.app.clone();
                                    let path_clone = p.path.clone();
                                    cx.spawn(async move {
                                        if let Err(e) = set_prompt_choice(&app_clone, &path_clone, "w").await {
                                            eprintln!("Erreur lors du set_choice: {:?}", e);
                                        }
                                    });
                                },
                                "Writable (w)"
                            }
                            button {
                                class: "submit-btn",
                                onclick: move |_| {
                                    let app_clone = p.app.clone();
                                    let path_clone = p.path.clone();
                                    cx.spawn(async move {
                                        if let Err(e) = set_prompt_choice(&app_clone, &path_clone, "s").await {
                                            eprintln!("Erreur lors du set_choice: {:?}", e);
                                        }
                                    });
                                },
                                "Skip (s)"
                            }
                        }
                    }
                }
            })
        }
    })
}

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
    let env_files = use_state(&cx, || Vec::<AppPolicy>::new());
    let selected_env = use_state(&cx, || String::new());
    let ro_list = use_state(&cx, || Vec::<String>::new());
    let rw_list = use_state(&cx, || Vec::<String>::new());
    let tcp_bind = use_state(&cx, || "9418".to_string());
    let tcp_connect = use_state(&cx, || "80:443".to_string());
    let new_program = use_state(&cx, || String::new());
    let new_program_ro = use_state(&cx, || String::new());
    let new_program_rw = use_state(&cx, || String::new());
    let selected_tab = use_state(&cx, || "rules".to_string());
    let events = use_state(&cx, || Vec::<SandboxEvent>::new());

    // Récupérer la liste des configurations via l'API
    use_future(&cx, (), |_| {
        let env_files = env_files.clone();
        async move {
            match fetch_env_files().await {
                Ok(policies) => env_files.set(policies),
                Err(e) => eprintln!("Erreur lors du fetch des fichiers : {:?}", e),
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
                                }
                            }
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
                            }
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
        Notification {}
    })
}
