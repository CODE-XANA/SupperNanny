use dioxus::prelude::*;
use dioxus_desktop::{Config, LogicalSize, launch_with_props, WindowBuilder};
use reqwest;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

/* ==================== Fonctions d'appel API (env files) =================== */

async fn fetch_env_files() -> Result<Vec<String>, reqwest::Error> {
    let client = reqwest::Client::new();
    let response = client
        .get("http://127.0.0.1:8080/envs")
        .send()
        .await?
        .error_for_status()?;
    let files: Vec<String> = response.json().await?;
    Ok(files)
}

async fn fetch_env_content(program: &str) -> Result<String, reqwest::Error> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:8080/env/{}", program);
    let response = client.get(&url).send().await?.error_for_status()?;
    let content = response.text().await?;
    Ok(content)
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
    ll_fs_ro: String,
    ll_fs_rw: String,
    tcp_bind: String,
    tcp_connect: String,
) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    let url = "http://127.0.0.1:8080/env";
    let payload = json!({
        "program": program,
        "ll_fs_ro": ll_fs_ro,
        "ll_fs_rw": ll_fs_rw,
        "ll_tcp_bind": tcp_bind,
        "ll_tcp_connect": tcp_connect,
    });
    client.post(url).json(&payload).send().await?.error_for_status()?;
    Ok(())
}


/* ========================================================================== */



/* ================= Fonctions d'appel API (script prompts) ================= */

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

/* ========================================================================== */



/* ==================== Composant Notification (Frontend) =================== */

fn Notification(cx: Scope) -> Element {
    let pending_prompts = use_state(&cx, || Vec::<PendingPrompt>::new());

    // Polling toutes les 5 secondes pour récupérer les prompts en attente.
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

/* ========================================================================== */



/* ========================== Application Frontend ========================== */

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
    let env_files = use_state(&cx, || Vec::<String>::new());
    let selected_env = use_state(&cx, || String::new());
    let ro_list = use_state(&cx, || Vec::<String>::new());
    let rw_list = use_state(&cx, || Vec::<String>::new());
    let new_ro_item = use_state(&cx, || String::new());
    let new_rw_item = use_state(&cx, || String::new());
    let tcp_bind = use_state(&cx, || "9418".to_string());
    let tcp_connect = use_state(&cx, || "80:443".to_string());
    let new_program = use_state(&cx, || String::new());
    let new_program_ro = use_state(&cx, || String::new());
    let new_program_rw = use_state(&cx, || String::new());

    use_future(&cx, (), |_| {
        let env_files = env_files.clone();
        async move {
            match fetch_env_files().await {
                Ok(files) => env_files.set(files),
                Err(e) => eprintln!("Erreur lors du fetch des fichiers : {:?}", e),
            }
        }
    });

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
                Ok(content) => {
                    let mut ro = String::new();
                    let mut rw = String::new();
                    for line in content.lines() {
                        if line.starts_with("export LL_FS_RO=") {
                            if let Some(start) = line.find('"') {
                                if let Some(end) = line[start + 1..].find('"') {
                                    ro = line[start + 1..start + 1 + end].to_string();
                                }
                            }
                        } else if line.starts_with("export LL_FS_RW=") {
                            if let Some(start) = line.find('"') {
                                if let Some(end) = line[start + 1..].find('"') {
                                    rw = line[start + 1..start + 1 + end].to_string();
                                }
                            }
                        } else if line.starts_with("export LL_TCP_BIND=") {
                            if let Some(start) = line.find('"') {
                                if let Some(end) = line[start + 1..].find('"') {
                                    tcp_bind.set(line[start + 1..start + 1 + end].to_string());
                                }
                            }
                        } else if line.starts_with("export LL_TCP_CONNECT=") {
                            if let Some(start) = line.find('"') {
                                if let Some(end) = line[start + 1..].find('"') {
                                    tcp_connect.set(line[start + 1..start + 1 + end].to_string());
                                }
                            }
                        }
                    }
                    ro_list.set(
                        ro.split(':')
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect(),
                    );
                    rw_list.set(
                        rw.split(':')
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect(),
                    );
                }
                Err(e) => eprintln!("Erreur lors du fetch du contenu : {:?}", e),
            }
        }
    });

    cx.render(rsx! {
        link {
            rel: "stylesheet",
            href: "assets/styles.css",
        }
        div { class: "main-container",
            div { class: "left-column",
                div {
                    class: "left-header",
                    style: "display: flex; align-items: center; gap: 8px;",
                    h2 { "Fichiers de règles" }
                    button {
                        class: "refresh-btn",
                        title: "Refresh",
                        onclick: move |_| {
                            let env_files = env_files.clone();
                            cx.spawn(async move {
                                match fetch_env_files().await {
                                    Ok(files) => env_files.set(files),
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
                                path {
                                    d: "M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6s-2.69 6-6 6a5.99 5.99 0 0 1-5.2-3H4.35A8 8 0 0 0 12 20c4.41 0 8-3.59 8-8s-3.59-8-8-8z"
                                }
                            }
                        }
                    }
                }
                ul {
                    env_files.get().iter().map(|file| {
                        let file = file.clone();
                        rsx! {
                            li {
                                onclick: move |_| {
                                    selected_env.set(file.clone());
                                },
                                "{file}"
                            }
                        }
                    })
                }
                h3 { "Créer un nouveau fichier" }
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
                                    println!("Fichier créé");
                                    match fetch_env_files().await {
                                        Ok(files) => env_files.set(files),
                                        Err(e) => eprintln!("Erreur lors du fetch après création : {:?}", e),
                                    }
                                },
                                Err(e) => eprintln!("Erreur lors de la création : {:?}", e),
                            }
                        });
                    },
                    "Créer le fichier"
                }
            }
            div { class: "middle-column",
            (if !selected_env.get().is_empty() {
                rsx! {
                    // Titre avec icônes
                    h2 {
                        style: "display: flex; justify-content: space-between; align-items: center;",
                        // Titre à gauche
                        span { "Éditer: {selected_env}" },
                        // Icônes à droite
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
                                            Ok(content) => {
                                                let mut ro = String::new();
                                                let mut rw = String::new();
                                                for line in content.lines() {
                                                    if line.starts_with("export LL_FS_RO=") {
                                                        if let Some(start) = line.find('"') {
                                                            if let Some(end) = line[start + 1..].find('"') {
                                                                ro = line[start + 1..start + 1 + end].to_string();
                                                            }
                                                        }
                                                    } else if line.starts_with("export LL_FS_RW=") {
                                                        if let Some(start) = line.find('"') {
                                                            if let Some(end) = line[start + 1..].find('"') {
                                                                rw = line[start + 1..start + 1 + end].to_string();
                                                            }
                                                        }
                                                    } else if line.starts_with("export LL_TCP_BIND=") {
                                                        if let Some(start) = line.find('"') {
                                                            if let Some(end) = line[start + 1..].find('"') {
                                                                tcp_bind.set(line[start + 1..start + 1 + end].to_string());
                                                            }
                                                        }
                                                    } else if line.starts_with("export LL_TCP_CONNECT=") {
                                                        if let Some(start) = line.find('"') {
                                                            if let Some(end) = line[start + 1..].find('"') {
                                                                tcp_connect.set(line[start + 1..start + 1 + end].to_string());
                                                            }
                                                        }
                                                    }
                                                }
                                                ro_list.set(
                                                    ro.split(':')
                                                      .filter(|s| !s.is_empty())
                                                      .map(|s| s.to_string())
                                                      .collect()
                                                );
                                                rw_list.set(
                                                    rw.split(':')
                                                      .filter(|s| !s.is_empty())
                                                      .map(|s| s.to_string())
                                                      .collect()
                                                );
                                            }
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
                                        path {
                                            d: "M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6s-2.69 6-6 6a5.99 5.99 0 0 1-5.2-3H4.35A8 8 0 0 0 12 20c4.41 0 8-3.59 8-8s-3.59-8-8-8z"
                                        }
                                    }
                                }
                            }
                            // Bouton Check pour valider (mise à jour)
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
                                        path {
                                            d: "M9 16.17l-4.17-4.17-1.42 1.41L9 19l10.59-10.59-1.42-1.41z"
                                        }
                                    }
                                }
                            }
                            // Bouton Poubelle pour supprimer le fichier
                            button {
                                class: "icon-button delete-button",
                                title: "Supprimer le fichier",
                                onclick: move |_| {
                                    let program = selected_env.get().clone();
                                    let env_files = env_files.clone();
                                    let selected_env = selected_env.clone();
                                    cx.spawn(async move {
                                        match delete_env(&program).await {
                                            Ok(_) => {
                                                println!("Fichier supprimé");
                                                match fetch_env_files().await {
                                                    Ok(files) => {
                                                        env_files.set(files);
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
                                        width: "20",
                                        height: "20",
                                        path {
                                            d: "M3 6l3 18h12l3-18H3zm18-2H3V2h5.5l1-1h5l1 1H21v2z"
                                        }
                                    }
                                }
                            }
                        }
                    }                    

                    // Section LL_FS_RO
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
                        input {
                            placeholder: "Ajouter chemin (RO)",
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
                            "Ajouter"
                        }
                    }

                    // Section LL_FS_RW
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
                        input {
                            placeholder: "Ajouter chemin (RW)",
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
                            "Ajouter"
                        }
                    }

                    // Boutons en bas (optionnels, si vous voulez les conserver)
                    button {
                        class: "submit-btn",
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
                        "Mettre à jour"
                    }
                    button {
                        class: "del-btn",
                        onclick: move |_| {
                            let program = selected_env.get().clone();
                            let env_files = env_files.clone();
                            let selected_env = selected_env.clone();
                            cx.spawn(async move {
                                match delete_env(&program).await {
                                    Ok(_) => {
                                        println!("Fichier supprimé");
                                        match fetch_env_files().await {
                                            Ok(files) => {
                                                env_files.set(files);
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
                        "Supprimer le fichier"
                    }
                }
            } else {
                rsx! { div { "Sélectionnez un fichier pour l'éditer" } }
            })
        }
            div { class: "right-column",
                h2 { "Résumé" }
                (if !selected_env.get().is_empty() {
                    rsx! {
                        p { "Fichier sélectionné: {selected_env}" }
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
        // Zone de notification pour les prompts du script
        Notification {}
    })
}

/* ========================================================================== */