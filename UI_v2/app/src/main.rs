use dioxus::prelude::*;
use dioxus_desktop::{Config, LogicalSize, launch_with_props, WindowBuilder};
use reqwest;
use serde_json::json;

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
    // États pour la gestion des fichiers .env et autres données
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

    // Charger la liste des fichiers au montage
    use_future(&cx, (), |_| {
        let env_files = env_files.clone();
        async move {
            match fetch_env_files().await {
                Ok(files) => env_files.set(files),
                Err(e) => eprintln!("Erreur lors du fetch des fichiers : {:?}", e),
            }
        }
    });

    // Charger le contenu du fichier lorsque la sélection change
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
            // Colonne de gauche : liste des fichiers, refresh, création et suppression
            div { class: "left-column",
                h2 { "Fichiers de règles" }
                button {
                    class: "submit-btn",
                    onclick: move |_| {
                        let env_files = env_files.clone();
                        cx.spawn(async move {
                            match fetch_env_files().await {
                                Ok(files) => env_files.set(files),
                                Err(e) => eprintln!("Erreur lors du fetch (refresh) : {:?}", e),
                            }
                        });
                    },
                    "Refresh"
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
                                    // Recharger la liste après création
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
                button {
                    class: "submit-btn",
                    onclick: move |_| {
                        let program = new_program.get().clone();
                        if program.is_empty() {
                            eprintln!("Entrez un nom pour supprimer un fichier");
                            return;
                        }
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
                    "Supprimer le fichier (par nom)"
                }
            }
            // Colonne centrale : édition du fichier sélectionné
            div { class: "middle-column",
                (if !selected_env.get().is_empty() {
                    rsx! {
                        h2 { "Éditer: {selected_env}" }
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
                            class: "submit-btn",
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
            // Colonne de droite : résumé des informations
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
    })
}

// ----- Fonctions d'appel API -----

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
