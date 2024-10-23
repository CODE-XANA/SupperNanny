extern crate libc;
use libc::{c_char, c_int};
use std::ffi::{CStr, CString};
use std::fs::OpenOptions;
use std::io::Write;
use gtk::{Dialog, DialogFlags, Label, Window};
use gtk::prelude::*;

#[no_mangle]
pub extern "C" fn execve(
    filename: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char
) -> c_int {
    unsafe {
        // Obtenir la version originale de l'appel execve via dlsym
        let orig_execve: unsafe extern "C" fn(*const c_char, *const *const c_char, *const *const c_char) -> c_int =
            std::mem::transmute(libc::dlsym(libc::RTLD_NEXT, CString::new("execve").unwrap().as_ptr()));

        // Récupérer le nom du programme exécuté pour la journalisation
        let program_name = CStr::from_ptr(filename).to_str().unwrap_or("Programme inconnu");

        // Écrire un message de log chaque fois que SuperNanny intercepte une commande
        let mut log_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("/var/log/supernanny.log")
            .expect("Impossible d'ouvrir le fichier de log");

        writeln!(log_file, "SuperNanny a intercepté : {}", program_name)
            .expect("Impossible d'écrire dans le fichier de log");

        // Appel de la fonction pour afficher une boîte de dialogue GTK demandant l'autorisation
        let permission_granted = show_permission_dialog(filename);

        // Si l'utilisateur refuse l'accès, retour d'une erreur
        if !permission_granted {
            println!("Accès refusé à {}", program_name);
            return -1; // Refuse l'exécution si l'utilisateur refuse
        }

        // Exécuter le programme original
        return orig_execve(filename, argv, envp);
    }
}

// Fonction pour afficher une boîte de dialogue demandant l'autorisation à l'utilisateur
fn show_permission_dialog(file: *const c_char) -> bool {
    // Initialiser GTK
    gtk::init().expect("Impossible d'initialiser GTK");

    // Créer une boîte de dialogue demandant l'autorisation
    let dialog = Dialog::with_buttons(
        Some("SuperNanny : Autoriser l'accès au fichier ?"),
        None::<&Window>,
        DialogFlags::MODAL,
        &[("Autoriser", gtk::ResponseType::Yes), ("Refuser", gtk::ResponseType::No)],
    );

    // Récupérer le conteneur de contenu (conteneur de la boîte de dialogue)
    let content_area = dialog.get_content_area();

    // Ajouter le label au conteneur de contenu
    let label = Label::new(Some(
        format!(
            "Un programme tente d'accéder au fichier : {}",
            unsafe { CStr::from_ptr(file).to_str().unwrap() }
        )
        .as_str(),
    ));
    content_area.pack_start(&label, true, true, 0);
    label.show();

    // Récupérer la réponse de l'utilisateur
    let response = dialog.run();
    dialog.close();

    match response {
        gtk::ResponseType::Yes => true, // Autoriser
        gtk::ResponseType::No => false, // Refuser
        _ => false, // Refuser par défaut en cas d'erreur
    }
}

fn main() {
    // Point d'entrée du programme
    println!("Bienvenue dans SuperNanny !");
}