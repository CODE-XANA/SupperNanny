use actix_files::{Files, NamedFile};
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Result};
use once_cell::sync::Lazy;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::ServerConfig,
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{fs::File, io::BufReader, path::Path};

/* ---------- TLS auto‑signé dev ------------------------------------------ */
fn build_tls_config() -> ServerConfig {
    let cert_path = Path::new("certs/dev-cert.pem");
    let key_path  = Path::new("certs/dev-key.pem");

    // certificat
    let mut r = BufReader::new(File::open(cert_path).expect("open cert"));
    let certs: Vec<CertificateDer<'static>> =
        certs(&mut r).collect::<Result<_, _>>().expect("parse cert");

    // clé privée
    let mut r = BufReader::new(File::open(key_path).expect("open key"));
    let key: PrivatePkcs8KeyDer<'static> = pkcs8_private_keys(&mut r)
        .next()
        .expect("one key")            // Option
        .expect("valid pkcs8 key");   // Result

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, PrivateKeyDer::Pkcs8(key))
        .expect("TLS config")
}
static TLS_CFG: Lazy<ServerConfig> = Lazy::new(build_tls_config);

/* ---------- Fallback SPA (index.html) ----------------------------------- */
async fn spa_fallback(req: HttpRequest) -> Result<HttpResponse> {
    Ok(NamedFile::open("../frontend/dist/index.html")?.into_response(&req))
}

/* ---------- main -------------------------------------------------------- */
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // dossier généré par `trunk build`
    let dist_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../frontend/dist");
    println!("Serving static files from {}", dist_dir.display());

    HttpServer::new(move || {
        App::new()
            .service(
                Files::new("/", &dist_dir)
                    .index_file("index.html"),
            )
            .default_service(web::to(spa_fallback))
    })
    .bind_rustls_0_23(("0.0.0.0", 8444), TLS_CFG.clone())?
    .run()
    .await
}
