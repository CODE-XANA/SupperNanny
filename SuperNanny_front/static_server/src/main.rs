use actix_files::Files;
use actix_web::{App, HttpServer};
use once_cell::sync::Lazy;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::ServerConfig,
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{fs::File, io::BufReader, path::Path};

fn build_tls_config() -> ServerConfig {
    let cert_path = Path::new("certs/dev-cert.pem");
    let key_path = Path::new("certs/dev-key.pem");
    // ---- cert --------------------------------------------------------------
    let mut r = BufReader::new(File::open(cert_path).expect("cert"));
    let certs: Vec<CertificateDer<'static>> =
        certs(&mut r).collect::<Result<_, _>>().expect("parse cert");
    // ---- key --------------------------------------------------------------
    let mut r = BufReader::new(File::open(key_path).expect("key"));
    let key: PrivatePkcs8KeyDer<'static> =
        pkcs8_private_keys(&mut r)
            .next()
            .expect("one key") // Result<Option<…>>
            .expect("valid pkcs8 key"); // Result<…>
    // conversion explicite
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, PrivateKeyDer::Pkcs8(key))
        .expect("cfg")
}

static TLS_CFG: Lazy<ServerConfig> = Lazy::new(build_tls_config);

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("➡ Frontend : https://127.0.0.1:8444");
    HttpServer::new(|| {
        App::new().service(
            Files::new("/", "../frontend/dist")
                .index_file("index.html")
                .prefer_utf8(true),
        )
    })
    .bind_rustls_0_23(("0.0.0.0", 8444), TLS_CFG.clone())?
    .run()
    .await
}