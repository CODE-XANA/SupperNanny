use anyhow::Result;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::server::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{fs, path::Path};

const CERT_PATH: &str = "certs/dev-cert.pem";
const KEY_PATH:  &str = "certs/dev-key.pem";

pub fn rustls_config() -> Result<ServerConfig> {
    fs::create_dir_all("certs")?;

    // ── charger ou générer ──────────────────────────────────────────────────
    if !Path::new(CERT_PATH).exists() || !Path::new(KEY_PATH).exists() {
        // rcgen 0.13 renvoie maintenant CertifiedKey { cert, key_pair }
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;

        fs::write(CERT_PATH, cert.pem())?;
        fs::write(KEY_PATH,  key_pair.serialize_pem())?;
    }

    // ── PEM → DER ───────────────────────────────────────────────────────────
    let cert_pem = fs::read(CERT_PATH)?;
    let key_pem  = fs::read(KEY_PATH)?;

    let chain: Vec<_> = certs(&mut &*cert_pem)
        .collect::<Result<_, _>>()?;
    let mut keys: Vec<_> = pkcs8_private_keys(&mut &*key_pem)
        .collect::<Result<_, _>>()?; // Vec<PrivatePkcs8KeyDer<'_>>
    let key = keys.pop().expect("private key missing");

    // ── config rustls (TLS 1.3, aucun client-auth) ─────────────────────────
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            chain.into_iter().map(CertificateDer::from).collect(),
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)),
        )?;

    Ok(cfg)
}
