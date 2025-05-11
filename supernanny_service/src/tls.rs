use anyhow::Result;
use rcgen::generate_simple_self_signed;
use rustls::server::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::{fs, path::Path, sync::Arc};

const CERT_PATH: &str = "dev-cert.pem";
const KEY_PATH: &str = "dev-key.pem";

pub fn generate_self_signed_cert() -> Result<Arc<ServerConfig>> {
    let (cert_pem, key_pem) = if Path::new(CERT_PATH).exists() && Path::new(KEY_PATH).exists() {
        let cert_pem = fs::read_to_string(CERT_PATH)?;
        let key_pem = fs::read_to_string(KEY_PATH)?;
        (cert_pem, key_pem)
    } else {
        let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
        let certified_key = generate_simple_self_signed(subject_alt_names)?;

        let cert_pem = certified_key.cert.pem();
        let key_pem = certified_key.key_pair.serialize_pem();

        fs::write(CERT_PATH, &cert_pem)?;
        fs::write(KEY_PATH, &key_pem)?;

        (cert_pem, key_pem)
    };

    let cert_der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to parse certificate"))??;

    let key_der = rustls_pemfile::pkcs8_private_keys(&mut key_pem.as_bytes())
        .next()
        .ok_or_else(|| anyhow::anyhow!("Failed to parse private key"))??;

    let cert_chain = vec![CertificateDer::from(cert_der)];
    let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;

    Ok(Arc::new(tls_config))
}
