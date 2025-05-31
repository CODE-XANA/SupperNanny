// src/bin/ebpf_interceptor.rs

use anyhow::Result;
use ebpf_service::integration;
use tracing::info;
use tracing_subscriber;

/// Point d’entrée du binaire eBPF interceptor.
///
/// Charge le programme BPF, démarre la lecture des events
/// et tourne jusqu’à Ctrl-C.
#[tokio::main]
async fn main() -> Result<()> {
    ebpf_service::ebpf::user::event::print_event_size();

    // Initialise le logger via tracing_subscriber
    tracing_subscriber::fmt::init();

    info!("🛡️  Démarrage de l’intercepteur eBPF SuperNanny…");
    integration::run().await?;
    info!("👋  Arrêt de l’intercepteur eBPF.");

    Ok(())
}
