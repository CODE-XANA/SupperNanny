//! State global de l’API.
//!
//! * pool Diesel partagé (`AppState::db`)
//! * helpers (random_bytes, now)
//! * caches/métriques en mémoire (anti-bruteforce, rate-limit, blacklist)

use chrono::Utc;
use diesel::{pg::PgConnection, r2d2};
use once_cell::sync::Lazy;
use rand::RngCore;
use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
};

// ---------------------------------------------------------------------------
// Type alias pour le pool Diesel
// ---------------------------------------------------------------------------

pub type DbPool = r2d2::Pool<r2d2::ConnectionManager<PgConnection>>;

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
}

impl AppState {
    pub fn new(db: DbPool) -> Self { Self { db } }
}

// ---------------------------------------------------------------------------
// Helpers génériques
// ---------------------------------------------------------------------------

#[inline] pub fn now() -> i64 { Utc::now().timestamp() }

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

// ---------------------------------------------------------------------------
// Anti-bruteforce / rate-limit
// ---------------------------------------------------------------------------

/// Clé : IP → (compteur, deadline_unix)
pub static LOGIN_ATTEMPTS: Lazy<Mutex<HashMap<String, (u32, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Rate-limit global (ex. 100 req / min / IP)
pub static RATE_LIMIT: Lazy<Mutex<HashMap<String, (u32, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// ---------------------------------------------------------------------------
// Blacklist de JWT (optionnel)
// ---------------------------------------------------------------------------

/// Liste des « jti » révoqués / tokens invalidés avant leur expiry.
pub static JWT_BLACKLIST: Lazy<Mutex<HashSet<String>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));