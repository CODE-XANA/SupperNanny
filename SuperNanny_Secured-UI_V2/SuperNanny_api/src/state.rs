//! Contient uniquement le pool Diesel + éventuellement le brute-force map.

use chrono::Utc;
use diesel::{pg::PgConnection, r2d2};
use once_cell::sync::Lazy;
use rand::{rngs::OsRng, RngCore};
use std::{
    collections::HashMap,
    sync::Mutex,
};

pub type DbPool = r2d2::Pool<r2d2::ConnectionManager<PgConnection>>;

/// Limiteur de brute-force pour /admin/login
pub static LOGIN_ATTEMPTS: Lazy<Mutex<HashMap<String, (u32, i64)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
}

impl AppState {
    pub fn new(db: DbPool) -> Self { Self { db } }
}

#[inline] pub fn now() -> i64 { Utc::now().timestamp() }

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}
