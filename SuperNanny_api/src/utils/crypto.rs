use crate::state::random_bytes;
use base64::{engine::general_purpose::STANDARD, Engine};

pub fn random_base64<const N: usize>() -> String {
    STANDARD.encode(random_bytes::<N>())
}