use anyhow::Result;
use chrono::Utc;
use diesel::prelude::*;

use crate::{
    schema::security_logs,
    state::DbPool,
};

// ─── Structs Diesel ─────────────────────────────────────────────────────────

#[derive(Queryable, serde::Serialize)]
pub struct LogEntry {
    pub log_id: i32,
    pub timestamp: chrono::NaiveDateTime,
    pub username: Option<String>,
    pub ip_address: Option<String>,
    pub action: String,
    pub detail: Option<String>,
    pub severity: String,
}

#[derive(Insertable)]
#[diesel(table_name = security_logs)]
pub struct NewLogEntry<'a> {
    pub timestamp:  chrono::NaiveDateTime,
    pub username:   Option<&'a str>,
    pub ip_address: Option<&'a str>,
    pub action:     &'a str,
    pub detail:     Option<&'a str>,
    pub severity:   &'a str,
}

// ─── Helper interne ────────────────────────────────────────────────────────

fn conn(pool: &DbPool) -> Result<diesel::r2d2::PooledConnection<
    diesel::r2d2::ConnectionManager<diesel::PgConnection>>> {
    Ok(pool.get()?)
}

// ─── API public ────────────────────────────────────────────────────────────

/// Insère une ligne dans security_logs.
pub fn insert(
    pool:        &DbPool,
    username:    Option<&str>,
    ip_address:  Option<&str>,
    action:      &str,
    detail:      Option<&str>,
    severity:    &str,
) -> Result<()> {
    let entry = NewLogEntry {
        timestamp:  Utc::now().naive_utc(),
        username,
        ip_address,
        action,
        detail,
        severity,
    };

    diesel::insert_into(security_logs::table)
        .values(&entry)
        .execute(&mut conn(pool)?)?;

    Ok(())
}

/// Renvoie les 10 derniers évènements (ordre DESC).
pub fn last_10(pool: &DbPool) -> Result<Vec<LogEntry>> {
    use crate::schema::security_logs::dsl::*;
    Ok(security_logs
        .order(timestamp.desc())
        .limit(10)
        .load::<LogEntry>(&mut conn(pool)?)?)
}