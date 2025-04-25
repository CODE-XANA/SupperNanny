use diesel::prelude::*;

use crate::schema::security_logs;

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
    pub username:  Option<&'a str>,
    pub ip_address: Option<&'a str>,
    pub action:   &'a str,
    pub detail:   Option<&'a str>,
    pub severity: &'a str,
}