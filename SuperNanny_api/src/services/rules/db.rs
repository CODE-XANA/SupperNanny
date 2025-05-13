use anyhow::Result;
use chrono::NaiveDateTime;
use diesel::prelude::*;

use crate::{
    schema::{default_policies, app_policy, roles},
    state::DbPool,
};


/// ---- rôle simple -------------------------------------------------------

#[derive(Queryable, serde::Serialize)]
#[diesel(table_name = roles, primary_key(role_id))]
pub struct Role {
    pub role_id:   i32,
    pub role_name: String,
}

/// Liste tous les rôles
pub fn list_roles(pool: &DbPool) -> Result<Vec<Role>> {
    let mut conn = pool.get()?;
    Ok(roles::table.load::<Role>(&mut conn)?)
}


// ---------------- default_policies ----------------------------------------

#[derive(Queryable, serde::Serialize)]
pub struct DefaultPolicy {
    pub role_id: i32,
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
    pub allowed_ips: String,
    pub allowed_domains: String,
}

#[derive(Insertable)]
#[diesel(table_name = default_policies)]
pub struct NewDefaultPolicy<'a> {
    pub role_id: i32,
    pub default_ro: &'a str,
    pub default_rw: &'a str,
    pub tcp_bind: &'a str,
    pub tcp_connect: &'a str,
    pub allowed_ips: &'a str,
    pub allowed_domains: &'a str,
}

#[derive(AsChangeset)]
#[diesel(table_name = default_policies)]
pub struct DefaultPolicyChangeset<'a> {
    pub default_ro:      Option<&'a str>,
    pub default_rw:      Option<&'a str>,
    pub tcp_bind:        Option<&'a str>,
    pub tcp_connect:     Option<&'a str>,
    pub allowed_ips:     Option<&'a str>,
    pub allowed_domains: Option<&'a str>,
}

// ---------------- app_policy ----------------------------------------------

#[derive(Queryable, serde::Serialize)]
pub struct AppPolicy {
    pub policy_id: i32,
    pub app_name: String,
    pub role_id: i32,
    pub default_ro: String,
    pub default_rw: String,
    pub tcp_bind: String,
    pub tcp_connect: String,
    pub allowed_ips: String,
    pub allowed_domains: String,
    pub updated_at: NaiveDateTime,
}

#[derive(Insertable)]
#[diesel(table_name = app_policy)]
pub struct NewAppPolicy<'a> {
    pub app_name: &'a str,
    pub role_id: i32,
    pub default_ro: &'a str,
    pub default_rw: &'a str,
    pub tcp_bind: &'a str,
    pub tcp_connect: &'a str,
    pub allowed_ips: &'a str,
    pub allowed_domains: &'a str,
}

pub fn list_envs(pool: &DbPool) -> Result<Vec<AppPolicy>> {
    let mut conn = pool.get()?;
    Ok(app_policy::table.load::<AppPolicy>(&mut conn)?)
}

pub fn by_name(pool: &DbPool, name: &str) -> Result<Option<AppPolicy>> {
    let mut conn = pool.get()?;
    Ok(app_policy::table.filter(app_policy::app_name.eq(name)).first::<AppPolicy>(&mut conn).optional()?)
}

pub fn by_id(pool: &DbPool, pid: i32) -> Result<Option<AppPolicy>> {
    let mut conn = pool.get()?;
    Ok(app_policy::table.filter(app_policy::policy_id.eq(pid)).first::<AppPolicy>(&mut conn).optional()?)
}

pub fn insert_env(pool: &DbPool, p: NewAppPolicy) -> Result<()> {
    let mut conn = pool.get()?;
    diesel::insert_into(app_policy::table).values(&p).execute(&mut conn)?;
    Ok(())
}

pub fn update_env(
    pool: &DbPool,
    pid: i32,
    ro: &str,
    rw: &str,
    bind: &str,
    conn_tcp: &str,
    ips: &str,
    domains: &str,
) -> Result<()> {
    let mut conn = pool.get()?;
    diesel::update(app_policy::table.filter(app_policy::policy_id.eq(pid)))
        .set((
            app_policy::default_ro.eq(ro),
            app_policy::default_rw.eq(rw),
            app_policy::tcp_bind.eq(bind),
            app_policy::tcp_connect.eq(conn_tcp),
            app_policy::allowed_ips.eq(ips),
            app_policy::allowed_domains.eq(domains),
            app_policy::updated_at.eq(chrono::Utc::now().naive_utc()),
        ))
        .execute(&mut conn)?;
    Ok(())
}

pub fn delete_env(pool: &DbPool, pid: i32) -> Result<bool> {
    let mut conn = pool.get()?;
    Ok(diesel::delete(app_policy::table.filter(app_policy::policy_id.eq(pid)))
        .execute(&mut conn)? > 0)
}
