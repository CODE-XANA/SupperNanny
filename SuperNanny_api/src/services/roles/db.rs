//! BD – rôles, default policies & permissions.

use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, PooledConnection},
    result::{DatabaseErrorKind, Error as DbErr},
};
use crate::{schema, state::DbPool};

type Conn = PooledConnection<ConnectionManager<PgConnection>>;

fn conn(pool: &DbPool) -> Result<Conn, DbErr> {
    pool.get()
        .map_err(|e| DbErr::DatabaseError(DatabaseErrorKind::Unknown, Box::new(e.to_string())))
}

/* -------------------------------------------------------------------------- */
/*                                 STRUCTURES                                 */
/* -------------------------------------------------------------------------- */

#[derive(Queryable, Identifiable, serde::Serialize)]
#[diesel(table_name = schema::roles, primary_key(role_id))]
pub struct Role {
    pub role_id:   i32,
    pub role_name: String,
}

#[derive(Insertable)]
#[diesel(table_name = schema::roles)]
pub struct NewRole<'a> {
    pub role_name: &'a str,
}

/* ---- default policies ----------------------------------------------------- */

#[derive(Queryable, Identifiable, Associations, serde::Serialize)]
#[diesel(
    table_name = schema::default_policies,
    primary_key(role_id),
    belongs_to(Role)
)]
pub struct DefaultPolicy {
    pub role_id:        i32,
    pub default_ro:     String,
    pub default_rw:     String,
    pub tcp_bind:       String,
    pub tcp_connect:    String,
    pub allowed_ips:    String,
    pub allowed_domains:String,
}

#[derive(Insertable, serde::Deserialize)]
#[diesel(table_name = schema::default_policies)]
pub struct NewDefaultPolicy {
    pub role_id:        i32,
    pub default_ro:     String,
    pub default_rw:     String,
    pub tcp_bind:       String,
    pub tcp_connect:    String,
    pub allowed_ips:    String,
    pub allowed_domains:String,
}

#[derive(serde::Deserialize)]
pub struct DefaultPolicyPatch {
    pub default_ro:     Option<String>,
    pub default_rw:     Option<String>,
    pub tcp_bind:       Option<String>,
    pub tcp_connect:    Option<String>,
    pub allowed_ips:    Option<String>,
    pub allowed_domains:Option<String>,
}

/* -------------------------------------------------------------------------- */
/*                                    CRUD                                    */
/* -------------------------------------------------------------------------- */

pub fn list(pool: &DbPool) -> Result<Vec<Role>, DbErr> {
    use schema::roles::dsl::*;
    roles.load(&mut conn(pool)?)
}

pub fn insert(pool: &DbPool, new: NewRole<'_>) -> Result<i32, DbErr> {
    use schema::roles::dsl::*;
    diesel::insert_into(roles)
        .values(new)
        .returning(role_id)
        .get_result(&mut conn(pool)?)
}

pub fn delete(pool: &DbPool, rid: i32) -> Result<(), DbErr> {
    use schema::roles::dsl::*;
    diesel::delete(roles.filter(role_id.eq(rid))).execute(&mut conn(pool)?)?;
    Ok(())
}

/* ---- default policies ----------------------------------------------------- */

pub fn get_default_policy(pool: &DbPool, rid: i32) -> Result<Option<DefaultPolicy>, DbErr> {
    use schema::default_policies::dsl::*;
    default_policies
        .filter(role_id.eq(rid))
        .first(&mut conn(pool)?)
        .optional()
}

pub fn create_default_policy(pool: &DbPool, new: NewDefaultPolicy) -> Result<(), DbErr> {
    diesel::insert_into(schema::default_policies::table)
        .values(&new)
        .execute(&mut conn(pool)?)?;
    Ok(())
}

pub fn update_default_policy(pool: &DbPool, rid: i32, p: DefaultPolicyPatch) -> Result<(), DbErr> {
    use schema::default_policies::dsl::*;
    diesel::update(default_policies.filter(role_id.eq(rid)))
        .set((
            p.default_ro.map(|v| default_ro.eq(v)),
            p.default_rw.map(|v| default_rw.eq(v)),
            p.tcp_bind.map(|v| tcp_bind.eq(v)),
            p.tcp_connect.map(|v| tcp_connect.eq(v)),
            p.allowed_ips.map(|v| allowed_ips.eq(v)),
            p.allowed_domains.map(|v| allowed_domains.eq(v)),
        ))
        .execute(&mut conn(pool)?)?;
    Ok(())
}

