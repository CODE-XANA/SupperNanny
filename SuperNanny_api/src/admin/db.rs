use anyhow::Result;
use diesel::{
    prelude::*,
    r2d2::{ConnectionManager, PooledConnection},
    result::{DatabaseErrorKind, Error as DbErr},
};

use crate::{
    schema::{user_admin, permission_admin, role_permissions_admin},
    state::DbPool,
};

#[allow(dead_code)]
#[derive(Queryable)]
pub struct Admin {
    pub user_admin_id: i32,
    pub username_admin: String,
    pub password_hash_admin: String,
}

type Conn = PooledConnection<ConnectionManager<PgConnection>>;

fn conn(pool: &DbPool) -> Result<Conn, DbErr> {
    pool.get().map_err(|e| {
        DbErr::DatabaseError(DatabaseErrorKind::Unknown, Box::new(e.to_string()))
    })
}

/// Renvoie l’admin + toutes ses permissions.
pub fn get_admin_with_perms(pool: &DbPool, username: &str) -> Result<Option<(Admin, Vec<String>)>> {
    let mut conn = pool.get()?;

    let admin: Admin = match user_admin::table
        .filter(user_admin::username_admin.eq(username))
        .first(&mut conn)
        .optional()?
    {
        Some(a) => a,
        None => return Ok(None),
    };

    let perms: Vec<String> = permission_admin::table
        .inner_join(role_permissions_admin::table.on(
            permission_admin::permission_admin_id.eq(role_permissions_admin::permission_admin_id),
        ))
        .filter(role_permissions_admin::user_admin_id.eq(admin.user_admin_id))
        .select(permission_admin::permission_admin_name)
        .load(&mut conn)?;

    Ok(Some((admin, perms)))
}

pub fn get_admin_username(pool: &DbPool, admin_id: i32) -> Result<Option<String>, DbErr> {
    use crate::schema::user_admin::dsl::{user_admin, user_admin_id, username_admin};

    user_admin
        .select(username_admin)
        .filter(user_admin_id.eq(admin_id))
        .first::<String>(&mut conn(pool)?)
        .optional()
}