use anyhow::Result;
use diesel::prelude::*;

use crate::{
    schema::{roles, user_roles, role_permissions, permissions},
    state::DbPool,
};

#[derive(Queryable, serde::Serialize)]
pub struct Role { pub role_id: i32, pub role_name: String }

#[derive(Insertable)]
#[diesel(table_name = roles)]
pub struct NewRole<'a> { pub role_name: &'a str }

#[derive(Queryable, serde::Serialize)]
pub struct Permission { pub permission_id: i32, pub permission_name: String }

#[derive(Insertable)]
#[diesel(table_name = permissions)]
pub struct NewPermission<'a> { pub permission_name: &'a str }

// ------------------------------------------------------------------ roles --

pub fn list(pool: &DbPool) -> Result<Vec<Role>> {
    let mut conn = pool.get()?;
    Ok(roles::table.load::<Role>(&mut conn)?)
}

pub fn insert(pool: &DbPool, role: NewRole) -> Result<()> {
    let mut conn = pool.get()?;
    diesel::insert_into(roles::table).values(&role).execute(&mut conn)?;
    Ok(())
}

pub fn delete(pool: &DbPool, id: i32) -> Result<()> {
    let mut conn = pool.get()?;
    diesel::delete(roles::table.filter(roles::role_id.eq(id))).execute(&mut conn)?;
    Ok(())
}

// ------------------------------------------------------------- user_roles --

pub fn assign_role(pool: &DbPool, uid: i32, rid: i32) -> Result<()> {
    let mut conn = pool.get()?;
    diesel::insert_into(user_roles::table)
        .values(&(user_roles::user_id.eq(uid), user_roles::role_id.eq(rid)))
        .on_conflict(user_roles::user_id)
        .do_update()
        .set(user_roles::role_id.eq(rid))
        .execute(&mut conn)?;
    Ok(())
}

pub fn remove_role(pool: &DbPool, uid: i32, rid: i32) -> Result<()> {
    let mut conn = pool.get()?;
    diesel::delete(
        user_roles::table
            .filter(user_roles::user_id.eq(uid))
            .filter(user_roles::role_id.eq(rid)),
    )
    .execute(&mut conn)?;
    Ok(())
}

pub fn roles_of_user(pool: &DbPool, uid: i32) -> Result<Vec<Role>> {
    let mut conn = pool.get()?;
    Ok(roles::table
        .inner_join(user_roles::table.on(roles::role_id.eq(user_roles::role_id)))
        .filter(user_roles::user_id.eq(uid))
        .select((roles::role_id, roles::role_name))
        .load::<Role>(&mut conn)?)
}

// -------------------------------------------------------- role_permissions --

pub fn assign_permission(pool: &DbPool, rid: i32, pid: i32) -> Result<()> {
    let mut conn = pool.get()?;
    diesel::insert_into(role_permissions::table)
        .values(&(role_permissions::role_id.eq(rid), role_permissions::permission_id.eq(pid)))
        .on_conflict_do_nothing()
        .execute(&mut conn)?;
    Ok(())
}

pub fn remove_permission(pool: &DbPool, rid: i32, pid: i32) -> Result<()> {
    let mut conn = pool.get()?;
    diesel::delete(
        role_permissions::table
            .filter(role_permissions::role_id.eq(rid))
            .filter(role_permissions::permission_id.eq(pid)),
    )
    .execute(&mut conn)?;
    Ok(())
}

pub fn permissions_of_role(pool: &DbPool, rid: i32) -> Result<Vec<Permission>> {
    let mut conn = pool.get()?;
    Ok(permissions::table
        .inner_join(role_permissions::table.on(permissions::permission_id.eq(role_permissions::permission_id)))
        .filter(role_permissions::role_id.eq(rid))
        .select((permissions::permission_id, permissions::permission_name))
        .load::<Permission>(&mut conn)?)
}
