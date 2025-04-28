//! BD – utilisateurs & rôles associés.

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
#[diesel(table_name = schema::users, primary_key(user_id))]
pub struct User {
    pub user_id:       i32,
    pub username:      String,
    pub password_hash: String,
}

#[derive(Insertable)]
#[diesel(table_name = schema::users)]
pub struct NewUser<'a> {
    pub username:      &'a str,
    pub password_hash: &'a str,
}

#[derive(Queryable, serde::Serialize)]
#[diesel(table_name = schema::roles, primary_key(role_id))]
pub struct Role {
    pub role_id:   i32,
    pub role_name: String,
}

/* -------------------------------------------------------------------------- */
/*                                    CRUD                                    */
/* -------------------------------------------------------------------------- */

pub fn list(pool: &DbPool) -> Result<Vec<User>, DbErr> {
    use schema::users::dsl::*;
    users.load(&mut conn(pool)?)
}

pub fn insert_returning_id(pool: &DbPool, new: NewUser<'_>) -> Result<i32, DbErr> {
    use schema::users::dsl::*;
    diesel::insert_into(users)
        .values(new)
        .returning(user_id)
        .get_result(&mut conn(pool)?)
}

pub fn delete(pool: &DbPool, uid: i32) -> Result<(), DbErr> {
    use schema::users::dsl::*;
    diesel::delete(users.filter(user_id.eq(uid))).execute(&mut conn(pool)?)?;
    Ok(())
}

/* -------------- rôles d’un utilisateur ------------------------------------ */

pub fn assign_role(pool: &DbPool, uid: i32, rid: i32) -> Result<(), DbErr> {
    use schema::user_roles::dsl::*;
    diesel::insert_into(schema::user_roles::table)
        .values((user_id.eq(uid), role_id.eq(rid)))
        .execute(&mut conn(pool)?)?;
    Ok(())
}

pub fn roles_of_user(pool: &DbPool, uid: i32) -> Result<Vec<Role>, DbErr> {
    use schema::{roles, user_roles};

    roles::table
        .inner_join(user_roles::table.on(user_roles::role_id.eq(roles::role_id)))
        .filter(user_roles::user_id.eq(uid))
        .select((roles::role_id, roles::role_name))
        .load(&mut conn(pool)?)
}

/* -------------- catalogue de tous les rôles ------------------------------- */

pub fn all_roles(pool: &DbPool) -> Result<Vec<Role>, DbErr> {
    use schema::roles::dsl::*;
    roles.load(&mut conn(pool)?)
}
