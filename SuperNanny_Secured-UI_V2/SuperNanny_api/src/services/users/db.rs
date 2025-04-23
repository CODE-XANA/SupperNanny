use diesel::prelude::*;
use anyhow::Result;

use crate::{schema, state::DbPool};
use crate::schema::users;

#[derive(Queryable, serde::Serialize)]
pub struct User {
    pub user_id: i32,
    pub username: String,
    pub password_hash: String,
}

#[derive(Insertable)]
#[diesel(table_name = users)]
pub struct NewUser<'a> {
    pub username: &'a str,
    pub password_hash: &'a str,
}

// ---------------------------------------------------------------------------

pub fn list(pool: &DbPool) -> Result<Vec<User>> {
    let mut conn = pool.get()?;
    Ok(users::table.load::<User>(&mut conn)?)
}

pub fn insert(pool: &DbPool, user: NewUser) -> Result<()> {
    let mut conn = pool.get()?;
    diesel::insert_into(users::table).values(&user).execute(&mut conn)?;
    Ok(())
}

pub fn delete(pool: &DbPool, id: i32) -> Result<()> {
    let mut conn = pool.get()?;
    diesel::delete(users::table.filter(users::user_id.eq(id))).execute(&mut conn)?;
    Ok(())
}
