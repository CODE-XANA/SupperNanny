use r2d2::Pool;
use r2d2_postgres::PostgresConnectionManager;
use postgres::NoTls;

#[derive(Clone)]
pub struct AppState {
    pub db_pool: Pool<PostgresConnectionManager<NoTls>>,
}
