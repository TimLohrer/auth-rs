use rocket_db_pools::{
    mongodb::{Client, Database},
    Connection, Database as RocketDB,
};

#[derive(RocketDB)]
#[database("auth-rs-db")]
pub struct AuthRsDatabase(Client);

pub fn get_main_db_name() -> &'static str {
    "auth-rs-data"
}

pub fn get_logs_db_name() -> &'static str {
    "auth-rs-logs"
}

pub fn get_main_db(connection: &Connection<AuthRsDatabase>) -> Database {
    connection.database(get_main_db_name())
}

pub fn get_logs_db(connection: &Connection<AuthRsDatabase>) -> Database {
    connection.database(get_logs_db_name())
}
