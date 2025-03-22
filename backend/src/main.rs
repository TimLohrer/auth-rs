mod auth;
mod db;
mod errors;
mod models;
mod routes;
mod utils;

use std::{collections::HashMap, env};

use auth::mfa::MfaHandler;
use db::AuthRsDatabase;
use dotenv::dotenv;
use errors::{AppError, AppResult};
use models::{role::Role, user::User};
use mongodb::bson::Uuid;
use rocket::{
    fairing::AdHoc,
    http::Method::{Connect, Delete, Get, Patch, Post, Put},
    launch, routes,
    tokio::sync::Mutex,
};
use rocket_cors::{AllowedHeaders, AllowedOrigins, CorsOptions};
use rocket_db_pools::{mongodb::Collection, Database};
use routes::oauth::token::TokenOAuthData;

// oauth codes stored in memory
lazy_static::lazy_static! {
    //TODO: Replace with Redis or other cache, so this application can be stateless
    static ref OAUTH_CODES: Mutex<HashMap<u32, TokenOAuthData>> = Mutex::new(HashMap::new());
    static ref MFA_SESSIONS: Mutex<HashMap<Uuid, MfaHandler>> = Mutex::new(HashMap::new());

    static ref ADMIN_ROLE_ID: Uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000000")
        .expect("Failed to parse ADMIN_ROLE_ID UUID");
    static ref DEFAULT_ROLE_ID: Uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000001")
        .expect("Failed to parse DEFAULT_ROLE_ID UUID");
    static ref SYSTEM_USER_ID: Uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000000")
        .expect("Failed to parse SYSTEM_USER_ID UUID");
}

/// Initialize the database with default roles and system user
async fn initialize_database(db: &AuthRsDatabase) -> AppResult<()> {
    let data_db = db.database(db::get_main_db_name());

    let roles_collection: Collection<Role> = data_db.collection(Role::COLLECTION_NAME);
    let users_collection: Collection<User> = data_db.collection(User::COLLECTION_NAME);

    // Initialize default roles if they don't exist
    let roles_count = roles_collection
        .count_documents(None, None)
        .await
        .map_err(AppError::RocketMongoError)?;

    if roles_count == 0 {
        let admin_role = Role::new_system(*ADMIN_ROLE_ID, "Admin".to_string())
            .map_err(|e| AppError::HttpResponseError(e.message()))?;

        let default_role = Role::new_system(*DEFAULT_ROLE_ID, "Default".to_string())
            .map_err(|e| AppError::HttpResponseError(e.message()))?;

        let roles = vec![admin_role, default_role];

        roles_collection
            .insert_many(roles, None)
            .await
            .map_err(AppError::RocketMongoError)?;

        println!("Inserted default roles into the database");
    }

    // Initialize system user if no users exist
    let users_count = users_collection
        .count_documents(None, None)
        .await
        .map_err(AppError::RocketMongoError)?;

    if users_count == 0 {
        let system_email = env::var("SYSTEM_EMAIL")?;
        let system_password = env::var("SYSTEM_PASSWORD")?;

        let system_user = User::new_system(
            *SYSTEM_USER_ID,
            system_email,
            system_password,
            "System".to_string(),
            "".to_string(),
            Vec::from([(*ADMIN_ROLE_ID).to_string(), (*DEFAULT_ROLE_ID).to_string()]),
        )
        .map_err(AppError::from)?;

        users_collection
            .insert_one(system_user, None)
            .await
            .map_err(AppError::RocketMongoError)?;

        println!("Inserted system user into the database");
    }

    Ok(())
}

#[launch]
fn rocket() -> _ {
    dotenv().ok();
    let cors = CorsOptions::default()
        .allowed_origins(AllowedOrigins::all())
        .allowed_methods(
            vec![Get, Post, Put, Patch, Delete, Connect]
                .into_iter()
                .map(From::from)
                .collect(),
        )
        .allowed_headers(AllowedHeaders::all())
        .allow_credentials(true);

    rocket::build()
        .attach(db::AuthRsDatabase::init())
        .attach(cors.to_cors().expect("Failed to create CORS fairing"))
        .attach(AdHoc::try_on_ignite("Default Values", |rocket| async {
            let db = match AuthRsDatabase::fetch(&rocket) {
                Some(db) => db,
                None => {
                    eprintln!("Failed to fetch database connection");
                    return Err(rocket);
                }
            };

            match initialize_database(db).await {
                Ok(_) => Ok(rocket),
                Err(err) => {
                    eprintln!("Failed to initialize database: {}", err);
                    Err(rocket)
                }
            }
        }))
        .mount(
            "/api",
            routes![
                routes::base::base,
                // Audit Log routes
                routes::audit_logs::get_by_type::get_audit_logs_by_type,
                routes::audit_logs::get_by_id::get_audit_log_by_id,
                routes::audit_logs::get_by_entity_id::get_audit_log_by_entity_id,
                routes::audit_logs::get_by_user_id::get_audit_logs_by_user_id,
                // User Routes
                routes::users::create::create_user,
                routes::users::get_all::get_all_users,
                routes::users::get_by_id::get_user_by_id,
                routes::users::me::get_current_user,
                // this is mainly used for oauth apps
                routes::users::me::get_current_user_plain,
                routes::users::mfa::enable_totp_mfa,
                routes::users::mfa::disable_totp_mfa,
                routes::users::update::update_user,
                routes::users::delete::delete_user,
                // Role Routes
                routes::roles::create::create_role,
                routes::roles::get_all::get_all_roles,
                routes::roles::get_by_id::get_role_by_id,
                routes::roles::update::update_role,
                routes::roles::delete::delete_role,
                // OAuth Application Routes
                routes::oauth_applications::create::create_oauth_application,
                routes::oauth_applications::get_all::get_all_oauth_applications,
                routes::oauth_applications::get_by_id::get_oauth_application_by_id,
                routes::oauth_applications::update::update_oauth_application,
                routes::oauth_applications::delete::delete_oauth_application,
                // OAuth Routes
                routes::oauth::token::get_oauth_token,
                routes::oauth::authorize::authorize_oauth_application,
                routes::oauth::revoke::revoke_oauth_token,
                // Connection Routes
                routes::connections::get_by_user_id::get_by_user_id,
                routes::connections::disconnect::disconnect,
                // Auth Routes
                routes::auth::register::register,
                routes::auth::login::login,
                routes::auth::mfa::mfa
            ],
        )
}
