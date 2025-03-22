use rocket::http::Status;
use rocket::{
    error, post,
    serde::{json::Json, Deserialize},
};
use rocket_db_pools::Connection;

use crate::models::user::UserDTO;
use crate::utils::response::json_response;
use crate::{
    db::AuthRsDatabase,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
        user::User,
        user_error::{UserError, UserResult},
    },
};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct CreateUserData {
    email: String,
    password: String,
    first_name: String,
    last_name: String,
}

#[allow(unused)]
#[post("/users", format = "json", data = "<data>")]
pub async fn create_user(
    db: Connection<AuthRsDatabase>,
    data: Json<CreateUserData>,
) -> (Status, Json<HttpResponse<UserDTO>>) {
    let result = create_user_internal(db, data.into_inner()).await;

    match result {
        Ok(user) => json_response(HttpResponse {
            status: 201,
            message: "User created".to_string(),
            data: Some(user.to_dto()),
        }),
        Err(err) => json_response(err.into()),
    }
}

async fn create_user_internal(
    db: Connection<AuthRsDatabase>,
    data: CreateUserData,
) -> UserResult<User> {
    // Check if user with email already exists
    if User::get_by_email(&data.email, &db).await.is_ok() {
        return Err(UserError::EmailAlreadyExists(data.email));
    }

    if !data.email.contains('@') || !data.email.contains('.') || data.email.len() < 5 {
        return Err(UserError::InvalidEmail);
    }
    if data.first_name.len() < 1 {
        return Err(UserError::FirstNameRequired);
    }
    if data.password.len() < 8 {
        return Err(UserError::PasswordToShort);
    }

    // Create new user
    let user = User::new(
        data.email.to_lowercase(),
        data.password,
        data.first_name,
        data.last_name,
    )?;

    // Insert user into database
    let inserted_user = user.insert(&db).await?;

    // Create audit log
    if let Err(err) = AuditLog::new(
        inserted_user.id,
        AuditLogEntityType::User,
        AuditLogAction::Create,
        "User created.".to_string(),
        inserted_user.id,
        None,
        None,
    )
    .insert(&db)
    .await
    {
        error!("Failed to create audit log: {}", err);
    }

    Ok(inserted_user)
}
