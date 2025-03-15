use rocket::{
    error, post,
    serde::{json::Json, Deserialize},
};
use rocket_db_pools::Connection;

use crate::models::user::UserDTO;
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
) -> Json<HttpResponse<UserDTO>> {
    let result = create_user_internal(db, data.into_inner()).await;

    match result {
        Ok(user) => Json(HttpResponse {
            status: 201,
            message: "User created".to_string(),
            data: Some(user.to_dto()),
        }),
        Err(err) => Json(err.into()),
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

    // Create new user
    let user = User::new(data.email, data.password, data.first_name, data.last_name)?;

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
