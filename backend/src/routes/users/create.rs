use rocket::form::validate::Len;
use rocket::http::Status;
use rocket::{
    error, post,
    serde::{json::Json, Deserialize},
};
use rocket_db_pools::Connection;

use crate::{
    auth::auth::OptionalAuthEntity,
    db::AuthRsDatabase,
    models::registration_token::RegistrationToken,
    models::user::UserDTO,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
        user::User,
        user_error::{UserError, UserResult},
    },
    utils::response::json_response,
    SETTINGS,
};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct CreateUserData {
    email: String,
    password: String,
    first_name: String,
    last_name: String,
    registration_code: Option<String>,
}

#[allow(unused)]
#[post("/users", format = "json", data = "<data>")]
pub async fn create_user(
    db: Connection<AuthRsDatabase>,
    auth_entity: Option<OptionalAuthEntity>,
    data: Json<CreateUserData>,
) -> (Status, Json<HttpResponse<UserDTO>>) {
    let result = create_user_internal(db, auth_entity, data.into_inner()).await;

    match result {
        Ok(user) => json_response(HttpResponse {
            status: 201,
            message: "User created".to_string(),
            data: Some(user.to_dto(true)),
        }),
        Err(err) => json_response(err.into()),
    }
}

async fn create_user_internal(
    db: Connection<AuthRsDatabase>,
    auth_entity: Option<OptionalAuthEntity>,
    data: CreateUserData,
) -> UserResult<User> {
    let req_user = if auth_entity.as_ref().is_some() && auth_entity.as_ref().unwrap().user.is_some()
    {
        Some(auth_entity.unwrap().user.unwrap())
    } else {
        None
    };

    let mut registration_token: Option<RegistrationToken> = None;

    // Handle closed registration
    let settings = (*SETTINGS).lock().await;
    if !settings.open_registration && (req_user.is_none() || !req_user.as_ref().unwrap().is_admin())
    {
        if data.registration_code.is_none() || data.registration_code.len() < 1 {
            return Err(UserError::RegistrationClosed);
        }

        registration_token =
            match RegistrationToken::get_by_code(data.registration_code.unwrap(), &db).await {
                Ok(token) => Some(token),
                Err(_) => {
                    return Err(UserError::RegistrationCodeInvalid);
                }
            }
    }

    // Check if user with email already exists
    if User::get_by_email(&data.email, &db).await.is_ok() {
        return Err(UserError::EmailAlreadyExists(data.email));
    }

    if !data.email.contains('@') || !data.email.contains('.') || data.email.len() < 5 {
        return Err(UserError::InvalidEmail);
    }
    if data.first_name.is_empty() {
        return Err(UserError::FirstNameRequired);
    }
    if data.password.len() < 8 {
        return Err(UserError::PasswordToShort);
    }

    // Create new user
    let mut user = User::new(
        data.email.to_lowercase(),
        data.password,
        data.first_name,
        data.last_name,
    )?;

    // Handle registration token
    if registration_token.is_some() {
        let token = registration_token.clone().unwrap();
        token
            .use_token(&db, user.id)
            .await
            .map_err(|_| UserError::RegistrationCodeInvalid)?;

        for role_id in token.auto_roles {
            user.roles.push(role_id);
        }
    }

    // Insert user into database
    let inserted_user = user.insert(&db).await?;

    // Create audit log
    if let Err(err) = AuditLog::new(
        inserted_user.id.to_string(),
        AuditLogEntityType::User,
        AuditLogAction::Create,
        format!(
            "User created.|{}|{}",
            if registration_token.is_some() {
                AuditLogEntityType::RegistrationToken
            } else {
                AuditLogEntityType::User
            },
            if registration_token.is_some() {
                registration_token.as_ref().unwrap().id
            } else if let Some(req_user) = &req_user {
                req_user.id
            } else {
                inserted_user.id
            }
        ),
        if let Some(req_user) = &req_user {
            req_user.id
        } else {
            inserted_user.id
        },
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
