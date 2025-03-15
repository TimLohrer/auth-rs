use mongodb::bson::Uuid;
use pwhash::bcrypt;
use rocket::{
    error, patch,
    serde::{json::Json, Deserialize},
};
use rocket_db_pools::Connection;
use std::collections::HashMap;

use crate::models::user::UserDTO;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    errors::AppError,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
        role::Role,
        user::User,
        user_error::{UserError, UserResult},
    },
    ADMIN_ROLE_ID, DEFAULT_ROLE_ID, SYSTEM_USER_ID,
};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserData {
    email: Option<String>,
    password: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    roles: Option<Vec<Uuid>>,
    disabled: Option<bool>,
}

#[allow(unused)]
#[patch("/users/<id>", format = "json", data = "<data>")]
pub async fn update_user(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    data: Json<UpdateUserData>,
) -> Json<HttpResponse<UserDTO>> {
    let result = update_user_internal(db, req_entity, id, data.into_inner()).await;

    match result {
        Ok(user) => Json(HttpResponse::success("User updated", user.to_dto())),
        Err(err) => Json(err.into()),
    }
}

async fn update_user_internal(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    data: UpdateUserData,
) -> UserResult<User> {
    // Check if the request is from a user (not a token)
    if !req_entity.is_user() {
        return Err(UserError::MissingPermissions);
    }

    // Parse UUID
    let uuid = Uuid::parse_str(id).map_err(|e| UserError::InvalidUuid(e.to_string()))?;

    // Check permissions
    let req_user = req_entity
        .user()
        .map_err(|_| UserError::MissingPermissions)?;
    if req_entity.user_id != uuid && !req_user.is_admin() {
        return Err(UserError::MissingPermissions);
    }

    // Get the user to update
    let old_user = User::get_by_id(uuid, &db)
        .await
        .map_err(|_| UserError::NotFound(uuid))?;
    let mut new_user = old_user.clone();

    let mut old_values: HashMap<String, String> = HashMap::new();
    let mut new_values: HashMap<String, String> = HashMap::new();

    // Update email if provided and different
    if let Some(email) = data.email {
        if old_user.email != email {
            new_user.email = email;
            old_values.insert("email".to_string(), old_user.email.clone());
            new_values.insert("email".to_string(), new_user.email.clone());
        }
    }

    // Update password if provided
    if let Some(password) = data.password {
        let password_hash =
            bcrypt::hash(password).map_err(|e| UserError::PasswordHashingError(e.to_string()))?;

        new_user.password_hash = password_hash;
        old_values.insert("password".to_string(), "HIDDEN".to_string());
        new_values.insert("password".to_string(), "HIDDEN".to_string());
    }

    // Update first name if provided and different
    if let Some(first_name) = data.first_name {
        if old_user.first_name != first_name {
            new_user.first_name = first_name;
            old_values.insert("firstName".to_string(), old_user.first_name.clone());
            new_values.insert("firstName".to_string(), new_user.first_name.clone());
        }
    }

    // Update last name if provided and different
    if let Some(last_name) = data.last_name {
        if old_user.last_name != last_name {
            new_user.last_name = last_name;
            old_values.insert("lastName".to_string(), old_user.last_name.clone());
            new_values.insert("lastName".to_string(), new_user.last_name.clone());
        }
    }

    // Update roles if provided, different, and user is admin
    if let Some(mut new_roles) = data.roles {
        if old_user.roles != new_roles && req_user.is_admin() {
            // Ensure the target user is not the system user
            if new_user.id == *SYSTEM_USER_ID {
                return Err(UserError::SystemUserModification);
            }

            // Get available roles
            let available_roles = Role::get_all(&db, None)
                .await
                .map_err(|e| UserError::InternalServerError(e.message()))?;

            // Validate each role exists
            for role_id in &new_roles {
                if !available_roles.iter().any(|r| r.id == *role_id) {
                    return Err(UserError::RoleNotFound(*role_id));
                }
            }

            // Ensure DEFAULT_ROLE_ID is always included
            if !new_roles.contains(&DEFAULT_ROLE_ID) {
                new_roles.push(*DEFAULT_ROLE_ID);
            }

            // Only system admin can assign admin role
            if new_roles.contains(&ADMIN_ROLE_ID) && !req_user.is_system_admin() {
                return Err(UserError::AdminRoleAssignment);
            }

            new_user.roles = new_roles;
            old_values.insert(
                "roles".to_string(),
                old_user
                    .roles
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
            new_values.insert(
                "roles".to_string(),
                new_user
                    .roles
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
    }

    // Update disabled status if provided, different, and user is admin
    if let Some(disabled) = data.disabled {
        if old_user.disabled != disabled && req_user.is_admin() {
            // Prevent disabling system user
            if new_user.id == *SYSTEM_USER_ID {
                return Err(UserError::SystemUserModification);
            }

            new_user.disabled = disabled;
            old_values.insert("disabled".to_string(), old_user.disabled.to_string());
            new_values.insert("disabled".to_string(), new_user.disabled.to_string());
        }
    }

    // If no changes were made, return early
    if new_values.is_empty() {
        return Ok(new_user);
    }

    // Update the user
    let updated_user = new_user
        .update(&db)
        .await
        .map_err(|e| UserError::DatabaseError(format!("Failed to update user: {}", e)))?;

    // Log the audit
    if let Err(err) = AuditLog::new(
        updated_user.id,
        AuditLogEntityType::User,
        AuditLogAction::Update,
        "User updated.".to_string(),
        req_entity.user_id,
        Some(old_values),
        Some(new_values),
    )
    .insert(&db)
    .await
    {
        error!("Failed to create audit log: {}", err);
    }

    Ok(updated_user)
}
