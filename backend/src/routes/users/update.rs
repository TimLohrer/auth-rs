use crate::models::user::UserDTO;
use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
        role::Role,
        user::User,
        user_error::{UserError, UserResult},
    },
    ADMIN_ROLE_ID, DEFAULT_ROLE_ID, SYSTEM_USER_ID,
};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use mongodb::bson::Uuid;
use rocket::{
    error,
    http::Status,
    patch,
    serde::{json::Json, Deserialize},
};
use rocket_db_pools::Connection;
use std::collections::HashMap;

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
) -> (Status, Json<HttpResponse<UserDTO>>) {
    let result = update_user_internal(db, req_entity, id, data.into_inner()).await;

    match result {
        Ok(user) => json_response(HttpResponse::success("User updated", user.to_dto())),
        Err(err) => json_response(err.into()),
    }
}

struct UserUpdate {
    user: User,
    old_values: HashMap<String, String>,
    new_values: HashMap<String, String>,
    modified: bool,
}

impl UserUpdate {
    fn new(user: User) -> Self {
        Self {
            user,
            old_values: HashMap::new(),
            new_values: HashMap::new(),
            modified: false,
        }
    }

    fn update_field<T: ToString>(&mut self, field: &str, old_value: T, new_value: T) {
        self.old_values
            .insert(field.to_string(), old_value.to_string());
        self.new_values
            .insert(field.to_string(), new_value.to_string());
        self.modified = true;
    }

    fn update_email(&mut self, new_email: String) -> UserResult<()> {
        if self.user.email != new_email {
            if !new_email.contains(".") || !new_email.contains("@") || new_email.len() < 5 {
                return Err(UserError::InvalidEmail);
            }
            let old_email = self.user.email.clone();
            self.update_field("email", old_email, new_email.clone());
            self.user.email = new_email;
        }
        Ok(())
    }

    fn update_password(&mut self, password: String) -> UserResult<()> {
        if password.len() < 8 {
            return Err(UserError::PasswordToShort);
        }
        let salt =
            SaltString::from_b64(&self.user.salt).map_err(|_| UserError::PasswordHashingError)?;
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| UserError::PasswordHashingError)?
            .to_string();
        self.update_field("password", "HIDDEN", "HIDDEN");
        self.user.password_hash = password_hash;
        Ok(())
    }

    fn update_name(
        &mut self,
        first_name: Option<String>,
        last_name: Option<String>,
    ) -> UserResult<()> {
        if let Some(first_name) = first_name {
            if self.user.first_name != first_name {
                if first_name.len() < 1 {
                    return Err(UserError::FirstNameRequired);
                }
                let old_first_name = self.user.first_name.clone();
                self.update_field("firstName", old_first_name, first_name.clone());
                self.user.first_name = first_name;
            }
        }

        if let Some(last_name) = last_name {
            if self.user.last_name != last_name {
                let old_last_name = self.user.last_name.clone();
                self.update_field("lastName", old_last_name, last_name.clone());
                self.user.last_name = last_name;
            }
        }
        Ok(())
    }

    async fn update_roles(
        &mut self,
        new_roles: Vec<Uuid>,
        db: &Connection<AuthRsDatabase>,
        req_user: &User,
    ) -> UserResult<()> {
        if self.user.roles == new_roles {
            return Ok(());
        }

        // System user check
        if self.user.id == *SYSTEM_USER_ID {
            return Err(UserError::SystemUserModification);
        }

        // Admin permission check
        if !req_user.is_admin() {
            return Err(UserError::MissingPermissions);
        }

        // Validate roles exist
        let available_roles = Role::get_all(db, None)
            .await
            .map_err(|e| UserError::InternalServerError(e.message()))?;

        for role_id in &new_roles {
            if !available_roles.iter().any(|r| r.id == *role_id) {
                return Err(UserError::RoleNotFound(*role_id));
            }
        }

        let mut final_roles = new_roles;
        if !final_roles.contains(&DEFAULT_ROLE_ID) {
            final_roles.push(*DEFAULT_ROLE_ID);
        }

        // Admin role assignment check
        if final_roles.contains(&ADMIN_ROLE_ID) && !req_user.is_system_admin() {
            return Err(UserError::AdminRoleAssignment);
        }

        let old_roles = self
            .user
            .roles
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let new_roles = final_roles
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        self.update_field("roles", old_roles, new_roles);
        self.user.roles = final_roles;
        Ok(())
    }

    fn update_disabled(&mut self, disabled: bool, req_user: &User) -> UserResult<()> {
        if self.user.disabled == disabled {
            return Ok(());
        }

        if !req_user.is_admin() || req_user.id == self.user.id {
            return Err(UserError::MissingPermissions);
        }

        if self.user.id == *SYSTEM_USER_ID {
            return Err(UserError::SystemUserModification);
        }

        let old_disabled = self.user.disabled;
        self.update_field("disabled", old_disabled, disabled);
        self.user.disabled = disabled;
        Ok(())
    }

    async fn save(self, db: &Connection<AuthRsDatabase>, req_user_id: Uuid) -> UserResult<User> {
        if !self.modified {
            return Ok(self.user);
        }

        let updated_user = self
            .user
            .update(db)
            .await
            .map_err(|e| UserError::DatabaseError(format!("Failed to update user: {}", e)))?;

        // Create audit log
        if let Err(err) = AuditLog::new(
            updated_user.id,
            AuditLogEntityType::User,
            AuditLogAction::Update,
            "User updated.".to_string(),
            req_user_id,
            Some(self.old_values),
            Some(self.new_values),
        )
        .insert(db)
        .await
        {
            error!("Failed to create audit log: {}", err);
        }

        Ok(updated_user)
    }
}

async fn update_user_internal(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    data: UpdateUserData,
) -> UserResult<User> {
    // Basic permission checks
    if !req_entity.is_user() {
        return Err(UserError::MissingPermissions);
    }

    let uuid = Uuid::parse_str(id).map_err(|e| UserError::InvalidUuid(e.to_string()))?;
    let req_user = req_entity
        .user()
        .map_err(|_| UserError::MissingPermissions)?;

    if req_entity.user_id != uuid && !req_user.is_admin() {
        return Err(UserError::MissingPermissions);
    }

    // Get user and prepare update
    let user = User::get_by_id(uuid, &db)
        .await
        .map_err(|_| UserError::NotFound(uuid))?;
    let mut update = UserUpdate::new(user);

    // Apply updates
    if let Some(email) = data.email {
        update.update_email(email)?;
    }

    if let Some(password) = data.password {
        update.update_password(password)?;
    }

    update.update_name(data.first_name, data.last_name)?;

    if let Some(roles) = data.roles {
        update.update_roles(roles, &db, req_user).await?;
    }

    if let Some(disabled) = data.disabled {
        update.update_disabled(disabled, req_user)?;
    }

    // Save changes
    update.save(&db, req_entity.user_id).await
}
