use crate::utils::parse_uuid::parse_uuid;
use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    errors::ApiError,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
        role::Role,
        role::RoleResult,
    },
};
use rocket::http::Status;
use rocket::{
    error, patch,
    serde::{json::Json, Deserialize},
};
use rocket_db_pools::Connection;
use std::collections::HashMap;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct UpdateRoleData {
    name: Option<String>,
}

#[allow(unused)]
#[patch("/roles/<id>", format = "json", data = "<data>")]
pub async fn update_role(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    data: Json<UpdateRoleData>,
) -> (Status, Json<HttpResponse<Role>>) {
    let result = update_role_internal(db, req_entity, id, data.into_inner()).await;

    match result {
        Ok(role) => json_response(HttpResponse::success("Role updated", role)),
        Err(err) => json_response(err.into()),
    }
}

struct RoleUpdate {
    role: Role,
    old_values: HashMap<String, String>,
    new_values: HashMap<String, String>,
    modified: bool,
}

impl RoleUpdate {
    fn new(role: Role) -> Self {
        Self {
            role,
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

    fn update_name(&mut self, new_name: String) {
        if self.role.name != new_name {
            let old_name = self.role.name.clone();
            self.update_field("name", old_name, new_name.clone());
            self.role.name = new_name;
        }
    }

    async fn save(
        self,
        db: &Connection<AuthRsDatabase>,
        req_user_id: mongodb::bson::Uuid,
    ) -> RoleResult<Role> {
        if !self.modified {
            return Ok(self.role);
        }

        let updated_role = self.role.update(db).await?;

        // Create audit log
        if let Err(err) = AuditLog::new(
            updated_role.id,
            AuditLogEntityType::Role,
            AuditLogAction::Update,
            "Role updated.".to_string(),
            req_user_id,
            Some(self.old_values),
            Some(self.new_values),
        )
        .insert(db)
        .await
        {
            error!("Failed to create audit log: {}", err);
        }

        Ok(updated_role)
    }
}

async fn update_role_internal(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    data: UpdateRoleData,
) -> RoleResult<Role> {
    // Basic permission checks
    if !req_entity.is_user() {
        return Err(ApiError::Forbidden("Forbidden".to_string()).into());
    }

    let req_user = req_entity
        .user()
        .map_err(|_| ApiError::Forbidden("Forbidden".to_string()))?;
    if !req_user.is_admin() {
        return Err(ApiError::Forbidden("Missing permissions!".to_string()).into());
    }

    let uuid = parse_uuid(id).map_err(|e| ApiError::BadRequest(e.to_string()))?;

    // Get role and prepare update
    let role = Role::get_by_id(uuid, &db).await?;

    // Prevent modification of system roles
    if role.system {
        return Err(ApiError::Forbidden("Cannot modify system role".to_string()).into());
    }

    let mut update = RoleUpdate::new(role);

    // Apply updates
    if let Some(name) = data.name {
        update.update_name(name);
    }

    // Save changes
    update.save(&db, req_entity.user_id).await
}
