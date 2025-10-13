use crate::models::registration_token::{
    RegistrationToken, RegistrationTokenDTO, RegistrationTokenError, RegistrationTokenResult
};
use crate::models::role::Role;
use crate::utils::parse_uuid::parse_uuid;
use crate::utils::response::json_response;
use crate::DEFAULT_ROLE_ID;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    errors::ApiError,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
    },
};
use mongodb::bson::{DateTime, Uuid};
use rocket::http::Status;
use rocket::{
    error, patch,
    serde::{json::Json, Deserialize},
};
use rocket_db_pools::Connection;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct UpdateRegistrationTokenData {
    pub max_uses: Option<u32>,
    pub expires_in: Option<u64>,
    pub auto_roles: Option<Vec<Uuid>>,
}

#[allow(unused)]
#[patch("/registration-tokens/<id>", format = "json", data = "<data>")]
pub async fn update_registration_token(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    data: Json<UpdateRegistrationTokenData>,
 ) -> (Status, Json<HttpResponse<RegistrationTokenDTO>>) {
    let result = update_registration_token_internal(db, req_entity, id, data.into_inner()).await;

    match result {
        Ok(app) => json_response(HttpResponse::success("Registration token updated", app.to_dto())),
        Err(err) => json_response(err.into()),
    }
}

struct RegistrationTokenUpdate {
    token: RegistrationToken,
    old_values: HashMap<String, String>,
    new_values: HashMap<String, String>,
    modified: bool,
}

impl RegistrationTokenUpdate {
    fn new(token: RegistrationToken) -> Self {
        Self {
            token,
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

    fn update_max_uses(&mut self, new_max_uses: u32) {
        if self.token.max_uses != new_max_uses {
            let old_max_uses = self.token.max_uses;
            self.token.max_uses = new_max_uses;
            self.update_field("max_uses", old_max_uses, new_max_uses);
        }
    }

    fn update_expires_in(&mut self, new_expires_in: Option<u64>) {
        if self.token.expires_in != new_expires_in {
            let old_expires_in = self.token.expires_in;
            self.token.expires_in = if new_expires_in.is_some() {
                new_expires_in
            } else {
                None
            };
            self.token.expires_from = if new_expires_in.is_some() {
                Some(DateTime::now())
            } else {
                None
            };
            self.update_field(
                "expires_in",
                old_expires_in
                    .map(|v| format!("{:?}", v))
                    .unwrap_or("None".to_string()),
                Some(new_expires_in)
                    .map(|v| format!("{:?}", v))
                    .unwrap_or("None".to_string()),
            );
        }
    }

    async fn update_roles(
        &mut self,
        new_auto_roles: Vec<Uuid>,
        db: &Connection<AuthRsDatabase>,
    ) -> RegistrationTokenResult<()> {
        if self.token.auto_roles == new_auto_roles {
            return Ok(());
        }

        // Validate roles exist
        let available_roles = Role::get_all(db, None)
            .await
            .map_err(|e| RegistrationTokenError::InternalServerError(e.message()))?;

        for role_id in &new_auto_roles {
            if !available_roles.iter().any(|r| r.id == *role_id) {
                return Err(RegistrationTokenError::RoleNotFound(*role_id));
            }
        }

        let final_roles = new_auto_roles
            .iter()
            .filter(|role_id| **role_id != *DEFAULT_ROLE_ID)
            .cloned()
            .collect::<Vec<Uuid>>();

        let old_roles = self
            .token
            .auto_roles
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let new_roles = final_roles
            .iter()
            .map(|role_id| role_id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        self.update_field("auto_roles", old_roles, new_roles);
        self.token.auto_roles = final_roles;
        Ok(())
    }

    async fn save(
        self,
        db: &Connection<AuthRsDatabase>,
        req_user_id: Uuid,
    ) -> RegistrationTokenResult<RegistrationToken> {
        if !self.modified {
            return Ok(self.token);
        }

        let updated_token = self.token.update(db).await?;

        // Create audit log
        if let Err(err) = AuditLog::new(
            updated_token.id.to_string(),
            AuditLogEntityType::RegistrationToken,
            AuditLogAction::Update,
            "Registration token updated.".to_string(),
            req_user_id,
            Some(self.old_values),
            Some(self.new_values),
        )
        .insert(db)
        .await
        {
            error!("Failed to create audit log: {}", err);
        }

        Ok(updated_token)
    }
}

async fn update_registration_token_internal(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    data: UpdateRegistrationTokenData,
) -> RegistrationTokenResult<RegistrationToken> {
    // Basic permission checks
    if !req_entity.is_user() || !req_entity.user.clone().unwrap().is_admin() {
        return Err(
            ApiError::Forbidden("Only admins can update registration tokens".to_string()).into(),
        );
    }

    let uuid = parse_uuid(id).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let token = RegistrationToken::get_by_id(uuid, &db).await?;

    let mut update = RegistrationTokenUpdate::new(token);

    // Apply updates
    if let Some(max_uses) = data.max_uses {
        update.update_max_uses(max_uses);
    }

    update.update_expires_in(data.expires_in);

    if let Some(auto_roles) = data.auto_roles {
        update.update_roles(auto_roles, &db).await?;
    }

    // Save changes
    update.save(&db, req_entity.user_id).await
}
