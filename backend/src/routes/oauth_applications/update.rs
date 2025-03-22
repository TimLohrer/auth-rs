use crate::utils::parse_uuid::parse_uuid;
use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    errors::ApiError,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
        oauth_application::{OAuthApplication, OAuthApplicationDTO, OAuthApplicationResult},
    },
};
use mongodb::bson::Uuid;
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
pub struct UpdateOAuthApplicationData {
    name: Option<String>,
    description: Option<String>,
    redirect_uris: Option<Vec<String>>,
}

#[allow(unused)]
#[patch("/oauth-applications/<id>", format = "json", data = "<data>")]
pub async fn update_oauth_application(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    data: Json<UpdateOAuthApplicationData>,
) -> (Status, Json<HttpResponse<OAuthApplicationDTO>>) {
    let result = update_oauth_application_internal(db, req_entity, id, data.into_inner()).await;

    match result {
        Ok(app) => json_response(HttpResponse::success(
            "OAuth Application updated",
            app.to_dto(),
        )),
        Err(err) => json_response(err.into()),
    }
}

struct OAuthApplicationUpdate {
    app: OAuthApplication,
    old_values: HashMap<String, String>,
    new_values: HashMap<String, String>,
    modified: bool,
}

impl OAuthApplicationUpdate {
    fn new(app: OAuthApplication) -> Self {
        Self {
            app,
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
        if self.app.name != new_name {
            let old_name = self.app.name.clone();
            self.update_field("name", old_name, new_name.clone());
            self.app.name = new_name;
        }
    }

    fn update_description(&mut self, new_description: Option<String>) {
        if self.app.description != new_description {
            let old_description = self
                .app
                .description
                .clone()
                .unwrap_or_else(|| "None".to_string());
            let new_desc = match new_description {
                Some(desc) if !desc.is_empty() => {
                    let desc_clone = desc.clone();
                    self.app.description = Some(desc);
                    desc_clone
                }
                _ => {
                    self.app.description = None;
                    "None".to_string()
                }
            };
            self.update_field("description", old_description, new_desc);
        }
    }

    fn update_redirect_uris(&mut self, new_uris: Vec<String>) {
        if self.app.redirect_uris != new_uris {
            let old_uris = self.app.redirect_uris.join(", ");
            let new_uris_str = new_uris.join(", ");
            self.update_field("redirect_uris", old_uris, new_uris_str);
            self.app.redirect_uris = new_uris;
        }
    }

    async fn save(
        self,
        db: &Connection<AuthRsDatabase>,
        req_user_id: Uuid,
    ) -> OAuthApplicationResult<OAuthApplication> {
        if !self.modified {
            return Ok(self.app);
        }

        let updated_app = self.app.update(db).await?;

        // Create audit log
        if let Err(err) = AuditLog::new(
            updated_app.id,
            AuditLogEntityType::OAuthApplication,
            AuditLogAction::Update,
            "OAuthApplication updated.".to_string(),
            req_user_id,
            Some(self.old_values),
            Some(self.new_values),
        )
        .insert(db)
        .await
        {
            error!("Failed to create audit log: {}", err);
        }

        Ok(updated_app)
    }
}

async fn update_oauth_application_internal(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
    data: UpdateOAuthApplicationData,
) -> OAuthApplicationResult<OAuthApplication> {
    // Basic permission checks
    if !req_entity.is_user() {
        return Err(ApiError::Forbidden("Forbidden".to_string()).into());
    }

    let uuid = parse_uuid(id).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let app = OAuthApplication::get_by_id(uuid, &db).await?;

    let req_user = req_entity
        .user()
        .map_err(|_| ApiError::Forbidden("Forbidden".to_string()))?;
    if req_entity.user_id != app.owner && !req_user.is_admin() {
        return Err(ApiError::Forbidden("Missing permissions!".to_string()).into());
    }

    let mut update = OAuthApplicationUpdate::new(app);

    // Apply updates
    if let Some(name) = data.name {
        update.update_name(name);
    }

    if let Some(description) = data.description {
        update.update_description(Some(description));
    }

    if let Some(redirect_uris) = data.redirect_uris {
        update.update_redirect_uris(redirect_uris);
    }

    // Save changes
    update.save(&db, req_entity.user_id).await
}
