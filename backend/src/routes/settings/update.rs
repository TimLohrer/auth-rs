use crate::models::settings::{Settings, SettingsError, SettingsResult};
use crate::utils::response::json_response;
use crate::SETTINGS;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
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
#[serde(rename_all = "camelCase")]
pub struct UpdateSettingsData {
    open_registration: Option<bool>,
    allow_oauth_apps_for_users: Option<bool>,
}

#[allow(unused)]
#[patch("/admin/settings", format = "json", data = "<data>")]
pub async fn update_settings(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    data: Json<UpdateSettingsData>,
) -> (Status, Json<HttpResponse<Settings>>) {
    let result = update_settings_internal(db, req_entity, data.into_inner()).await;

    match result {
        Ok(settings) => {
            *SETTINGS.lock().await = settings.clone();
            json_response(HttpResponse::success("Settings updated", settings))
        }
        Err(err) => json_response(err.into()),
    }
}

struct SettingsUpdate {
    settings: Settings,
    old_values: HashMap<String, String>,
    new_values: HashMap<String, String>,
    modified: bool,
}

impl SettingsUpdate {
    fn new(settings: Settings) -> Self {
        Self {
            settings,
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

    fn update_open_registration(&mut self, new_open_registration: bool) {
        if self.settings.open_registration != new_open_registration {
            let old_open_registration = self.settings.open_registration;
            self.update_field(
                "open_registration",
                old_open_registration.to_string(),
                new_open_registration.to_string(),
            );
            self.settings.open_registration = new_open_registration;
        }
    }

    fn update_allow_oauth_apps_for_users(&mut self, new_allow_oauth_apps_for_users: bool) {
        if self.settings.allow_oauth_apps_for_users != new_allow_oauth_apps_for_users {
            let old_allow_oauth_apps_for_users = self.settings.allow_oauth_apps_for_users;
            self.update_field(
                "allow_oauth_apps_for_users",
                old_allow_oauth_apps_for_users.to_string(),
                new_allow_oauth_apps_for_users.to_string(),
            );
            self.settings.allow_oauth_apps_for_users = new_allow_oauth_apps_for_users;
        }
    }

    async fn save(
        self,
        db: &Connection<AuthRsDatabase>,
        req_user_id: mongodb::bson::Uuid,
    ) -> SettingsResult<Settings> {
        if !self.modified {
            return Ok(self.settings);
        }

        let updated_settings = self.settings.update(db).await?;

        // Create audit log
        if let Err(err) = AuditLog::new(
            updated_settings.id.to_string(),
            AuditLogEntityType::Settings,
            AuditLogAction::Update,
            "Settings updated.".to_string(),
            req_user_id,
            Some(self.old_values),
            Some(self.new_values),
        )
        .insert(db)
        .await
        {
            error!("Failed to create audit log: {}", err);
        }

        Ok(updated_settings)
    }
}

async fn update_settings_internal(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    data: UpdateSettingsData,
) -> SettingsResult<Settings> {
    // Basic permission checks
    if !req_entity.is_user() {
        return Err(SettingsError::Forbidden(
            "Only the system user can change settings!".to_string(),
        ));
    }

    let req_user = req_entity.user().map_err(|_| {
        SettingsError::Forbidden("Only the system user can change settings!".to_string())
    })?;
    if !req_user.is_system_admin() {
        return Err(SettingsError::Forbidden(
            "Only the system user can change settings!".to_string(),
        ));
    }

    // Get role and prepare update
    let settings = Settings::get(&db).await?;

    let mut update = SettingsUpdate::new(settings);

    // Apply updates
    if let Some(open_registration) = data.open_registration {
        update.update_open_registration(open_registration);
    }

    if let Some(allow_oauth_apps_for_users) = data.allow_oauth_apps_for_users {
        update.update_allow_oauth_apps_for_users(allow_oauth_apps_for_users);
    }

    // Save changes
    update.save(&db, req_entity.user_id).await
}
