use crate::{models::{settings::Settings, user::User}, SETTINGS_ID};
use dotenv::var;
use mongodb::bson::{doc, DateTime, Uuid};
use rocket::serde::{Deserialize, Serialize};
use rocket_db_pools::mongodb::Database;

pub struct DatabaseMigrator {}

impl DatabaseMigrator {
    pub async fn run_migrations(db: &Database) -> Result<(), String> {
        let current_version = var("VERSION").expect("VERSION must be set in .env file");
        let mut db_version = match db
            .collection::<Settings>("settings")
            .find_one(doc! { "_id": *SETTINGS_ID }, None)
            .await
        {
            Ok(Some(settings)) => settings.version,
            Ok(None) => "1.0.22".to_string(),
            Err(_) => "1.0.22".to_string(),
        };

        if db_version == current_version {
            println!(
                "Database is up to date (version {}), no migrations needed!",
                db_version
            );
            return Ok(());
        }

        if db_version == "1.0.22" {
            println!("Running migration from version 1.0.22 to 1.0.23...");

            println!("Adding 'dataStorage' field to all users...");

            db.collection::<User>("users")
                .update_many(
                    doc! { "dataStorage": { "$exists": false } },
                    doc! { "$set": { "dataStorage": {} } },
                    None,
                )
                .await
                .map_err(|e| format!("Failed to update users during migration: {:?}", e))?;
            
            db_version = "1.0.23".to_string();
            println!("Migration to version 1.0.23 completed.");
        }

        Self::update_version_history(&db, &current_version).await;

        Ok(())
    }

    async fn update_version_history(db: &Database, new_version: &str) {
        let mut settings = match new_version.starts_with("1.0.") && new_version.split(".").last().unwrap().parse::<u32>().unwrap() <= 24 {
            true => {
                // Special case for initializing settings to enable migrations from versions 1.0.22 or older
                #[derive(Debug, Clone, Serialize, Deserialize)]
                #[serde(crate = "rocket::serde")]
                #[serde(rename_all = "camelCase")]
                struct OldSettings {
                    #[serde(rename = "_id")]
                    pub id: Uuid,
                    pub open_registration: bool,
                    pub allow_oauth_apps_for_users: bool,
                }
                let old_settings = db.collection::<OldSettings>("settings")
                    .find_one(doc! { "_id": *SETTINGS_ID }, None)
                    .await
                    .expect("Failed to fetch settings for version update")
                    .expect("Settings not found for version update");
                
                Settings {
                    id: old_settings.id,
                    version: "1.0.22".to_string(),
                    version_history: vec![],
                    open_registration: old_settings.open_registration,
                    allow_oauth_apps_for_users: old_settings.allow_oauth_apps_for_users,
                }
            }
            false => db
                .collection::<Settings>("settings")
                .find_one(doc! { "_id": *SETTINGS_ID }, None)
                .await
                .expect("Failed to fetch settings for version update")
                .expect("Settings not found for version update"),
        };

        settings.version = new_version.to_string();
        settings
            .version_history
            .push((new_version.to_string(), DateTime::now()));

        db.collection::<Settings>("settings")
            .replace_one(doc! { "_id": *SETTINGS_ID }, settings, None)
            .await
            .expect("Failed to update settings during version update");
    }
}
