use rocket::http::Status;
use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::models::settings::{Settings, SettingsDTO};
use crate::utils::response::json_response;
use crate::{db::AuthRsDatabase, models::http_response::HttpResponse};

#[allow(unused)]
#[get("/settings", format = "json")]
pub async fn get_settings(
    db: Connection<AuthRsDatabase>,
) -> (Status, Json<HttpResponse<SettingsDTO>>) {
    match Settings::get(&db).await {
        Ok(settings) => json_response(HttpResponse::success("Loaded settings", settings.to_dto())),
        Err(err) => json_response(err.into()),
    }
}
