use rocket::http::Status;
use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        http_response::HttpResponse,
        oauth_application::{OAuthApplication, OAuthApplicationDTO},
    },
    utils::parse_uuid::parse_uuid,
};

#[allow(unused)]
#[get("/oauth-applications/<id>", format = "json")]
pub async fn get_oauth_application_by_id(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
) -> (Status, Json<HttpResponse<OAuthApplicationDTO>>) {
    if !req_entity.is_user() {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    match OAuthApplication::get_by_id(uuid, &db).await {
        Ok(oauth_application) => json_response(HttpResponse::success(
            "Found oauth_application by id",
            oauth_application.to_dto(),
        )),
        Err(err) => json_response(err.into()),
    }
}
