use rocket::http::Status;
use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{http_response::HttpResponse, registration_token::RegistrationToken},
    utils::parse_uuid::parse_uuid,
};

#[allow(unused)]
#[get("/registration-tokens/<id>", format = "json")]
pub async fn get_registration_token_by_id(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
) -> (Status, Json<HttpResponse<RegistrationToken>>) {
    if !req_entity.is_user() || !req_entity.user.unwrap().is_admin() {
        return json_response(HttpResponse::forbidden(
            "Only admins can get registration tokens",
        ));
    }

    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    match RegistrationToken::get_by_id(uuid, &db).await {
        Ok(registration_token) => json_response(HttpResponse::success(
            "Found registration token by id",
            registration_token,
        )),
        Err(err) => json_response(err.into()),
    }
}
