use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{http_response::HttpResponse, registration_token::RegistrationToken},
};
use mongodb::bson::doc;
use rocket::http::Status;
use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

#[allow(unused)]
#[get("/registration-tokens", format = "json")]
pub async fn get_all_registration_tokens(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
) -> (Status, Json<HttpResponse<Vec<RegistrationToken>>>) {
    if !req_entity.is_user() || !req_entity.user.unwrap().is_admin() {
        return json_response(HttpResponse::forbidden(
            "Only admins can view registration tokens",
        ));
    }

    let registration_tokens = match RegistrationToken::get_all(&db, None).await {
        Ok(registration_tokens) => registration_tokens,
        Err(err) => return json_response(err.into()),
    };

    json_response(HttpResponse::success(
        "Successfully retrieved all registration tokens",
        registration_tokens,
    ))
}
