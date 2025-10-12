use rocket::http::Status;
use rocket::{post, serde::json::Json};
use rocket_db_pools::Connection;

use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{http_response::HttpResponse, oauth_token::OAuthToken},
};

#[allow(unused)]
#[post("/oauth/token/revoke", format = "json")]
pub async fn revoke_oauth_token(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
) -> (Status, Json<HttpResponse<()>>) {
    if !req_entity.is_token() {
        return json_response(HttpResponse::forbidden("No token provided"));
    }

    let oauth_token = match OAuthToken::get_by_token(
        &req_entity.token.unwrap().token,
        &db.database(OAuthToken::COLLECTION_NAME),
    )
    .await
    {
        Ok(token) => token,
        Err(_) => {
            return json_response(HttpResponse::internal_error("Failed to revoke token"));
        }
    };

    match oauth_token.delete(&db).await {
        Ok(_) => json_response(HttpResponse::success_no_data("Token revoked")),
        Err(err) => json_response(err.into()),
    }
}
