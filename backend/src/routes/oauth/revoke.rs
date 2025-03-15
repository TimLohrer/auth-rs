use rocket::{post, serde::json::Json};
use rocket_db_pools::Connection;

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
) -> Json<HttpResponse<()>> {
    if !req_entity.is_token() {
        return Json(HttpResponse::forbidden("No token provided"));
    }

    let oauth_token = match OAuthToken::get_by_token(
        &req_entity.token.unwrap().token,
        &db.database(OAuthToken::COLLECTION_NAME),
    )
    .await
    {
        Ok(token) => token,
        Err(_) => {
            return Json(HttpResponse::internal_error("Failed to revoke token"));
        }
    };

    match oauth_token.delete(&db).await {
        Ok(_) => Json(HttpResponse::success_no_data("Token revoked")),
        Err(err) => Json(err.into()),
    }
}
