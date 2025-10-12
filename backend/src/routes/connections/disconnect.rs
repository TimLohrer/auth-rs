use rocket::http::Status;
use rocket::{delete, serde::json::Json};
use rocket_db_pools::Connection;

use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        http_response::HttpResponse,
        oauth_application::OAuthApplication,
        oauth_scope::{OAuthScope, ScopeActions},
        oauth_token::OAuthToken,
    },
    utils::parse_uuid::parse_uuid,
};

#[allow(unused)]
#[delete("/connections/<id>")]
pub async fn disconnect(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
) -> (Status, Json<HttpResponse<()>>) {
    if req_entity.is_token()
        && (!req_entity
            .token
            .as_ref()
            .unwrap()
            .check_scope(OAuthScope::Connections(ScopeActions::Delete))
            || req_entity
                .token
                .as_ref()
                .unwrap()
                .check_scope(OAuthScope::Connections(ScopeActions::All)))
    {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return json_response(err.into()),
    };

    if (req_entity.is_user()
        && req_entity.user_id != uuid
        && !req_entity.user.clone().unwrap().is_admin())
    {
        return json_response(HttpResponse::forbidden("Missing permissions!"));
    }

    let oauth_application = match OAuthApplication::get_by_id(uuid, &db).await {
        Ok(application) => application,
        Err(err) => return json_response(err.into()),
    };

    let tokens = match OAuthToken::get_by_application_id(oauth_application.id, &db).await {
        Ok(tokens) => tokens,
        Err(err) => {
            return json_response(err.into());
        }
    };

    if tokens.is_empty() {
        return json_response(HttpResponse::not_found(
            "You are not connected to that application",
        ));
    }

    for token in tokens {
        match token.delete(&db).await {
            Ok(_) => (),
            Err(err) => {
                return json_response(err.into());
            }
        }
    }

    json_response(HttpResponse::success_no_data(
        "Successfully disconnected from application",
    ))
}
