use rocket::http::Status;
use rocket::{
    error, post,
    serde::{json::Json, Deserialize},
};
use rocket_db_pools::Connection;

use crate::utils::response::json_response;
use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
        oauth_application::OAuthApplication,
    },
};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct CreateOAuthApplicationData {
    name: String,
    description: Option<String>,
    redirect_uris: Vec<String>,
}

#[allow(unused)]
#[post("/oauth-applications", format = "json", data = "<data>")]
pub async fn create_oauth_application(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    data: Json<CreateOAuthApplicationData>,
) -> (Status, Json<HttpResponse<OAuthApplication>>) {
    let data = data.into_inner();

    if !req_entity.is_user() {
        return json_response(HttpResponse::forbidden("Forbidden"));
    }

    let oauth_application = match OAuthApplication::new(
        data.name,
        data.description,
        data.redirect_uris,
        req_entity.user_id,
    ) {
        Ok(oauth_application) => oauth_application,
        Err(err) => return json_response(err.into()),
    };

    match oauth_application.insert(&db).await {
        Ok(oauth_application) => {
            match AuditLog::new(
                oauth_application.id,
                AuditLogEntityType::OAuthApplication,
                AuditLogAction::Create,
                "OAuth Application created.".to_string(),
                req_entity.user_id,
                None,
                None,
            )
            .insert(&db)
            .await
            {
                Ok(_) => (),
                Err(err) => error!("{}", err),
            }

            json_response(HttpResponse {
                status: 201,
                message: "OAuth Application created".to_string(),
                data: Some(oauth_application),
            })
        }
        Err(err) => json_response(err.into()),
    }
}
