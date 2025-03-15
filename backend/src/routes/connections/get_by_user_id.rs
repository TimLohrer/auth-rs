use crate::{
    auth::auth::AuthEntity,
    db::AuthRsDatabase,
    models::{
        http_response::HttpResponse,
        oauth_application::{OAuthApplication, OAuthApplicationDTO},
        oauth_scope::{OAuthScope, ScopeActions},
        oauth_token::OAuthToken,
    },
    utils::parse_uuid,
};
use mongodb::bson::{doc, DateTime, Uuid};
use rocket::{
    get,
    serde::{json::Json, Deserialize, Serialize},
};
use rocket_db_pools::Connection;

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct OAuthConnection {
    #[serde(rename = "_id")]
    pub id: Uuid,
    pub application: OAuthApplicationDTO,
    pub user_id: Uuid,
    pub scope: Vec<OAuthScope>,
    pub expires_in: u64,
    pub created_at: DateTime,
}

#[allow(unused)]
#[get("/users/<id>/connections", format = "json")]
pub async fn get_by_user_id(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    id: &str,
) -> Json<HttpResponse<Vec<OAuthConnection>>> {
    if req_entity.is_token()
        && (!req_entity
            .token
            .clone()
            .unwrap()
            .check_scope(OAuthScope::Connections(ScopeActions::Read))
            || req_entity
                .token
                .clone()
                .unwrap()
                .check_scope(OAuthScope::Connections(ScopeActions::All)))
    {
        return Json(HttpResponse::forbidden("Forbidden"));
    }

    let uuid = match parse_uuid(id) {
        Ok(uuid) => uuid,
        Err(err) => return Json(err.into()),
    };

    if (req_entity.is_user()
        && req_entity.user_id != uuid
        && !req_entity.user.clone().unwrap().is_admin())
        || req_entity.is_token() && req_entity.user_id != uuid
    {
        return Json(HttpResponse::forbidden("Missing permissions!"));
    }

    let connected_applications = match OAuthToken::get_by_user_id(uuid, &db).await {
        Ok(tokens) => tokens,
        Err(err) => {
            return Json(err.into());
        }
    };

    let filter = doc! {
        "_id": {
            "$in": connected_applications.iter().map(|token| token.clone().application_id).collect::<Vec<Uuid>>()
        }
    };

    let applications = match OAuthApplication::get_all(&db, Some(filter)).await {
        Ok(applications) => applications,
        Err(err) => return Json(err.into()),
    };

    Json(HttpResponse {
        status: 200,
        message: "Found connections by user id".to_string(),
        data: Some(
            connected_applications
                .iter()
                .map(|token| {
                    let application = applications
                        .iter()
                        .find(|app| app.id == token.application_id)
                        .unwrap();
                    OAuthConnection {
                        id: token.id,
                        application: application.to_dto(),
                        user_id: token.user_id,
                        scope: token.scope.clone(),
                        expires_in: token.expires_in,
                        created_at: token.created_at,
                    }
                })
                .collect::<Vec<OAuthConnection>>(),
        ),
    })
}
