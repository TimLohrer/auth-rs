use mongodb::bson::Uuid;
use rocket::http::Status;
use rocket::{
    form::Form,
    post,
    serde::{json::Json, Deserialize, Serialize},
    FromForm,
};
use rocket_db_pools::Connection;

use crate::{
    db::AuthRsDatabase,
    models::{oauth_scope::OAuthScope, oauth_token::OAuthToken},
    OAUTH_CODES,
};

#[derive(Debug, Deserialize, FromForm)]
#[serde(crate = "rocket::serde")]
pub struct TokenOAuthFieldData {
    #[form(field = "client_id")]
    pub client_id: String,
    #[form(field = "client_secret")]
    pub client_secret: String,
    #[form(field = "grant_type")]
    pub grant_type: String,
    #[form(field = "code")]
    pub code: u32,
    #[form(field = "redirect_uri")]
    pub redirect_uri: String,
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct TokenOAuthData {
    pub client_id: Uuid,
    pub client_secret: String,
    pub grant_type: String,
    pub user_id: Option<Uuid>,
    pub code: u32,
    pub scope: Option<Vec<OAuthScope>>,
    pub redirect_uri: String,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
pub struct TokenOAuthResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
}

#[allow(unused)]
#[post(
    "/oauth/token",
    format = "application/x-www-form-urlencoded",
    data = "<data>"
)]
pub async fn get_oauth_token(
    db: Connection<AuthRsDatabase>,
    data: Form<TokenOAuthFieldData>,
) -> (Status, Option<Json<TokenOAuthResponse>>) {
    let form_data = data.into_inner();

    let client_id = match Uuid::parse_str(&form_data.client_id) {
        Ok(client_id) => client_id,
        Err(_) => return (Status::BadRequest, None),
    };

    let data = TokenOAuthData {
        client_id,
        client_secret: form_data.client_secret,
        grant_type: form_data.grant_type,
        user_id: None,
        code: form_data.code,
        scope: None,
        redirect_uri: form_data.redirect_uri,
    };

    let mut codes = OAUTH_CODES.lock().await;
    let code_data = match codes.get(&data.code) {
        Some(code_data) => code_data,
        None => return (Status::Unauthorized, None),
    };

    if code_data.client_id != data.client_id
        || code_data.grant_type.trim() != data.grant_type.trim()
        || code_data.client_secret.trim() != data.client_secret.trim()
        || code_data.redirect_uri.trim() != data.redirect_uri.trim()
    {
        return (Status::Unauthorized, None);
    }

    let mut existing_tokens = match OAuthToken::get_by_user_and_application_id(
        code_data.user_id.unwrap(),
        code_data.client_id,
        &db,
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(err) => return (Status::BadRequest, None),
    };

    let token = if !existing_tokens.is_empty() {
        // TODO: implement a proper scope check here
        if existing_tokens[0].scope.len() > code_data.scope.as_ref().unwrap().len() {
            existing_tokens[0].clone()
        } else {
            existing_tokens[0]
                .reauthenticate(code_data.scope.as_ref().unwrap().clone(), &db)
                .await
                .unwrap()
        }
    } else {
        match OAuthToken::new(
            code_data.client_id,
            code_data.user_id.unwrap(),
            code_data.scope.clone().unwrap(),
            30 * 24 * 60 * 60 * 1000,
        )
        .unwrap()
        .insert(&db)
        .await
        {
            Ok(token) => token,
            Err(_) => return (Status::InternalServerError, None),
        }
    };

    codes.remove(&data.code);

    drop(codes);

    (
        Status::Ok,
        Some(Json(TokenOAuthResponse {
            access_token: token.token.to_string(),
            token_type: "Bearer".to_string(),
            expires_in: token.expires_in,
            scope: token
                .scope
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>()
                .join(","),
        })),
    )
}
