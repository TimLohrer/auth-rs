use crate::{
    auth::jwt::verify_id_token, db::{get_main_db_name, AuthRsDatabase}, errors::{AppError, AppResult}, models::{oauth_token::OAuthToken, user::User}
};
use mongodb::bson::Uuid;
use rocket::{http::Status, outcome::Outcome, request::FromRequest, Request};

#[derive(Debug, Clone)]
pub struct AuthEntity {
    pub user_id: Uuid,
    pub user: Option<User>,
    pub token: Option<OAuthToken>,
}

#[allow(unused)]
impl AuthEntity {
    pub fn from_user(user: User) -> Self {
        Self {
            user_id: user.id,
            user: Some(user),
            token: None,
        }
    }

    pub fn from_token(token: OAuthToken) -> Self {
        Self {
            user_id: token.user_id,
            user: None,
            token: Some(token),
        }
    }

    pub fn is_user(&self) -> bool {
        self.user.is_some()
    }

    pub fn is_token(&self) -> bool {
        self.token.is_some()
    }

    pub fn user(&self) -> AppResult<&User> {
        self.user.as_ref().ok_or(AppError::MissingPermissions)
    }

    pub fn token(&self) -> AppResult<&OAuthToken> {
        self.token.as_ref().ok_or(AppError::InvalidToken)
    }
}

#[derive(Debug, Clone)]
#[allow(unused)]
pub struct OptionalAuthEntity {
    pub user_id: Option<Uuid>,
    pub user: Option<User>,
    pub token: Option<OAuthToken>,
}

#[allow(unused)]
impl OptionalAuthEntity {
    pub fn from_user(user: User) -> Self {
        Self {
            user_id: Some(user.id),
            user: Some(user),
            token: None,
        }
    }

    pub fn from_token(token: OAuthToken) -> Self {
        Self {
            user_id: Some(token.user_id),
            user: None,
            token: Some(token),
        }
    }

    pub fn from_empty() -> Self {
        Self {
            user_id: None,
            user: None,
            token: None,
        }
    }

    pub fn is_user(&self) -> bool {
        self.user.is_some()
    }

    pub fn is_token(&self) -> bool {
        self.token.is_some()
    }

    pub fn user(&self) -> AppResult<&User> {
        self.user.as_ref().ok_or(AppError::MissingPermissions)
    }

    pub fn token(&self) -> AppResult<&OAuthToken> {
        self.token.as_ref().ok_or(AppError::InvalidToken)
    }
}

#[derive(Debug)]
pub enum AuthError {
    DatabaseError,
    InvalidToken,
    Unauthorized,
    Forbidden,
}

impl From<AuthError> for AppError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::DatabaseError => AppError::InternalServerError("Database error".to_string()),
            AuthError::InvalidToken => AppError::InvalidToken,
            AuthError::Unauthorized => AppError::AuthenticationError("Unauthorized".to_string()),
            AuthError::Forbidden => AppError::UserDisabled,
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthEntity {
    type Error = AuthError;

    async fn from_request(
        request: &'r Request<'_>,
    ) -> Outcome<AuthEntity, (Status, AuthError), Status> {
        let db = match request.guard::<&AuthRsDatabase>().await {
            Outcome::Success(db) => db.database(get_main_db_name()),
            _ => return Outcome::Error((Status::InternalServerError, AuthError::DatabaseError)),
        };

        let auth_header = request.headers().get_one("Authorization");

        match auth_header {
            Some(token) => {
                let token_parts: Vec<&str> = token.split_whitespace().collect();

                if token_parts.len() != 2 {
                    return Outcome::Error((Status::Unauthorized, AuthError::InvalidToken));
                }

                let token_type = token_parts[0];
                let token_value = token_parts[1];

                if token_value.is_empty() {
                    return Outcome::Error((Status::Unauthorized, AuthError::InvalidToken));
                }

                match token_type {
                    "Bearer" => {
                        let user_id_and_claims = match verify_id_token(&token_value.to_owned()) {
                            Ok(data) => {
                                match Uuid::parse_str(&data.claims.sub) {
                                    Ok(uuid) => (uuid, data.claims),
                                    Err(_) => return Outcome::Error((Status::InternalServerError, AuthError::DatabaseError))
                                }
                            },
                            Err(_) => return Outcome::Error((Status::Forbidden, AuthError::InvalidToken)),
                        };

                        let (user_id, claims) = user_id_and_claims;

                        if claims.sub == claims.aud {
                            match User::get_by_id_db_param(user_id, &db).await {
                                Ok(user) => {
                                    if user.disabled || user.get_device_by_token(&token_value.to_owned()).is_none() {
                                        return Outcome::Error((Status::Forbidden, AuthError::Forbidden));
                                    }

                                    Outcome::Success(AuthEntity::from_user(user))
                                }
                                Err(_) => Outcome::Error((Status::NotFound, AuthError::DatabaseError)),
                            }
                        } else {
                            match OAuthToken::get_by_token(token_value, &db).await {
                                Ok(token) => {
                                    if token.is_expired() {
                                        return Outcome::Error((
                                            Status::Unauthorized,
                                            AuthError::InvalidToken,
                                        ));
                                    }

                                    Outcome::Success(AuthEntity::from_token(token))
                                }
                                Err(_) => Outcome::Error((Status::Forbidden, AuthError::InvalidToken))
                            }
                        }
                    },
                    _ => Outcome::Error((Status::Unauthorized, AuthError::Unauthorized)),
                }
            }
            None => Outcome::Error((Status::Unauthorized, AuthError::Unauthorized)),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OptionalAuthEntity {
    type Error = AuthError;

    async fn from_request(
        request: &'r Request<'_>,
    ) -> Outcome<OptionalAuthEntity, (Status, AuthError), Status> {
        let db = match request.guard::<&AuthRsDatabase>().await {
            Outcome::Success(db) => db.database(get_main_db_name()),
            _ => return Outcome::Error((Status::InternalServerError, AuthError::DatabaseError)),
        };

        let auth_header = request.headers().get_one("Authorization");

        match auth_header {
            Some(token) => {
                let token_parts: Vec<&str> = token.split_whitespace().collect();

                if token_parts.len() != 2 {
                    return Outcome::Success(OptionalAuthEntity::from_empty());
                }

                let token_type = token_parts[0];
                let token_value = token_parts[1];

                if token_value.is_empty() {
                    return Outcome::Success(OptionalAuthEntity::from_empty());
                }

                match token_type {
                    "Bearer" => {
                        let user_id_and_claims = match verify_id_token(&token_value.to_owned()) {
                            Ok(data) => {
                                match Uuid::parse_str(&data.claims.sub) {
                                    Ok(uuid) => (uuid, data.claims),
                                    Err(_) => return Outcome::Success(OptionalAuthEntity::from_empty())
                                }
                            },
                            Err(_) => return Outcome::Success(OptionalAuthEntity::from_empty()),
                        };

                        let (user_id, claims) = user_id_and_claims;

                        if claims.sub == claims.aud {
                            match User::get_by_id_db_param(user_id, &db).await {
                                Ok(user) => {
                                    if user.disabled || user.get_device_by_token(&token_value.to_owned()).is_none() {
                                        return Outcome::Success(OptionalAuthEntity::from_empty());
                                    }

                                    Outcome::Success(OptionalAuthEntity::from_user(user))
                                }
                                Err(_) => Outcome::Success(OptionalAuthEntity::from_empty()),
                            }
                        } else {
                            match OAuthToken::get_by_token(token_value, &db).await {
                                Ok(token) => {
                                    if token.is_expired() {
                                        return Outcome::Success(OptionalAuthEntity::from_empty());
                                    }

                                    Outcome::Success(OptionalAuthEntity::from_token(token))
                                }
                                Err(_) => Outcome::Success(OptionalAuthEntity::from_empty()),
                            }
                        }
                    },
                    _ => Outcome::Success(OptionalAuthEntity::from_empty()),
                }
            }
            None => Outcome::Success(OptionalAuthEntity::from_empty()),
        }
    }
}

pub struct IpAddr {
    pub addr: Option<String>
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for IpAddr {
    type Error = (Status, ());

    async fn from_request(request: &'r Request<'_>) -> Outcome<IpAddr, (Status, Self::Error), Status> {
        match request.headers().get_one("CF-Connecting-IP") {
            Some(cloudflare_client_ip) => Outcome::Success(IpAddr { addr: Some(cloudflare_client_ip.to_string()) }),
            None => match request.client_ip() {
                Some(ip) => Outcome::Success(IpAddr { addr: Some(ip.to_string()) }),
                None => Outcome::Success(IpAddr { addr: None })
            }
        }
    }
}

#[allow(unused)]
pub struct RequestHeaders {
    pub headers: Vec<(String, String)>
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RequestHeaders {
    type Error = (Status, ());

    async fn from_request(request: &'r Request<'_>) -> Outcome<RequestHeaders, (Status, Self::Error), Status> {
        Outcome::Success(RequestHeaders { headers: request.headers().iter().map(|h| (h.name().to_string(), h.value().to_string())).collect() } )
    }
}