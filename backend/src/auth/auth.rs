use crate::{
    db::{get_main_db_name, AuthRsDatabase},
    errors::{AppError, AppResult},
    models::{oauth_token::OAuthToken, user::User},
};
use mongodb::bson::Uuid;
use rocket::{http::Status, outcome::Outcome, request::FromRequest, Request};

#[derive(Debug, Clone)]
pub struct AuthEntity {
    pub user_id: Uuid,
    pub user: Option<User>,
    pub token: Option<OAuthToken>,
}

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
                    "Bearer" => match User::get_full_by_token(token_value.to_owned(), &db).await {
                        Ok(user) => {
                            if user.disabled {
                                return Outcome::Error((Status::Forbidden, AuthError::Forbidden));
                            }

                            Outcome::Success(AuthEntity::from_user(user))
                        }
                        Err(_) => match OAuthToken::get_by_token(token_value, &db).await {
                            Ok(token) => {
                                if token.is_expired() {
                                    return Outcome::Error((
                                        Status::Unauthorized,
                                        AuthError::InvalidToken,
                                    ));
                                }

                                Outcome::Success(AuthEntity::from_token(token))
                            }
                            Err(_) => {
                                Outcome::Error((Status::Unauthorized, AuthError::Unauthorized))
                            }
                        },
                    },
                    _ => Outcome::Error((Status::Unauthorized, AuthError::InvalidToken)),
                }
            }
            None => Outcome::Error((Status::Unauthorized, AuthError::Unauthorized)),
        }
    }
}
