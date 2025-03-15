use rocket::serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct HttpResponse<T> {
    pub status: u16,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T> HttpResponse<T> {
    // Create a success response with data
    pub fn success(message: &str, data: T) -> Self {
        Self {
            status: 200,
            message: message.to_string(),
            data: Some(data),
        }
    }

    // Create a success response without data
    pub fn success_no_data(message: &str) -> Self {
        Self {
            status: 200,
            message: message.to_string(),
            data: None,
        }
    }

    // Create an error response
    pub fn error(status: u16, message: &str) -> Self {
        Self {
            status,
            message: message.to_string(),
            data: None,
        }
    }

    // Common error responses
    pub fn not_found(message: &str) -> Self {
        Self::error(404, message)
    }

    pub fn bad_request(message: &str) -> Self {
        Self::error(400, message)
    }

    pub fn unauthorized(message: &str) -> Self {
        Self::error(401, message)
    }

    pub fn forbidden(message: &str) -> Self {
        Self::error(403, message)
    }

    pub fn internal_error(message: &str) -> Self {
        Self::error(500, message)
    }
}
