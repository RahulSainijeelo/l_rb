use crate::models::Claims;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use poem::{
    http::StatusCode,
    middleware::Middleware,
    Endpoint, IntoResponse, Request, Response, Result,
};
use std::env;

pub fn create_jwt(user_id: String, role: String) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user_id,
        role,
        exp: expiration as usize,
    };

    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
}

pub struct AuthMiddleware;

impl<E: Endpoint> Middleware<E> for AuthMiddleware {
    type Output = AuthEndpoint<E>;

    fn transform(&self, ep: E) -> Self::Output {
        AuthEndpoint { ep }
    }
}

pub struct AuthEndpoint<E> {
    ep: E,
}

#[async_trait::async_trait]
impl<E: Endpoint> Endpoint for AuthEndpoint<E> {
    type Output = Response;

    async fn call(&self, mut req: Request) -> Result<Self::Output> {
        let auth_header = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok());

        if let Some(auth_header) = auth_header {
            if auth_header.starts_with("Bearer ") {
                let token = &auth_header[7..];
                let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
                
                let validation = Validation::default();
                let token_data = decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(secret.as_ref()),
                    &validation,
                );

                if let Ok(data) = token_data {
                    // Inject claims into request extensions (like req.user in Express)
                    req.extensions_mut().insert(data.claims);
                    return self.ep.call(req).await.map(IntoResponse::into_response);
                }
            }
        }

        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body("Unauthorized"))
    }
}
