use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String, // Subject (user ID)
    pub exp: usize,  // Expiration time
    pub iat: usize,  // Issued at
    pub email: Option<String>,
    pub role: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String,      // Subject (user ID)
    pub exp: usize,       // Expiration time
    pub token_id: String, // Unique identifier for the refresh token
}

#[derive(Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

pub struct TokenService {
    pub access_token_secret: Vec<u8>,
    pub refresh_token_secret: Vec<u8>,
}

impl Default for TokenService {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenService {
    pub fn new() -> Self {
        TokenService {
            access_token_secret: std::env::var("ACCESS_TOKEN_SECRET")
                .unwrap_or_else(|_| "default_access_token_secret".to_string())
                .into_bytes(),
            refresh_token_secret: std::env::var("REFRESH_TOKEN_SECRET")
                .unwrap_or_else(|_| "default_refresh_token_secret".to_string())
                .into_bytes(),
        }
    }

    pub fn create_tokens(
        &self,
        user_id: &str,
        email: Option<String>,
        role: &str,
    ) -> Result<TokenPair, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let iat = now.timestamp() as usize;

        // Access token expires in 15 minutes
        let access_token_exp = (now + Duration::minutes(15)).timestamp() as usize;

        // Refresh token expires in 7 days
        let refresh_token_exp = (now + Duration::days(7)).timestamp() as usize;

        // Generate a unique ID for the refresh token
        let refresh_token_id = Uuid::new_v4().to_string();

        // Create access token claims
        let access_claims = AccessTokenClaims {
            sub: user_id.to_string(),
            exp: access_token_exp,
            iat,
            email,
            role: role.to_string(),
        };

        // Create refresh token claims
        let refresh_claims = RefreshTokenClaims {
            sub: user_id.to_string(),
            exp: refresh_token_exp,
            token_id: refresh_token_id.clone(),
        };

        // Encode access token
        let access_token = encode(
            &Header::default(),
            &access_claims,
            &EncodingKey::from_secret(&self.access_token_secret),
        )?;

        // Encode refresh token
        let refresh_token = encode(
            &Header::default(),
            &refresh_claims,
            &EncodingKey::from_secret(&self.refresh_token_secret),
        )?;

        Ok(TokenPair {
            access_token,
            refresh_token,
        })
    }

    pub fn decode_skip_verify_access_token(
        &self,
        token: &str,
    ) -> Result<AccessTokenClaims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::default();
        validation.validate_exp = false;
        decode::<AccessTokenClaims>(
            token,
            &DecodingKey::from_secret(&self.access_token_secret),
            &validation,
        )
        .map(|data| data.claims)
    }

    pub fn verify_access_token(
        &self,
        token: &str,
    ) -> Result<AccessTokenClaims, jsonwebtoken::errors::Error> {
        decode::<AccessTokenClaims>(
            token,
            &DecodingKey::from_secret(&self.access_token_secret),
            &Validation::default(),
        )
        .map(|data| data.claims)
    }

    fn verify_refresh_token(
        &self,
        token: &str,
    ) -> Result<RefreshTokenClaims, jsonwebtoken::errors::Error> {
        decode::<RefreshTokenClaims>(
            token,
            &DecodingKey::from_secret(&self.refresh_token_secret),
            &Validation::default(),
        )
        .map(|data| data.claims)
    }

    pub fn refresh_access_token(
        &self,
        access_token: &str,
        refresh_token: &str,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let access_claims = self.decode_skip_verify_access_token(access_token)?;
        // Verify the refresh token first
        self.verify_refresh_token(refresh_token)?;

        // Create a new access token for the same user
        let now = Utc::now();
        let iat = now.timestamp() as usize;
        let access_token_exp = (now + Duration::minutes(15)).timestamp() as usize;

        let new_access_claims = AccessTokenClaims {
            sub: access_claims.sub,
            exp: access_token_exp,
            iat,
            email: access_claims.email, // You might want to retrieve this from your user store
            role: access_claims.role,   // You might want to retrieve this from your user store
        };

        // Encode and return new access token
        encode(
            &Header::default(),
            &new_access_claims,
            &EncodingKey::from_secret(&self.access_token_secret),
        )
    }
}
