use crate::security::SecurityConfig;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Authentication credentials
#[derive(Debug, Clone)]
pub enum Credentials {
    UsernamePassword {
        username: String,
        password: String,
        ip_address: Option<String>,
    },
    JwtToken {
        token: String,
        ip_address: Option<String>,
    },
    ApiKey {
        key: String,
        ip_address: Option<String>,
    },
    OAuth2 {
        provider: String,
        access_token: String,
        ip_address: Option<String>,
    },
}

impl Credentials {
    pub fn user_id(&self) -> &str {
        match self {
            Credentials::UsernamePassword { username, .. } => username,
            Credentials::JwtToken { .. } => "jwt_user",
            Credentials::ApiKey { .. } => "api_user",
            Credentials::OAuth2 { .. } => "oauth_user",
        }
    }

    pub fn auth_method(&self) -> &str {
        match self {
            Credentials::UsernamePassword { .. } => "username_password",
            Credentials::JwtToken { .. } => "jwt",
            Credentials::ApiKey { .. } => "api_key",
            Credentials::OAuth2 { .. } => "oauth2",
        }
    }

    pub fn ip_address(&self) -> Option<String> {
        match self {
            Credentials::UsernamePassword { ip_address, .. } => ip_address.clone(),
            Credentials::JwtToken { ip_address, .. } => ip_address.clone(),
            Credentials::ApiKey { ip_address, .. } => ip_address.clone(),
            Credentials::OAuth2 { ip_address, .. } => ip_address.clone(),
        }
    }
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub user_id: String,
    pub tenant_id: Option<String>,
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: HashMap<String, String>,
}

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String, // Subject (user ID)
    pub exp: i64,    // Expiration time
    pub iat: i64,    // Issued at
    pub iss: String, // Issuer
    pub aud: String, // Audience
    pub tenant_id: Option<String>,
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
}

/// Authentication service trait
#[async_trait]
pub trait AuthenticationService: Send + Sync {
    async fn authenticate(
        &self,
        credentials: &Credentials,
    ) -> crate::core::error::Result<AuthenticationResult>;
    async fn validate_token(&self, token: &str)
        -> crate::core::error::Result<AuthenticationResult>;
    async fn create_token(
        &self,
        user_id: &str,
        permissions: Vec<String>,
    ) -> crate::core::error::Result<String>;
    async fn revoke_token(&self, token: &str) -> crate::core::error::Result<()>;
}

/// JWT-based authentication service
pub struct JwtAuthenticationService {
    config: Arc<SecurityConfig>,
    secret: Vec<u8>,
}

impl JwtAuthenticationService {
    pub fn new(config: Arc<SecurityConfig>) -> crate::core::error::Result<Self> {
        let secret = config
            .jwt_secret
            .as_ref()
            .ok_or_else(|| {
                crate::core::error::RustChainError::Security(
                    "JWT secret not configured".to_string(),
                )
            })?
            .as_bytes()
            .to_vec();

        Ok(Self { config, secret })
    }

    fn _generate_secret() -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(uuid::Uuid::new_v4().to_string());
        hex::encode(hasher.finalize())
    }
}

#[async_trait]
impl AuthenticationService for JwtAuthenticationService {
    async fn authenticate(
        &self,
        credentials: &Credentials,
    ) -> crate::core::error::Result<AuthenticationResult> {
        match credentials {
            Credentials::UsernamePassword {
                username, password, ..
            } => {
                #[cfg(feature = "enterprise")]
                {
                    // Enterprise edition: implement basic authentication
                    let admin_user = std::env::var("RUSTCHAIN_ADMIN_USER")
                        .unwrap_or_else(|_| "admin".to_string());
                    let admin_pass = std::env::var("RUSTCHAIN_ADMIN_PASS")
                        .unwrap_or_else(|_| "change_me_immediately".to_string());

                    if *username == admin_user && *password == admin_pass {
                        Ok(AuthenticationResult {
                            user_id: username.clone(),
                            tenant_id: Some("default".to_string()),
                            permissions: vec![
                                "admin:system".to_string(),
                                "read:missions".to_string(),
                                "write:missions".to_string(),
                            ],
                            roles: vec!["admin".to_string()],
                            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
                            metadata: HashMap::new(),
                        })
                    } else {
                        Err(crate::core::error::RustChainError::Security(
                            "Invalid credentials".to_string(),
                        ))
                    }
                }

                #[cfg(not(feature = "enterprise"))]
                {
                    // Community edition: authentication not implemented
                    Err(crate::core::error::RustChainError::Security(
                        "Authentication requires enterprise features. Use --features enterprise to enable.".to_string()
                    ))
                }
            }

            Credentials::JwtToken { token, .. } => self.validate_token(token).await,

            Credentials::ApiKey { key, .. } => {
                #[cfg(feature = "enterprise")]
                {
                    // Enterprise edition: implement basic API key authentication
                    let expected_key = std::env::var("RUSTCHAIN_API_KEY")
                        .unwrap_or_else(|_| "change_me_api_key".to_string());

                    if *key == expected_key {
                        Ok(AuthenticationResult {
                            user_id: "api_client".to_string(),
                            tenant_id: Some("default".to_string()),
                            permissions: vec!["read:missions".to_string()],
                            roles: vec!["client".to_string()],
                            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
                            metadata: HashMap::new(),
                        })
                    } else {
                        Err(crate::core::error::RustChainError::Security(
                            "Invalid API key".to_string(),
                        ))
                    }
                }

                #[cfg(not(feature = "enterprise"))]
                {
                    // Community edition: API key auth not implemented
                    Err(crate::core::error::RustChainError::Security(
                        "API key authentication requires enterprise features. Use --features enterprise to enable.".to_string()
                    ))
                }
            }

            Credentials::OAuth2 {
                provider,
                access_token: _access_token,
                ..
            } => {
                // Community edition: OAuth not implemented
                Err(crate::core::error::RustChainError::Security(
                    format!("OAuth2 authentication for {} requires enterprise features. Use --features enterprise to enable.", provider)
                ))
            }
        }
    }

    async fn validate_token(
        &self,
        token: &str,
    ) -> crate::core::error::Result<AuthenticationResult> {
        #[cfg(feature = "enterprise")]
        {
            use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

            let validation = Validation::new(Algorithm::HS256);
            let token_data =
                decode::<JwtClaims>(token, &DecodingKey::from_secret(&self.secret), &validation)
                    .map_err(|e| {
                        crate::core::error::RustChainError::Security(format!(
                            "Invalid JWT token: {}",
                            e
                        ))
                    })?;

            let claims = token_data.claims;

            // Check expiration
            if claims.exp < Utc::now().timestamp() {
                return Err(crate::core::error::RustChainError::Security(
                    "Token expired".to_string(),
                ));
            }

            Ok(AuthenticationResult {
                user_id: claims.sub,
                tenant_id: claims.tenant_id,
                permissions: claims.permissions,
                roles: claims.roles,
                expires_at: Some(DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(Utc::now)),
                metadata: HashMap::new(),
            })
        }

        #[cfg(not(feature = "enterprise"))]
        {
            Err(crate::core::error::RustChainError::Security(
                "JWT validation requires enterprise features".to_string(),
            ))
        }
    }

    async fn create_token(
        &self,
        user_id: &str,
        permissions: Vec<String>,
    ) -> crate::core::error::Result<String> {
        #[cfg(feature = "enterprise")]
        {
            use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

            let now = Utc::now();
            let expires_at =
                now + chrono::Duration::minutes(self.config.session_timeout_minutes as i64);

            let claims = JwtClaims {
                sub: user_id.to_string(),
                exp: expires_at.timestamp(),
                iat: now.timestamp(),
                iss: "rustchain".to_string(),
                aud: "rustchain-client".to_string(),
                tenant_id: Some("default".to_string()),
                permissions,
                roles: vec!["user".to_string()],
            };

            let header = Header::new(Algorithm::HS256);
            let token =
                encode(&header, &claims, &EncodingKey::from_secret(&self.secret)).map_err(|e| {
                    crate::core::error::RustChainError::Security(format!(
                        "Failed to create token: {}",
                        e
                    ))
                })?;

            Ok(token)
        }

        #[cfg(not(feature = "enterprise"))]
        {
            Err(crate::core::error::RustChainError::Security(
                "JWT token creation requires enterprise features".to_string(),
            ))
        }
    }

    async fn revoke_token(&self, _token: &str) -> crate::core::error::Result<()> {
        // Community edition: token revocation not implemented
        Err(crate::core::error::RustChainError::Security(
            "Token revocation requires enterprise features. Use --features enterprise to enable."
                .to_string(),
        ))
    }
}

/// Multi-factor authentication service
pub struct MfaAuthenticationService {
    base_service: Arc<dyn AuthenticationService>,
}

impl MfaAuthenticationService {
    pub fn new(base_service: Arc<dyn AuthenticationService>) -> Self {
        Self { base_service }
    }

    pub async fn verify_totp(
        &self,
        _user_id: &str,
        _code: &str,
    ) -> crate::core::error::Result<bool> {
        // Community edition: TOTP verification not implemented
        Err(crate::core::error::RustChainError::Security(
            "TOTP verification requires enterprise features. Use --features enterprise to enable."
                .to_string(),
        ))
    }

    pub async fn send_sms_code(
        &self,
        _user_id: &str,
        _phone: &str,
    ) -> crate::core::error::Result<String> {
        // Community edition: SMS sending not implemented
        Err(crate::core::error::RustChainError::Security(
            "SMS code sending requires enterprise features. Use --features enterprise to enable."
                .to_string(),
        ))
    }
}

#[async_trait]
impl AuthenticationService for MfaAuthenticationService {
    async fn authenticate(
        &self,
        credentials: &Credentials,
    ) -> crate::core::error::Result<AuthenticationResult> {
        // First, authenticate with the base service
        let mut result = self.base_service.authenticate(credentials).await?;

        // Add MFA requirement to metadata
        result
            .metadata
            .insert("mfa_required".to_string(), "true".to_string());
        result
            .metadata
            .insert("mfa_methods".to_string(), "totp,sms".to_string());

        Ok(result)
    }

    async fn validate_token(
        &self,
        token: &str,
    ) -> crate::core::error::Result<AuthenticationResult> {
        self.base_service.validate_token(token).await
    }

    async fn create_token(
        &self,
        user_id: &str,
        permissions: Vec<String>,
    ) -> crate::core::error::Result<String> {
        self.base_service.create_token(user_id, permissions).await
    }

    async fn revoke_token(&self, token: &str) -> crate::core::error::Result<()> {
        self.base_service.revoke_token(token).await
    }
}

#[cfg(all(test, feature = "enterprise"))]
mod tests {
    use super::*;

    fn set_auth_env() {
        std::env::set_var("RUSTCHAIN_ADMIN_USER", "admin");
        std::env::set_var("RUSTCHAIN_ADMIN_PASS", "admin123");
        std::env::set_var("RUSTCHAIN_API_KEY", "rustchain_api_key_12345");
    }

    #[tokio::test]
    async fn test_username_password_auth() {
        set_auth_env();
        let config = Arc::new(SecurityConfig {
            jwt_secret: Some("test_secret_key_12345".to_string()),
            ..Default::default()
        });

        let auth_service = JwtAuthenticationService::new(config).unwrap();

        let credentials = Credentials::UsernamePassword {
            username: "admin".to_string(),
            password: "admin123".to_string(),
            ip_address: Some("127.0.0.1".to_string()),
        };

        let result = auth_service.authenticate(&credentials).await.unwrap();

        assert_eq!(result.user_id, "admin");
        assert!(result.permissions.contains(&"admin:system".to_string()));
    }

    #[tokio::test]
    async fn test_invalid_credentials() {
        set_auth_env();
        let config = Arc::new(SecurityConfig {
            jwt_secret: Some("test_secret_key_12345".to_string()),
            ..Default::default()
        });

        let auth_service = JwtAuthenticationService::new(config).unwrap();

        let credentials = Credentials::UsernamePassword {
            username: "admin".to_string(),
            password: "wrong_password".to_string(),
            ip_address: Some("127.0.0.1".to_string()),
        };

        let result = auth_service.authenticate(&credentials).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_api_key_auth() {
        set_auth_env();
        let config = Arc::new(SecurityConfig {
            jwt_secret: Some("test_secret_key_12345".to_string()),
            ..Default::default()
        });

        let auth_service = JwtAuthenticationService::new(config).unwrap();

        let credentials = Credentials::ApiKey {
            key: "rustchain_api_key_12345".to_string(),
            ip_address: Some("127.0.0.1".to_string()),
        };

        let result = auth_service.authenticate(&credentials).await.unwrap();

        assert_eq!(result.user_id, "api_client");
        assert!(result.permissions.contains(&"read:missions".to_string()));
    }
}
