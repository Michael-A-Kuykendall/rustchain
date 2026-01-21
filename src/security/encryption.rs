use crate::security::SecurityContext;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Encryption algorithm types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
    Aes256Cbc,
}

/// Encrypted data container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub algorithm: EncryptionAlgorithm,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub tag: Option<Vec<u8>>,
    pub metadata: HashMap<String, String>,
}

/// Key derivation parameters
#[derive(Debug, Clone)]
pub struct KeyDerivationParams {
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub key_length: usize,
}

/// Encryption service trait
#[async_trait]
pub trait EncryptionService: Send + Sync {
    async fn encrypt(
        &self,
        data: &[u8],
        context: &SecurityContext,
    ) -> crate::core::error::Result<Vec<u8>>;
    async fn decrypt(
        &self,
        encrypted_data: &[u8],
        context: &SecurityContext,
    ) -> crate::core::error::Result<Vec<u8>>;
    async fn encrypt_with_key(
        &self,
        data: &[u8],
        key: &[u8],
    ) -> crate::core::error::Result<EncryptedData>;
    async fn decrypt_with_key(
        &self,
        encrypted: &EncryptedData,
        key: &[u8],
    ) -> crate::core::error::Result<Vec<u8>>;
    async fn derive_key(
        &self,
        password: &str,
        params: &KeyDerivationParams,
    ) -> crate::core::error::Result<Vec<u8>>;
    async fn generate_key(
        &self,
        algorithm: &EncryptionAlgorithm,
    ) -> crate::core::error::Result<Vec<u8>>;
}

/// AES-256-GCM encryption service
pub struct AesEncryptionService {
    master_key: Vec<u8>,
}

impl AesEncryptionService {
    pub fn new() -> crate::core::error::Result<Self> {
        // Load master key from environment or generate from seed for development
        // Production deployments should use secure key management systems
        let master_key = Self::generate_master_key()?;

        Ok(Self { master_key })
    }

    pub fn with_key(key: Vec<u8>) -> Self {
        Self { master_key: key }
    }

    fn generate_master_key() -> crate::core::error::Result<Vec<u8>> {
        use sha2::{Digest, Sha256};

        // Require explicit master key configuration - no fallbacks for security
        let seed = std::env::var("RUSTCHAIN_MASTER_KEY").map_err(|_| {
            crate::core::error::RustChainError::Security(
                "RUSTCHAIN_MASTER_KEY environment variable must be set".to_string(),
            )
        })?;

        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(b"rustchain_encryption");

        Ok(hasher.finalize().to_vec())
    }

    fn derive_data_key(&self, context: &SecurityContext) -> crate::core::error::Result<Vec<u8>> {
        // Create salt from context components
        let mut salt = Vec::new();
        salt.extend_from_slice(context.session_id.as_bytes());
        if let Some(user_id) = &context.user_id {
            salt.extend_from_slice(user_id.as_bytes());
        }
        if let Some(tenant_id) = &context.tenant_id {
            salt.extend_from_slice(tenant_id.as_bytes());
        }

        // Use PBKDF2 with 600,000 iterations for key derivation (NIST recommended)
        use pbkdf2::pbkdf2_hmac;
        let mut derived_key = [0u8; 32];
        pbkdf2_hmac::<sha2::Sha256>(&self.master_key, &salt, 600_000, &mut derived_key);

        Ok(derived_key.to_vec())
    }

    fn encrypt_aes_gcm(
        &self,
        data: &[u8],
        key: &[u8],
    ) -> crate::core::error::Result<EncryptedData> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        // Generate a random nonce
        let nonce_bytes: [u8; 12] = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(key);
            hasher.update(data);
            hasher.update(uuid::Uuid::new_v4().as_bytes());
            let hash = hasher.finalize();
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(&hash[..12]);
            nonce
        };

        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create AES-256-GCM cipher
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        // Encrypt the data
        let ciphertext = cipher.encrypt(nonce, data).map_err(|e| {
            crate::core::error::RustChainError::Security(format!(
                "AES-GCM encryption failed: {}",
                e
            ))
        })?;

        Ok(EncryptedData {
            algorithm: EncryptionAlgorithm::Aes256Gcm,
            ciphertext,
            nonce: nonce_bytes.to_vec(),
            tag: None, // AES-GCM includes the tag in the ciphertext
            metadata: HashMap::new(),
        })
    }

    fn decrypt_aes_gcm(
        &self,
        encrypted: &EncryptedData,
        key: &[u8],
    ) -> crate::core::error::Result<Vec<u8>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        let nonce = Nonce::from_slice(&encrypted.nonce);
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);

        // Decrypt the data
        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| {
                crate::core::error::RustChainError::Security(format!(
                    "AES-GCM decryption failed: {}",
                    e
                ))
            })?;

        Ok(plaintext)
    }
}

#[async_trait]
impl EncryptionService for AesEncryptionService {
    async fn encrypt(
        &self,
        data: &[u8],
        context: &SecurityContext,
    ) -> crate::core::error::Result<Vec<u8>> {
        let key = self.derive_data_key(context)?;
        let encrypted = self.encrypt_aes_gcm(data, &key)?;

        // Serialize the encrypted data
        serde_json::to_vec(&encrypted).map_err(|e| {
            crate::core::error::RustChainError::Security(format!(
                "Failed to serialize encrypted data: {}",
                e
            ))
        })
    }

    async fn decrypt(
        &self,
        encrypted_data: &[u8],
        context: &SecurityContext,
    ) -> crate::core::error::Result<Vec<u8>> {
        // Deserialize the encrypted data
        let encrypted: EncryptedData = serde_json::from_slice(encrypted_data).map_err(|e| {
            crate::core::error::RustChainError::Security(format!(
                "Failed to deserialize encrypted data: {}",
                e
            ))
        })?;

        let key = self.derive_data_key(context)?;
        self.decrypt_aes_gcm(&encrypted, &key)
    }

    async fn encrypt_with_key(
        &self,
        data: &[u8],
        key: &[u8],
    ) -> crate::core::error::Result<EncryptedData> {
        self.encrypt_aes_gcm(data, key)
    }

    async fn decrypt_with_key(
        &self,
        encrypted: &EncryptedData,
        key: &[u8],
    ) -> crate::core::error::Result<Vec<u8>> {
        self.decrypt_aes_gcm(encrypted, key)
    }

    async fn derive_key(
        &self,
        password: &str,
        params: &KeyDerivationParams,
    ) -> crate::core::error::Result<Vec<u8>> {
        // Simple PBKDF2-like key derivation (in production, use proper PBKDF2)
        use sha2::{Digest, Sha256};

        let mut key = password.as_bytes().to_vec();

        for _ in 0..params.iterations {
            let mut hasher = Sha256::new();
            hasher.update(&key);
            hasher.update(&params.salt);
            key = hasher.finalize().to_vec();
        }

        Ok(key[..params.key_length.min(32)].to_vec())
    }

    async fn generate_key(
        &self,
        algorithm: &EncryptionAlgorithm,
    ) -> crate::core::error::Result<Vec<u8>> {
        use sha2::{Digest, Sha256};

        let key_size = match algorithm {
            EncryptionAlgorithm::Aes256Gcm => 32,
            EncryptionAlgorithm::ChaCha20Poly1305 => 32,
            EncryptionAlgorithm::Aes256Cbc => 32,
        };

        let mut hasher = Sha256::new();
        hasher.update(uuid::Uuid::new_v4().as_bytes());
        hasher.update(chrono::Utc::now().timestamp().to_be_bytes());

        let hash = hasher.finalize();
        Ok(hash[..key_size].to_vec())
    }
}

/// Field-level encryption service for sensitive data
pub struct FieldEncryptionService {
    base_service: Box<dyn EncryptionService>,
}

impl FieldEncryptionService {
    pub fn new(base_service: Box<dyn EncryptionService>) -> Self {
        Self { base_service }
    }

    pub async fn encrypt_field(
        &self,
        field_name: &str,
        value: &str,
        context: &SecurityContext,
    ) -> crate::core::error::Result<String> {
        let data = format!("{}:{}", field_name, value);
        let encrypted = self.base_service.encrypt(data.as_bytes(), context).await?;
        Ok(base64_utils::encode(encrypted))
    }

    pub async fn decrypt_field(
        &self,
        field_name: &str,
        encrypted_value: &str,
        context: &SecurityContext,
    ) -> crate::core::error::Result<String> {
        let encrypted_data = base64_utils::decode(encrypted_value).map_err(|e| {
            crate::core::error::RustChainError::Security(format!("Invalid base64: {}", e))
        })?;

        let decrypted = self.base_service.decrypt(&encrypted_data, context).await?;
        let data = String::from_utf8(decrypted).map_err(|e| {
            crate::core::error::RustChainError::Security(format!("Invalid UTF-8: {}", e))
        })?;

        // Extract the value part (after field_name:)
        let prefix = format!("{}:", field_name);
        if data.starts_with(&prefix) {
            Ok(data[prefix.len()..].to_string())
        } else {
            Err(crate::core::error::RustChainError::Security(
                "Field name mismatch".to_string(),
            ))
        }
    }
}

/// Key management service
pub struct KeyManagementService {
    keys: std::collections::HashMap<String, Vec<u8>>,
    encryption_service: Box<dyn EncryptionService>,
}

impl KeyManagementService {
    pub fn new(encryption_service: Box<dyn EncryptionService>) -> Self {
        Self {
            keys: std::collections::HashMap::new(),
            encryption_service,
        }
    }

    pub async fn generate_data_encryption_key(
        &mut self,
        key_id: &str,
        algorithm: &EncryptionAlgorithm,
    ) -> crate::core::error::Result<String> {
        let key = self.encryption_service.generate_key(algorithm).await?;
        self.keys.insert(key_id.to_string(), key);
        Ok(key_id.to_string())
    }

    pub async fn encrypt_with_key(
        &self,
        key_id: &str,
        data: &[u8],
    ) -> crate::core::error::Result<Vec<u8>> {
        let key = self.keys.get(key_id).ok_or_else(|| {
            crate::core::error::RustChainError::Security("Key not found".to_string())
        })?;

        let encrypted = self.encryption_service.encrypt_with_key(data, key).await?;
        serde_json::to_vec(&encrypted).map_err(|e| {
            crate::core::error::RustChainError::Security(format!("Failed to serialize: {}", e))
        })
    }

    pub async fn decrypt_with_key(
        &self,
        key_id: &str,
        encrypted_data: &[u8],
    ) -> crate::core::error::Result<Vec<u8>> {
        let key = self.keys.get(key_id).ok_or_else(|| {
            crate::core::error::RustChainError::Security("Key not found".to_string())
        })?;

        let encrypted: EncryptedData = serde_json::from_slice(encrypted_data).map_err(|e| {
            crate::core::error::RustChainError::Security(format!("Failed to deserialize: {}", e))
        })?;

        self.encryption_service
            .decrypt_with_key(&encrypted, key)
            .await
    }

    pub fn list_keys(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    pub fn delete_key(&mut self, key_id: &str) -> crate::core::error::Result<()> {
        self.keys.remove(key_id);
        Ok(())
    }
}

// Simple base64 encoding for demo (uses stable engine API)
mod base64_utils {
    use base64::{engine::general_purpose, Engine as _};

    pub fn encode(data: Vec<u8>) -> String {
        general_purpose::STANDARD.encode(data)
    }

    pub fn decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
        general_purpose::STANDARD.decode(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{SecurityContext, SecurityLevel};
    use uuid::Uuid;

    fn set_master_key() {
        std::env::set_var("RUSTCHAIN_MASTER_KEY", "test_master_key");
    }

    #[tokio::test]
    async fn test_aes_encryption() {
        set_master_key();
        let encryption_service = AesEncryptionService::new().unwrap();

        let context = SecurityContext {
            session_id: Uuid::new_v4(),
            user_id: Some("test_user".to_string()),
            tenant_id: Some("test_tenant".to_string()),
            permissions: vec![],
            security_level: SecurityLevel::Internal,
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        let plaintext = b"Hello, World! This is a secret message.";

        let encrypted = encryption_service
            .encrypt(plaintext, &context)
            .await
            .unwrap();
        let decrypted = encryption_service
            .decrypt(&encrypted, &context)
            .await
            .unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_key_derivation() {
        set_master_key();
        let encryption_service = AesEncryptionService::new().unwrap();

        let params = KeyDerivationParams {
            salt: b"test_salt".to_vec(),
            iterations: 1000,
            key_length: 32,
        };

        let key1 = encryption_service
            .derive_key("password123", &params)
            .await
            .unwrap();
        let key2 = encryption_service
            .derive_key("password123", &params)
            .await
            .unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[tokio::test]
    async fn test_field_encryption() {
        set_master_key();
        let base_service = Box::new(AesEncryptionService::new().unwrap());
        let field_service = FieldEncryptionService::new(base_service);

        let context = SecurityContext {
            session_id: Uuid::new_v4(),
            user_id: Some("test_user".to_string()),
            tenant_id: Some("test_tenant".to_string()),
            permissions: vec![],
            security_level: SecurityLevel::Confidential,
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        let field_name = "ssn";
        let value = "123-45-6789";

        let encrypted = field_service
            .encrypt_field(field_name, value, &context)
            .await
            .unwrap();
        let decrypted = field_service
            .decrypt_field(field_name, &encrypted, &context)
            .await
            .unwrap();

        assert_eq!(value, decrypted);
    }
}
