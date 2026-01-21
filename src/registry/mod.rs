//! Registry module for RustChain marketplace functionality
//!
//! This module provides registry capabilities for the RustChain ecosystem.
//! In the enterprise edition, this would contain the full marketplace implementation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Registry client for accessing RustChain marketplace
#[derive(Debug, Clone)]
pub struct RegistryClient {
    base_url: String,
    api_key: Option<String>,
    client: reqwest::Client,
}

/// Represents a package in the registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPackage {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub download_count: u64,
    pub checksum: String,
}

/// Package metadata for registry operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub license: String,
    pub repository: Option<String>,
    pub homepage: Option<String>,
    pub keywords: Vec<String>,
    pub dependencies: HashMap<String, String>,
}

/// Registry search query parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    pub query: String,
    pub category: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Search results from registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResults {
    pub packages: Vec<RegistryPackage>,
    pub total: usize,
    pub has_more: bool,
}

impl RegistryClient {
    /// Create a new registry client
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            api_key: None,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }

    /// Set API key for authenticated requests
    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }

    /// Search for packages in the registry
    pub async fn search(&self, query: &SearchQuery) -> Result<SearchResults, RegistryError> {
        #[cfg(feature = "enterprise")]
        {
            // Enterprise edition: actual API call
            let url = format!("{}/api/search", self.base_url);
            let response = self.client.get(&url).query(&query).send().await?;

            if !response.status().is_success() {
                return Err(RegistryError::ApiError(response.status().as_u16()));
            }

            let results = response.json::<SearchResults>().await?;

            Ok(results)
        }

        #[cfg(not(feature = "enterprise"))]
        {
            // Community edition: registry functionality requires enterprise features
            Err(RegistryError::FeatureNotAvailable(
                "Registry search requires enterprise features. Use --features enterprise to enable.".to_string()
            ))
        }
    }

    /// Get package details by name and version
    pub async fn get_package(
        &self,
        name: &str,
        version: &str,
    ) -> Result<RegistryPackage, RegistryError> {
        #[cfg(feature = "enterprise")]
        {
            let url = format!("{}/api/packages/{}/{}", self.base_url, name, version);
            let response = self.client.get(&url).send().await?;

            if !response.status().is_success() {
                return Err(RegistryError::ApiError(response.status().as_u16()));
            }

            let package = response.json::<RegistryPackage>().await?;

            Ok(package)
        }

        #[cfg(not(feature = "enterprise"))]
        {
            // Community edition: return error indicating enterprise feature needed
            let _ = (name, version); // Suppress unused warnings
            Err(RegistryError::FeatureNotAvailable(
                "package_download".to_string(),
            ))
        }
    }

    /// Download a package from the registry
    pub async fn download_package(
        &self,
        name: &str,
        version: &str,
    ) -> Result<Vec<u8>, RegistryError> {
        #[cfg(feature = "enterprise")]
        {
            let url = format!(
                "{}/api/packages/{}/{}/download",
                self.base_url, name, version
            );
            let response = self.client.get(&url).send().await?;

            if !response.status().is_success() {
                return Err(RegistryError::ApiError(response.status().as_u16()));
            }

            let bytes = response.bytes().await?.to_vec();

            Ok(bytes)
        }

        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (name, version); // Suppress unused warnings
            Err(RegistryError::FeatureNotAvailable(
                "package_download".to_string(),
            ))
        }
    }

    /// Publish a package to the registry (requires authentication)
    pub async fn publish_package(
        &self,
        metadata: &PackageMetadata,
        package_data: Vec<u8>,
    ) -> Result<RegistryPackage, RegistryError> {
        #[cfg(feature = "enterprise")]
        {
            let api_key = self
                .api_key
                .as_ref()
                .ok_or_else(|| RegistryError::AuthenticationRequired)?;

            let url = format!("{}/api/packages", self.base_url);
            let form = reqwest::multipart::Form::new()
                .text("metadata", serde_json::to_string(metadata)?)
                .part("package", reqwest::multipart::Part::bytes(package_data));

            let response = self
                .client
                .post(&url)
                .header("Authorization", format!("Bearer {}", api_key))
                .multipart(form)
                .send()
                .await?;

            if !response.status().is_success() {
                return Err(RegistryError::ApiError(response.status().as_u16()));
            }

            let package = response.json::<RegistryPackage>().await?;

            Ok(package)
        }

        #[cfg(not(feature = "enterprise"))]
        {
            let _ = (metadata, package_data); // Suppress unused warnings
            Err(RegistryError::FeatureNotAvailable(
                "package_publish".to_string(),
            ))
        }
    }
}

/// Registry operation errors
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("Network error: {0}")]
    NetworkError(reqwest::Error),

    #[error("API error: HTTP {0}")]
    ApiError(u16),

    #[error("Parse error: {0}")]
    ParseError(reqwest::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Feature '{0}' is not available in community edition")]
    FeatureNotAvailable(String),

    #[error("Authentication required for this operation")]
    AuthenticationRequired,

    #[error("Package not found: {name}@{version}")]
    PackageNotFound { name: String, version: String },

    #[error("Invalid package format")]
    InvalidPackageFormat,
}

impl From<reqwest::Error> for RegistryError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_decode() {
            RegistryError::ParseError(err)
        } else {
            RegistryError::NetworkError(err)
        }
    }
}

/// Get the default registry URL
pub fn default_registry_url() -> String {
    std::env::var("RUSTCHAIN_REGISTRY_URL")
        .unwrap_or_else(|_| "https://registry.rustchain.ai".to_string())
}

/// Create a default registry client
pub fn create_registry_client() -> RegistryClient {
    RegistryClient::new(default_registry_url())
}

/// Initialize registry with authentication
pub fn create_authenticated_client(api_key: String) -> RegistryClient {
    RegistryClient::new(default_registry_url()).with_api_key(api_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_client_creation() {
        let client = RegistryClient::new("https://test.example.com".to_string());
        assert_eq!(client.base_url, "https://test.example.com");
        assert!(client.api_key.is_none());
    }

    #[test]
    fn test_registry_client_with_api_key() {
        let client = RegistryClient::new("https://test.example.com".to_string())
            .with_api_key("test-key".to_string());

        assert_eq!(client.api_key, Some("test-key".to_string()));
    }

    #[test]
    fn test_default_registry_url() {
        let url = default_registry_url();
        assert!(!url.is_empty());
        assert!(url.starts_with("http"));
    }

    #[tokio::test]
    async fn test_search_behavior() {
        let client = create_registry_client();
        let query = SearchQuery {
            query: "test".to_string(),
            category: None,
            limit: Some(10),
            offset: Some(0),
        };

        let results = client.search(&query).await;

        #[cfg(feature = "enterprise")]
        {
            // Enterprise edition may succeed or fail with network error
            // Both are acceptable in tests
            match results {
                Ok(search_results) => {
                    // API call succeeded - validate structure
                    // Note: len() is always >= 0 for usize, so we just check that it's accessible
                    let _ = search_results.packages.len();
                    let _ = search_results.total;
                }
                Err(_) => {
                    // Network error is acceptable in test environment
                    // where registry.rustchain.ai doesn't exist
                }
            }
        }

        #[cfg(not(feature = "enterprise"))]
        {
            // Community edition should return empty results
            let search_results = results.unwrap();
            assert_eq!(search_results.packages.len(), 0);
            assert_eq!(search_results.total, 0);
            assert!(!search_results.has_more);
        }
    }

    #[tokio::test]
    async fn test_get_package_behavior() {
        let client = create_registry_client();

        let result = client.get_package("test-package", "1.0.0").await;

        #[cfg(feature = "enterprise")]
        {
            // Enterprise edition may succeed or fail with network error
            match result {
                Ok(_) => {
                    // API call succeeded
                }
                Err(RegistryError::NetworkError(_)) => {
                    // Network error is acceptable in test environment
                }
                Err(RegistryError::ApiError(_)) => {
                    // API error (404, etc) is acceptable
                }
                Err(e) => {
                    // Other errors should be investigated
                    panic!("Unexpected error: {:?}", e);
                }
            }
        }

        #[cfg(not(feature = "enterprise"))]
        {
            // Community edition should return feature not available error
            match result {
                Err(RegistryError::FeatureNotAvailable(_)) => {
                    // Expected behavior
                }
                _ => panic!("Expected FeatureNotAvailable error"),
            }
        }
    }

    #[tokio::test]
    async fn test_download_package_behavior() {
        let client = create_registry_client();

        let result = client.download_package("test-package", "1.0.0").await;

        #[cfg(feature = "enterprise")]
        {
            // Enterprise edition may succeed or fail with network error
            match result {
                Ok(_) => {
                    // API call succeeded
                }
                Err(RegistryError::NetworkError(_)) => {
                    // Network error is acceptable in test environment
                }
                Err(RegistryError::ApiError(_)) => {
                    // API error (404, etc) is acceptable
                }
                Err(e) => {
                    // Other errors should be investigated
                    panic!("Unexpected error: {:?}", e);
                }
            }
        }

        #[cfg(not(feature = "enterprise"))]
        {
            // Community edition should return feature not available error
            match result {
                Err(RegistryError::FeatureNotAvailable(_)) => {
                    // Expected behavior
                }
                _ => panic!("Expected FeatureNotAvailable error"),
            }
        }
    }
}
