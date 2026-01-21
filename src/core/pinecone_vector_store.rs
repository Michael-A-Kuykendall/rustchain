// Pinecone Vector Store Implementation
use crate::core::error::{RustChainError, ToolError};
use crate::core::http_client::{create_http_client, read_error_body_bounded};
use crate::core::tools::{Tool, ToolCapability, ToolResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Pinecone Vector Store for storing and querying embeddings
pub struct PineconeVectorStore {
    api_key: String,
    environment: String,
    index_name: String,
    client: reqwest::Client,
}

impl PineconeVectorStore {
    pub fn new(api_key: String, environment: String, index_name: String) -> Self {
        Self {
            api_key,
            environment,
            index_name,
            client: create_http_client(None),
        }
    }

    fn get_base_url(&self) -> String {
        format!(
            "https://{}-{}.svc.pinecone.io",
            self.index_name, self.environment
        )
    }

    pub async fn upsert(
        &self,
        vectors: Vec<PineconeVector>,
    ) -> Result<UpsertResponse, RustChainError> {
        let url = format!("{}/vectors/upsert", self.get_base_url());

        let request_body = UpsertRequest {
            vectors,
            namespace: None,
        };

        debug!(
            "Upserting {} vectors to Pinecone",
            request_body.vectors.len()
        );

        let response = self
            .client
            .post(&url)
            .header("Api-Key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "pinecone_vector_store".to_string(),
                    reason: format!("Failed to send upsert request: {}", e),
                })
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "pinecone_vector_store".to_string(),
                reason: format!("Pinecone API error {}: {}", status, error_text),
            }));
        }

        let upsert_response: UpsertResponse = response.json().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "pinecone_vector_store".to_string(),
                reason: format!("Failed to parse upsert response: {}", e),
            })
        })?;

        info!(
            "Successfully upserted {} vectors to Pinecone",
            upsert_response.upserted_count
        );
        Ok(upsert_response)
    }

    pub async fn query(&self, params: QueryParams) -> Result<QueryResponse, RustChainError> {
        let url = format!("{}/query", self.get_base_url());

        debug!(
            "Querying Pinecone with {} dimensions, top_k: {}",
            params.vector.as_ref().map_or(0, |v| v.len()),
            params.top_k
        );

        let response = self
            .client
            .post(&url)
            .header("Api-Key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&params)
            .send()
            .await
            .map_err(|e| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "pinecone_vector_store".to_string(),
                    reason: format!("Failed to send query request: {}", e),
                })
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "pinecone_vector_store".to_string(),
                reason: format!("Pinecone API error {}: {}", status, error_text),
            }));
        }

        let query_response: QueryResponse = response.json().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "pinecone_vector_store".to_string(),
                reason: format!("Failed to parse query response: {}", e),
            })
        })?;

        info!(
            "Pinecone query returned {} matches",
            query_response.matches.len()
        );
        Ok(query_response)
    }

    pub async fn delete(
        &self,
        ids: Vec<String>,
        namespace: Option<String>,
    ) -> Result<(), RustChainError> {
        let url = format!("{}/vectors/delete", self.get_base_url());

        let request_body = DeleteRequest {
            ids: Some(ids.clone()),
            delete_all: None,
            namespace,
            filter: None,
        };

        debug!("Deleting {} vectors from Pinecone", ids.len());

        let response = self
            .client
            .post(&url)
            .header("Api-Key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "pinecone_vector_store".to_string(),
                    reason: format!("Failed to send delete request: {}", e),
                })
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "pinecone_vector_store".to_string(),
                reason: format!("Pinecone API error {}: {}", status, error_text),
            }));
        }

        info!("Successfully deleted {} vectors from Pinecone", ids.len());
        Ok(())
    }

    pub async fn fetch(
        &self,
        ids: Vec<String>,
        namespace: Option<String>,
    ) -> Result<FetchResponse, RustChainError> {
        let mut url = format!("{}/vectors/fetch", self.get_base_url());

        // Add query parameters
        let mut query_params = Vec::new();
        for id in &ids {
            query_params.push(format!("ids={}", urlencoding::encode(id)));
        }
        if let Some(ns) = &namespace {
            query_params.push(format!("namespace={}", urlencoding::encode(ns)));
        }

        if !query_params.is_empty() {
            url.push('?');
            url.push_str(&query_params.join("&"));
        }

        debug!("Fetching {} vectors from Pinecone", ids.len());

        let response = self
            .client
            .get(&url)
            .header("Api-Key", &self.api_key)
            .send()
            .await
            .map_err(|e| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "pinecone_vector_store".to_string(),
                    reason: format!("Failed to send fetch request: {}", e),
                })
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "pinecone_vector_store".to_string(),
                reason: format!("Pinecone API error {}: {}", status, error_text),
            }));
        }

        let fetch_response: FetchResponse = response.json().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "pinecone_vector_store".to_string(),
                reason: format!("Failed to parse fetch response: {}", e),
            })
        })?;

        info!(
            "Successfully fetched {} vectors from Pinecone",
            fetch_response.vectors.len()
        );
        Ok(fetch_response)
    }

    pub async fn describe_index_stats(&self) -> Result<IndexStats, RustChainError> {
        let url = format!("{}/describe_index_stats", self.get_base_url());

        debug!("Getting Pinecone index statistics");

        let response = self
            .client
            .post(&url)
            .header("Api-Key", &self.api_key)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "pinecone_vector_store".to_string(),
                    reason: format!("Failed to send stats request: {}", e),
                })
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "pinecone_vector_store".to_string(),
                reason: format!("Pinecone API error {}: {}", status, error_text),
            }));
        }

        let stats: IndexStats = response.json().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "pinecone_vector_store".to_string(),
                reason: format!("Failed to parse stats response: {}", e),
            })
        })?;

        info!(
            "Pinecone index has {} vectors with {} dimensions",
            stats.total_vector_count, stats.dimension
        );
        Ok(stats)
    }
}

#[async_trait]
impl Tool for PineconeVectorStore {
    fn name(&self) -> &'static str {
        "pinecone_vector_store"
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![ToolCapability::Basic, ToolCapability::NetworkAccess]
    }

    async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
        let operation: PineconeOperation = serde_json::from_str(input).map_err(|e| {
            RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "pinecone_vector_store".to_string(),
                details: format!("Invalid operation parameters: {}", e),
            })
        })?;

        match operation {
            PineconeOperation::Upsert { vectors } => {
                let response = self.upsert(vectors).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(response)?))
            }
            PineconeOperation::Query { params } => {
                let response = self.query(params).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(response)?))
            }
            PineconeOperation::Delete { ids, namespace } => {
                self.delete(ids, namespace).await?;
                Ok(ToolResult::Success(
                    "Vectors deleted successfully".to_string(),
                ))
            }
            PineconeOperation::Fetch { ids, namespace } => {
                let response = self.fetch(ids, namespace).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(response)?))
            }
            PineconeOperation::Stats => {
                let response = self.describe_index_stats().await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(response)?))
            }
        }
    }
}

// Data structures for Pinecone API

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation")]
pub enum PineconeOperation {
    #[serde(rename = "upsert")]
    Upsert { vectors: Vec<PineconeVector> },
    #[serde(rename = "query")]
    Query { params: QueryParams },
    #[serde(rename = "delete")]
    Delete {
        ids: Vec<String>,
        namespace: Option<String>,
    },
    #[serde(rename = "fetch")]
    Fetch {
        ids: Vec<String>,
        namespace: Option<String>,
    },
    #[serde(rename = "stats")]
    Stats,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PineconeVector {
    pub id: String,
    pub values: Vec<f32>,
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sparse_values: Option<SparseValues>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SparseValues {
    pub indices: Vec<u32>,
    pub values: Vec<f32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpsertRequest {
    pub vectors: Vec<PineconeVector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpsertResponse {
    #[serde(rename = "upsertedCount")]
    pub upserted_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vector: Option<Vec<f32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sparse_vector: Option<SparseValues>,
    #[serde(rename = "topK")]
    pub top_k: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "includeMetadata")]
    pub include_metadata: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "includeValues")]
    pub include_values: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryResponse {
    pub matches: Vec<ScoredVector>,
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScoredVector {
    pub id: String,
    pub score: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<f32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sparse_values: Option<SparseValues>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "deleteAll")]
    pub delete_all: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchResponse {
    pub vectors: HashMap<String, PineconeVector>,
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IndexStats {
    pub dimension: u32,
    #[serde(rename = "indexFullness")]
    pub index_fullness: f32,
    #[serde(rename = "totalVectorCount")]
    pub total_vector_count: u64,
    pub namespaces: Option<HashMap<String, NamespaceStats>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NamespaceStats {
    #[serde(rename = "vectorCount")]
    pub vector_count: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Usage {
    #[serde(rename = "readUnits")]
    pub read_units: Option<u32>,
    #[serde(rename = "writeUnits")]
    pub write_units: Option<u32>,
}

// Helper function to create Pinecone vector store from environment
pub fn create_pinecone_from_env() -> Result<PineconeVectorStore, RustChainError> {
    let api_key = std::env::var("PINECONE_API_KEY").map_err(|_| {
        RustChainError::Tool(ToolError::InvalidParameters {
            tool_name: "pinecone_vector_store".to_string(),
            details: "PINECONE_API_KEY environment variable not set".to_string(),
        })
    })?;

    let environment = std::env::var("PINECONE_ENVIRONMENT").map_err(|_| {
        RustChainError::Tool(ToolError::InvalidParameters {
            tool_name: "pinecone_vector_store".to_string(),
            details: "PINECONE_ENVIRONMENT environment variable not set".to_string(),
        })
    })?;

    let index_name = std::env::var("PINECONE_INDEX_NAME").map_err(|_| {
        RustChainError::Tool(ToolError::InvalidParameters {
            tool_name: "pinecone_vector_store".to_string(),
            details: "PINECONE_INDEX_NAME environment variable not set".to_string(),
        })
    })?;

    Ok(PineconeVectorStore::new(api_key, environment, index_name))
}

// Tool registry helper function
pub fn register_pinecone_vector_store(registry: &mut crate::core::tools::ToolRegistry) {
    if let Ok(pinecone) = create_pinecone_from_env() {
        registry.register(Box::new(pinecone));
        info!("Registered Pinecone Vector Store");
    } else {
        warn!("Pinecone Vector Store not registered - missing environment variables");
        debug!("Required: PINECONE_API_KEY, PINECONE_ENVIRONMENT, PINECONE_INDEX_NAME");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_pinecone_vector_serialization() {
        let mut metadata = HashMap::new();
        metadata.insert(
            "text".to_string(),
            serde_json::Value::String("sample text".to_string()),
        );

        let vector = PineconeVector {
            id: "test-1".to_string(),
            values: vec![0.1, 0.2, 0.3],
            metadata: Some(metadata),
            sparse_values: None,
        };

        let json = serde_json::to_string(&vector).unwrap();
        let deserialized: PineconeVector = serde_json::from_str(&json).unwrap();

        assert_eq!(vector.id, deserialized.id);
        assert_eq!(vector.values, deserialized.values);
    }

    #[test]
    fn test_query_params_serialization() {
        let params = QueryParams {
            vector: Some(vec![0.1, 0.2, 0.3]),
            sparse_vector: None,
            top_k: 10,
            filter: None,
            namespace: Some("test-namespace".to_string()),
            include_metadata: Some(true),
            include_values: Some(false),
            id: None,
        };

        let json = serde_json::to_value(&params).unwrap();
        assert_eq!(json["topK"], 10);
        assert_eq!(json["namespace"], "test-namespace");
        assert_eq!(json["includeMetadata"], true);
        assert_eq!(json["includeValues"], false);
    }

    #[test]
    fn test_pinecone_operation_serialization() {
        let operation = PineconeOperation::Query {
            params: QueryParams {
                vector: Some(vec![0.1, 0.2]),
                sparse_vector: None,
                top_k: 5,
                filter: None,
                namespace: None,
                include_metadata: Some(true),
                include_values: Some(true),
                id: None,
            },
        };

        let json = serde_json::to_string(&operation).unwrap();
        let deserialized: PineconeOperation = serde_json::from_str(&json).unwrap();

        match deserialized {
            PineconeOperation::Query { params } => {
                assert_eq!(params.top_k, 5);
                assert_eq!(params.include_metadata, Some(true));
            }
            _ => panic!("Wrong operation type deserialized"),
        }
    }

    #[test]
    fn test_upsert_response_deserialization() {
        let json = r#"{"upsertedCount": 100}"#;
        let response: UpsertResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.upserted_count, 100);
    }

    #[test]
    fn test_scored_vector_deserialization() {
        let json = r#"{
            "id": "vec-1", 
            "score": 0.95,
            "values": [0.1, 0.2, 0.3],
            "metadata": {"text": "sample"}
        }"#;

        let vector: ScoredVector = serde_json::from_str(json).unwrap();
        assert_eq!(vector.id, "vec-1");
        assert_eq!(vector.score, 0.95);
        assert_eq!(vector.values, Some(vec![0.1, 0.2, 0.3]));
    }

    #[test]
    fn test_index_stats_deserialization() {
        let json = r#"{
            "dimension": 1536,
            "indexFullness": 0.1,
            "totalVectorCount": 1000,
            "namespaces": {
                "default": {"vectorCount": 800},
                "test": {"vectorCount": 200}
            }
        }"#;

        let stats: IndexStats = serde_json::from_str(json).unwrap();
        assert_eq!(stats.dimension, 1536);
        assert_eq!(stats.total_vector_count, 1000);
        assert!(stats.namespaces.is_some());
    }

    #[test]
    fn test_sparse_values_serialization() {
        let sparse = SparseValues {
            indices: vec![0, 5, 10],
            values: vec![0.1, 0.5, 0.8],
        };

        let json = serde_json::to_string(&sparse).unwrap();
        let deserialized: SparseValues = serde_json::from_str(&json).unwrap();

        assert_eq!(sparse.indices, deserialized.indices);
        assert_eq!(sparse.values, deserialized.values);
    }

    #[test]
    fn test_pinecone_vector_store_creation() {
        let store = PineconeVectorStore::new(
            "test-key".to_string(),
            "test-env".to_string(),
            "test-index".to_string(),
        );

        assert_eq!(store.name(), "pinecone_vector_store");
        assert!(store.capabilities().contains(&ToolCapability::Basic));
        assert!(store
            .capabilities()
            .contains(&ToolCapability::NetworkAccess));
    }

    #[test]
    fn test_get_base_url() {
        let store = PineconeVectorStore::new(
            "test-key".to_string(),
            "us-west1-gcp".to_string(),
            "my-index".to_string(),
        );

        assert_eq!(
            store.get_base_url(),
            "https://my-index-us-west1-gcp.svc.pinecone.io"
        );
    }

    #[tokio::test]
    async fn test_invalid_operation_parameters() {
        let store = PineconeVectorStore::new(
            "test-key".to_string(),
            "test-env".to_string(),
            "test-index".to_string(),
        );

        let result = store.invoke("invalid json").await;
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("Invalid operation parameters"));
    }

    #[test]
    fn test_create_pinecone_from_env_missing_vars() {
        // Clear environment variables first
        std::env::remove_var("PINECONE_API_KEY");
        std::env::remove_var("PINECONE_ENVIRONMENT");
        std::env::remove_var("PINECONE_INDEX_NAME");

        let result = create_pinecone_from_env();
        assert!(result.is_err());
    }
}
