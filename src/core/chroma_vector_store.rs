// Chroma Vector Store Implementation
use crate::core::error::{RustChainError, ToolError};
use crate::core::http_client::{create_http_client, read_error_body_bounded};
use crate::core::tools::{Tool, ToolCapability, ToolResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Chroma Vector Store for storing and querying embeddings
pub struct ChromaVectorStore {
    host: String,
    port: u16,
    client: reqwest::Client,
}

impl ChromaVectorStore {
    pub fn new(host: String, port: u16) -> Self {
        Self {
            host,
            port,
            client: create_http_client(Some(30)), // 30 second timeout for vector operations
        }
    }

    fn get_base_url(&self) -> String {
        format!("http://{}:{}/api/v1", self.host, self.port)
    }

    pub async fn create_collection(
        &self,
        name: &str,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<CollectionResponse, RustChainError> {
        let url = format!("{}/collections", self.get_base_url());

        let request_body = CreateCollectionRequest {
            name: name.to_string(),
            metadata: metadata.unwrap_or_default(),
            get_or_create: Some(true),
        };

        debug!("Creating Chroma collection: {}", name);

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "chroma_vector_store".to_string(),
                    reason: format!("Failed to create collection: {}", e),
                })
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Chroma API error {}: {}", status, error_text),
            }));
        }

        let collection: CollectionResponse = response.json().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Failed to parse collection response: {}", e),
            })
        })?;

        info!("Successfully created/retrieved Chroma collection: {}", name);
        Ok(collection)
    }

    pub async fn add_documents(
        &self,
        collection_name: &str,
        request: AddRequest,
    ) -> Result<(), RustChainError> {
        let url = format!(
            "{}/collections/{}/add",
            self.get_base_url(),
            collection_name
        );

        debug!(
            "Adding {} documents to Chroma collection: {}",
            request.documents.as_ref().map_or(0, |docs| docs.len()),
            collection_name
        );

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "chroma_vector_store".to_string(),
                    reason: format!("Failed to add documents: {}", e),
                })
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Chroma API error {}: {}", status, error_text),
            }));
        }

        info!(
            "Successfully added documents to Chroma collection: {}",
            collection_name
        );
        Ok(())
    }

    pub async fn query_collection(
        &self,
        collection_name: &str,
        query: QueryRequest,
    ) -> Result<QueryResponse, RustChainError> {
        let url = format!(
            "{}/collections/{}/query",
            self.get_base_url(),
            collection_name
        );

        debug!(
            "Querying Chroma collection: {}, n_results: {}",
            collection_name,
            query.n_results.unwrap_or(10)
        );

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&query)
            .send()
            .await
            .map_err(|e| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "chroma_vector_store".to_string(),
                    reason: format!("Failed to query collection: {}", e),
                })
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Chroma API error {}: {}", status, error_text),
            }));
        }

        let query_response: QueryResponse = response.json().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Failed to parse query response: {}", e),
            })
        })?;

        info!(
            "Chroma query returned {} results",
            query_response.ids.first().map_or(0, |ids| ids.len())
        );
        Ok(query_response)
    }

    pub async fn delete_documents(
        &self,
        collection_name: &str,
        ids: Vec<String>,
    ) -> Result<(), RustChainError> {
        let url = format!(
            "{}/collections/{}/delete",
            self.get_base_url(),
            collection_name
        );

        let request_body = DeleteRequest {
            ids: Some(ids.clone()),
            where_clause: None,
            where_document: None,
        };

        debug!(
            "Deleting {} documents from Chroma collection: {}",
            ids.len(),
            collection_name
        );

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "chroma_vector_store".to_string(),
                    reason: format!("Failed to delete documents: {}", e),
                })
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Chroma API error {}: {}", status, error_text),
            }));
        }

        info!(
            "Successfully deleted {} documents from Chroma collection: {}",
            ids.len(),
            collection_name
        );
        Ok(())
    }

    pub async fn get_collection(&self, name: &str) -> Result<CollectionResponse, RustChainError> {
        let url = format!("{}/collections/{}", self.get_base_url(), name);

        debug!("Getting Chroma collection info: {}", name);

        let response = self.client.get(&url).send().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Failed to get collection: {}", e),
            })
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Chroma API error {}: {}", status, error_text),
            }));
        }

        let collection: CollectionResponse = response.json().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Failed to parse collection response: {}", e),
            })
        })?;

        info!("Successfully retrieved Chroma collection: {}", name);
        Ok(collection)
    }

    pub async fn list_collections(&self) -> Result<Vec<CollectionResponse>, RustChainError> {
        let url = format!("{}/collections", self.get_base_url());

        debug!("Listing all Chroma collections");

        let response = self.client.get(&url).send().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Failed to list collections: {}", e),
            })
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Chroma API error {}: {}", status, error_text),
            }));
        }

        let collections: Vec<CollectionResponse> = response.json().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Failed to parse collections response: {}", e),
            })
        })?;

        info!(
            "Successfully listed {} Chroma collections",
            collections.len()
        );
        Ok(collections)
    }

    pub async fn get_count(&self, collection_name: &str) -> Result<u64, RustChainError> {
        let url = format!(
            "{}/collections/{}/count",
            self.get_base_url(),
            collection_name
        );

        debug!(
            "Getting document count for Chroma collection: {}",
            collection_name
        );

        let response = self.client.get(&url).send().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Failed to get count: {}", e),
            })
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Chroma API error {}: {}", status, error_text),
            }));
        }

        let count: u64 = response.json().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "chroma_vector_store".to_string(),
                reason: format!("Failed to parse count response: {}", e),
            })
        })?;

        info!(
            "Chroma collection {} has {} documents",
            collection_name, count
        );
        Ok(count)
    }
}

#[async_trait]
impl Tool for ChromaVectorStore {
    fn name(&self) -> &'static str {
        "chroma_vector_store"
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![ToolCapability::Basic, ToolCapability::NetworkAccess]
    }

    async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
        let operation: ChromaOperation = serde_json::from_str(input).map_err(|e| {
            RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "chroma_vector_store".to_string(),
                details: format!("Invalid operation parameters: {}", e),
            })
        })?;

        match operation {
            ChromaOperation::CreateCollection { name, metadata } => {
                let response = self.create_collection(&name, metadata).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(response)?))
            }
            ChromaOperation::AddDocuments {
                collection_name,
                request,
            } => {
                self.add_documents(&collection_name, request).await?;
                Ok(ToolResult::Success(
                    "Documents added successfully".to_string(),
                ))
            }
            ChromaOperation::Query {
                collection_name,
                query,
            } => {
                let response = self.query_collection(&collection_name, query).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(response)?))
            }
            ChromaOperation::Delete {
                collection_name,
                ids,
            } => {
                self.delete_documents(&collection_name, ids).await?;
                Ok(ToolResult::Success(
                    "Documents deleted successfully".to_string(),
                ))
            }
            ChromaOperation::GetCollection { name } => {
                let response = self.get_collection(&name).await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(response)?))
            }
            ChromaOperation::ListCollections => {
                let response = self.list_collections().await?;
                Ok(ToolResult::StructuredJson(serde_json::to_value(response)?))
            }
            ChromaOperation::GetCount { collection_name } => {
                let count = self.get_count(&collection_name).await?;
                Ok(ToolResult::StructuredJson(
                    serde_json::json!({ "count": count }),
                ))
            }
        }
    }
}

// Data structures for Chroma API

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation")]
pub enum ChromaOperation {
    #[serde(rename = "create_collection")]
    CreateCollection {
        name: String,
        metadata: Option<HashMap<String, serde_json::Value>>,
    },
    #[serde(rename = "add_documents")]
    AddDocuments {
        collection_name: String,
        request: AddRequest,
    },
    #[serde(rename = "query")]
    Query {
        collection_name: String,
        query: QueryRequest,
    },
    #[serde(rename = "delete")]
    Delete {
        collection_name: String,
        ids: Vec<String>,
    },
    #[serde(rename = "get_collection")]
    GetCollection { name: String },
    #[serde(rename = "list_collections")]
    ListCollections,
    #[serde(rename = "get_count")]
    GetCount { collection_name: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCollectionRequest {
    pub name: String,
    pub metadata: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get_or_create: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CollectionResponse {
    pub id: String,
    pub name: String,
    pub metadata: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dimension: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embeddings: Option<Vec<Vec<f32>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadatas: Option<Vec<HashMap<String, serde_json::Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documents: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uris: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_embeddings: Option<Vec<Vec<f32>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_texts: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n_results: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub where_clause: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub where_document: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryResponse {
    pub ids: Vec<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embeddings: Option<Vec<Vec<Vec<f32>>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documents: Option<Vec<Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadatas: Option<Vec<Vec<HashMap<String, serde_json::Value>>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distances: Option<Vec<Vec<f32>>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "where")]
    pub where_clause: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub where_document: Option<HashMap<String, serde_json::Value>>,
}

// Helper function to create Chroma vector store from environment
pub fn create_chroma_from_env() -> Result<ChromaVectorStore, RustChainError> {
    let host = std::env::var("CHROMA_HOST").unwrap_or_else(|_| "localhost".to_string());

    let port = std::env::var("CHROMA_PORT")
        .unwrap_or_else(|_| "8000".to_string())
        .parse::<u16>()
        .map_err(|_| {
            RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "chroma_vector_store".to_string(),
                details: "CHROMA_PORT must be a valid port number".to_string(),
            })
        })?;

    Ok(ChromaVectorStore::new(host, port))
}

// Tool registry helper function
pub fn register_chroma_vector_store(registry: &mut crate::core::tools::ToolRegistry) {
    match create_chroma_from_env() {
        Ok(chroma) => {
            registry.register(Box::new(chroma));
            info!("Registered Chroma Vector Store");
        }
        Err(e) => {
            warn!("Chroma Vector Store not registered: {}", e);
            debug!("Optional: Set CHROMA_HOST and CHROMA_PORT environment variables");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_create_collection_request_serialization() {
        let mut metadata = HashMap::new();
        metadata.insert(
            "description".to_string(),
            serde_json::Value::String("test collection".to_string()),
        );

        let request = CreateCollectionRequest {
            name: "test_collection".to_string(),
            metadata,
            get_or_create: Some(true),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: CreateCollectionRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.name, deserialized.name);
        assert_eq!(request.get_or_create, deserialized.get_or_create);
    }

    #[test]
    fn test_collection_response_deserialization() {
        let json = r#"{
            "id": "collection-123",
            "name": "test_collection",
            "metadata": {"description": "test"},
            "dimension": 768
        }"#;

        let response: CollectionResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.id, "collection-123");
        assert_eq!(response.name, "test_collection");
        assert_eq!(response.dimension, Some(768));
    }

    #[test]
    fn test_add_request_serialization() {
        let request = AddRequest {
            ids: Some(vec!["id1".to_string(), "id2".to_string()]),
            embeddings: Some(vec![vec![0.1, 0.2], vec![0.3, 0.4]]),
            metadatas: None,
            documents: Some(vec!["doc1".to_string(), "doc2".to_string()]),
            uris: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: AddRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.ids, deserialized.ids);
        assert_eq!(request.embeddings, deserialized.embeddings);
        assert_eq!(request.documents, deserialized.documents);
    }

    #[test]
    fn test_query_request_serialization() {
        let request = QueryRequest {
            query_embeddings: Some(vec![vec![0.1, 0.2, 0.3]]),
            query_texts: Some(vec!["search query".to_string()]),
            n_results: Some(5),
            where_clause: None,
            where_document: None,
            include: Some(vec!["documents".to_string(), "metadatas".to_string()]),
        };

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["n_results"], 5);
        assert_eq!(json["query_texts"][0], "search query");
    }

    #[test]
    fn test_query_response_deserialization() {
        let json = r#"{
            "ids": [["id1", "id2"]],
            "documents": [["doc1", "doc2"]],
            "distances": [[0.1, 0.2]],
            "metadatas": [[{"key": "value"}, {}]]
        }"#;

        let response: QueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.ids.len(), 1);
        assert_eq!(response.ids[0].len(), 2);
        assert_eq!(response.ids[0][0], "id1");
        assert!(response.documents.is_some());
        assert!(response.distances.is_some());
    }

    #[test]
    fn test_chroma_operation_serialization() {
        let operation = ChromaOperation::Query {
            collection_name: "test_collection".to_string(),
            query: QueryRequest {
                query_texts: Some(vec!["test query".to_string()]),
                n_results: Some(10),
                query_embeddings: None,
                where_clause: None,
                where_document: None,
                include: None,
            },
        };

        let json = serde_json::to_string(&operation).unwrap();
        let deserialized: ChromaOperation = serde_json::from_str(&json).unwrap();

        match deserialized {
            ChromaOperation::Query {
                collection_name,
                query,
            } => {
                assert_eq!(collection_name, "test_collection");
                assert_eq!(query.n_results, Some(10));
            }
            _ => panic!("Wrong operation type deserialized"),
        }
    }

    #[test]
    fn test_delete_request_serialization() {
        let request = DeleteRequest {
            ids: Some(vec!["id1".to_string(), "id2".to_string()]),
            where_clause: None,
            where_document: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: DeleteRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(request.ids, deserialized.ids);
        assert!(deserialized.where_clause.is_none());
    }

    #[test]
    fn test_chroma_vector_store_creation() {
        let store = ChromaVectorStore::new("localhost".to_string(), 8000);

        assert_eq!(store.name(), "chroma_vector_store");
        assert!(store.capabilities().contains(&ToolCapability::Basic));
        assert!(store
            .capabilities()
            .contains(&ToolCapability::NetworkAccess));
    }

    #[test]
    fn test_get_base_url() {
        let store = ChromaVectorStore::new("127.0.0.1".to_string(), 9000);

        assert_eq!(store.get_base_url(), "http://127.0.0.1:9000/api/v1");
    }

    #[tokio::test]
    async fn test_invalid_operation_parameters() {
        let store = ChromaVectorStore::new("localhost".to_string(), 8000);

        let result = store.invoke("invalid json").await;
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("Invalid operation parameters"));
    }

    #[test]
    fn test_create_chroma_defaults() {
        // Test creating Chroma directly with default values
        let chroma = ChromaVectorStore::new("localhost".to_string(), 8000);
        assert_eq!(chroma.host, "localhost");
        assert_eq!(chroma.port, 8000);
    }

    #[test]
    fn test_create_chroma_custom_values() {
        // Test creating Chroma directly with custom values
        let chroma = ChromaVectorStore::new("192.168.1.100".to_string(), 9000);
        assert_eq!(chroma.host, "192.168.1.100");
        assert_eq!(chroma.port, 9000);
    }

    #[test]
    fn test_create_chroma_from_env_invalid_port() {
        // Set invalid port
        std::env::set_var("CHROMA_PORT", "invalid");

        let result = create_chroma_from_env();
        assert!(result.is_err());

        // Clean up
        std::env::remove_var("CHROMA_PORT");
    }

    #[test]
    fn test_chroma_operations_all_variants() {
        // Test that all variants can be created and serialized
        let operations = vec![
            ChromaOperation::CreateCollection {
                name: "test".to_string(),
                metadata: None,
            },
            ChromaOperation::AddDocuments {
                collection_name: "test".to_string(),
                request: AddRequest {
                    ids: None,
                    embeddings: None,
                    metadatas: None,
                    documents: None,
                    uris: None,
                },
            },
            ChromaOperation::Query {
                collection_name: "test".to_string(),
                query: QueryRequest {
                    query_embeddings: None,
                    query_texts: None,
                    n_results: None,
                    where_clause: None,
                    where_document: None,
                    include: None,
                },
            },
            ChromaOperation::Delete {
                collection_name: "test".to_string(),
                ids: vec!["id1".to_string()],
            },
            ChromaOperation::GetCollection {
                name: "test".to_string(),
            },
            ChromaOperation::ListCollections,
            ChromaOperation::GetCount {
                collection_name: "test".to_string(),
            },
        ];

        for operation in operations {
            let json = serde_json::to_string(&operation).unwrap();
            let _deserialized: ChromaOperation = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_empty_query_response() {
        let json = r#"{
            "ids": [],
            "documents": null,
            "distances": null,
            "metadatas": null,
            "embeddings": null
        }"#;

        let response: QueryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.ids.len(), 0);
        assert!(response.documents.is_none());
        assert!(response.distances.is_none());
    }
}
