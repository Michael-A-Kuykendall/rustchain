use crate::core::http_client::create_http_client;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    pub id: String,
    pub content: String,
    pub metadata: HashMap<String, serde_json::Value>,
    pub embedding: Option<Vec<f32>>,
    pub chunks: Vec<DocumentChunk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentChunk {
    pub id: String,
    pub content: String,
    pub start_index: usize,
    pub end_index: usize,
    pub metadata: HashMap<String, serde_json::Value>,
    pub embedding: Option<Vec<f32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRequest {
    pub query: String,
    pub limit: Option<usize>,
    pub similarity_threshold: Option<f32>,
    pub filters: HashMap<String, serde_json::Value>,
    pub include_metadata: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub chunk: DocumentChunk,
    pub document_id: String,
    pub similarity_score: f32,
    pub rank: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub results: Vec<QueryResult>,
    pub query: String,
    pub total_results: usize,
    pub processing_time_ms: u64,
}

#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    async fn embed_text(&self, text: &str) -> Result<Vec<f32>>;
    async fn embed_batch(&self, texts: Vec<&str>) -> Result<Vec<Vec<f32>>>;
    fn embedding_dimension(&self) -> usize;
    fn model_name(&self) -> &str;
}

#[async_trait]
pub trait VectorStore: Send + Sync {
    async fn store_document(&mut self, document: Document) -> Result<String>;
    async fn store_chunks(&mut self, document_id: &str, chunks: Vec<DocumentChunk>) -> Result<()>;
    async fn search(
        &self,
        query_embedding: Vec<f32>,
        request: QueryRequest,
    ) -> Result<SearchResponse>;
    async fn delete_document(&mut self, document_id: &str) -> Result<()>;
    async fn get_document(&self, document_id: &str) -> Result<Option<Document>>;
    async fn list_documents(&self, offset: usize, limit: usize) -> Result<Vec<String>>;
}

/// OpenAI embeddings provider
pub struct OpenAIEmbeddingProvider {
    client: reqwest::Client,
    api_key: String,
    model: String,
}

impl OpenAIEmbeddingProvider {
    pub fn new(api_key: String) -> Self {
        Self {
            client: create_http_client(Some(60)),
            api_key,
            model: "text-embedding-ada-002".to_string(),
        }
    }

    pub fn with_model(mut self, model: String) -> Self {
        self.model = model;
        self
    }
}

#[async_trait]
impl EmbeddingProvider for OpenAIEmbeddingProvider {
    async fn embed_text(&self, text: &str) -> Result<Vec<f32>> {
        let url = "https://api.openai.com/v1/embeddings";

        let request = serde_json::json!({
            "model": self.model,
            "input": text
        });

        debug!("Requesting embedding for text of length: {}", text.len());

        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("OpenAI embeddings API error: {}", error_text));
        }

        let embedding_response: serde_json::Value = response.json().await?;

        let embedding = embedding_response["data"][0]["embedding"]
            .as_array()
            .ok_or_else(|| anyhow!("Invalid embedding response"))?
            .iter()
            .map(|v| v.as_f64().unwrap_or(0.0) as f32)
            .collect();

        Ok(embedding)
    }

    async fn embed_batch(&self, texts: Vec<&str>) -> Result<Vec<Vec<f32>>> {
        let url = "https://api.openai.com/v1/embeddings";

        let request = serde_json::json!({
            "model": self.model,
            "input": texts
        });

        debug!("Requesting embeddings for {} texts", texts.len());

        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("OpenAI embeddings API error: {}", error_text));
        }

        let embedding_response: serde_json::Value = response.json().await?;

        let embeddings = embedding_response["data"]
            .as_array()
            .ok_or_else(|| anyhow!("Invalid embedding response"))?
            .iter()
            .map(|item| {
                item["embedding"]
                    .as_array()
                    .unwrap_or(&Vec::new())
                    .iter()
                    .map(|v| v.as_f64().unwrap_or(0.0) as f32)
                    .collect()
            })
            .collect();

        Ok(embeddings)
    }

    fn embedding_dimension(&self) -> usize {
        match self.model.as_str() {
            "text-embedding-ada-002" => 1536,
            "text-embedding-3-small" => 1536,
            "text-embedding-3-large" => 3072,
            _ => 1536, // Default
        }
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

/// In-memory vector store implementation
pub struct InMemoryVectorStore {
    documents: HashMap<String, Document>,
    chunks: HashMap<String, Vec<DocumentChunk>>,
}

impl Default for InMemoryVectorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryVectorStore {
    pub fn new() -> Self {
        Self {
            documents: HashMap::new(),
            chunks: HashMap::new(),
        }
    }

    fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() {
            return 0.0;
        }

        let dot_product: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }

        dot_product / (norm_a * norm_b)
    }
}

#[async_trait]
impl VectorStore for InMemoryVectorStore {
    async fn store_document(&mut self, document: Document) -> Result<String> {
        let document_id = document.id.clone();

        // Store chunks separately for efficient searching
        self.chunks
            .insert(document_id.clone(), document.chunks.clone());
        self.documents.insert(document_id.clone(), document);

        info!("Stored document: {}", document_id);
        Ok(document_id)
    }

    async fn store_chunks(&mut self, document_id: &str, chunks: Vec<DocumentChunk>) -> Result<()> {
        self.chunks.insert(document_id.to_string(), chunks);

        // Update the document with the new chunks
        if let Some(document) = self.documents.get_mut(document_id) {
            document.chunks = self.chunks[document_id].clone();
        }

        info!(
            "Stored {} chunks for document: {}",
            self.chunks[document_id].len(),
            document_id
        );
        Ok(())
    }

    async fn search(
        &self,
        query_embedding: Vec<f32>,
        request: QueryRequest,
    ) -> Result<SearchResponse> {
        let start_time = std::time::Instant::now();

        let mut all_results = Vec::new();

        // Search through all chunks
        for (document_id, chunks) in &self.chunks {
            for chunk in chunks {
                if let Some(ref embedding) = chunk.embedding {
                    let similarity = Self::cosine_similarity(&query_embedding, embedding);

                    // Apply similarity threshold filter
                    if let Some(threshold) = request.similarity_threshold {
                        if similarity < threshold {
                            continue;
                        }
                    }

                    // Apply metadata filters
                    let mut passes_filters = true;
                    for (key, expected_value) in &request.filters {
                        if let Some(actual_value) = chunk.metadata.get(key) {
                            if actual_value != expected_value {
                                passes_filters = false;
                                break;
                            }
                        } else {
                            passes_filters = false;
                            break;
                        }
                    }

                    if !passes_filters {
                        continue;
                    }

                    all_results.push(QueryResult {
                        chunk: chunk.clone(),
                        document_id: document_id.clone(),
                        similarity_score: similarity,
                        rank: 0, // Will be set after sorting
                    });
                }
            }
        }

        // Sort by similarity score (descending) - handle NaN values safely
        all_results.sort_by(|a, b| {
            b.similarity_score
                .partial_cmp(&a.similarity_score)
                .unwrap_or(std::cmp::Ordering::Equal) // Treat NaN as equal for sorting
        });

        // Update ranks
        for (i, result) in all_results.iter_mut().enumerate() {
            result.rank = i + 1;
        }

        // Apply limit
        let limit = request.limit.unwrap_or(10);
        all_results.truncate(limit);

        let processing_time = start_time.elapsed().as_millis() as u64;

        Ok(SearchResponse {
            results: all_results,
            query: request.query,
            total_results: self.chunks.values().map(|chunks| chunks.len()).sum(),
            processing_time_ms: processing_time,
        })
    }

    async fn delete_document(&mut self, document_id: &str) -> Result<()> {
        self.documents.remove(document_id);
        self.chunks.remove(document_id);
        info!("Deleted document: {}", document_id);
        Ok(())
    }

    async fn get_document(&self, document_id: &str) -> Result<Option<Document>> {
        Ok(self.documents.get(document_id).cloned())
    }

    async fn list_documents(&self, offset: usize, limit: usize) -> Result<Vec<String>> {
        let document_ids: Vec<String> = self.documents.keys().cloned().collect();
        let end = std::cmp::min(offset + limit, document_ids.len());

        if offset >= document_ids.len() {
            return Ok(Vec::new());
        }

        Ok(document_ids[offset..end].to_vec())
    }
}

/// Text chunking strategies
pub struct TextChunker {
    chunk_size: usize,
    overlap: usize,
}

impl TextChunker {
    pub fn new(chunk_size: usize, overlap: usize) -> Self {
        Self {
            chunk_size,
            overlap,
        }
    }

    pub fn chunk_text(&self, text: &str, document_id: &str) -> Vec<DocumentChunk> {
        let mut chunks = Vec::new();
        let chars: Vec<char> = text.chars().collect();

        if chars.len() <= self.chunk_size {
            // Single chunk
            chunks.push(DocumentChunk {
                id: format!("{}_chunk_0", document_id),
                content: text.to_string(),
                start_index: 0,
                end_index: chars.len(),
                metadata: HashMap::new(),
                embedding: None,
            });
            return chunks;
        }

        let mut start = 0;
        let mut chunk_index = 0;

        while start < chars.len() {
            let end = std::cmp::min(start + self.chunk_size, chars.len());
            let chunk_content: String = chars[start..end].iter().collect();

            chunks.push(DocumentChunk {
                id: format!("{}_chunk_{}", document_id, chunk_index),
                content: chunk_content,
                start_index: start,
                end_index: end,
                metadata: HashMap::new(),
                embedding: None,
            });

            // Move start position with overlap consideration
            if end == chars.len() {
                break;
            }

            start = end - self.overlap;
            // usize cannot be negative, so check for underflow/zero
            if start == 0 {
                start = end;
            }

            chunk_index += 1;
        }

        chunks
    }

    pub fn chunk_by_sentences(&self, text: &str, document_id: &str) -> Vec<DocumentChunk> {
        let sentences: Vec<&str> = text.split('.').collect();
        let mut chunks = Vec::new();
        let mut current_chunk = String::new();
        let mut start_index = 0;
        let mut chunk_index = 0;

        for sentence in sentences {
            let sentence = sentence.trim();
            if sentence.is_empty() {
                continue;
            }

            // Check if adding this sentence would exceed chunk size
            if !current_chunk.is_empty()
                && (current_chunk.len() + sentence.len() + 2) > self.chunk_size
            {
                // Finalize current chunk
                chunks.push(DocumentChunk {
                    id: format!("{}_sent_chunk_{}", document_id, chunk_index),
                    content: current_chunk.clone(),
                    start_index,
                    end_index: start_index + current_chunk.len(),
                    metadata: [("chunk_type".to_string(), serde_json::json!("sentence"))]
                        .iter()
                        .cloned()
                        .collect(),
                    embedding: None,
                });

                start_index += current_chunk.len();
                current_chunk.clear();
                chunk_index += 1;
            }

            if !current_chunk.is_empty() {
                current_chunk.push_str(". ");
            }
            current_chunk.push_str(sentence);
        }

        // Add final chunk if not empty
        if !current_chunk.is_empty() {
            let chunk_len = current_chunk.len();
            chunks.push(DocumentChunk {
                id: format!("{}_sent_chunk_{}", document_id, chunk_index),
                content: current_chunk,
                start_index,
                end_index: start_index + chunk_len,
                metadata: [("chunk_type".to_string(), serde_json::json!("sentence"))]
                    .iter()
                    .cloned()
                    .collect(),
                embedding: None,
            });
        }

        chunks
    }
}

/// RAG (Retrieval-Augmented Generation) system
pub struct RagSystem {
    vector_store: Box<dyn VectorStore>,
    embedding_provider: Box<dyn EmbeddingProvider>,
    chunker: TextChunker,
}

impl RagSystem {
    pub fn new(
        vector_store: Box<dyn VectorStore>,
        embedding_provider: Box<dyn EmbeddingProvider>,
        chunk_size: Option<usize>,
        overlap: Option<usize>,
    ) -> Self {
        Self {
            vector_store,
            embedding_provider,
            chunker: TextChunker::new(chunk_size.unwrap_or(1000), overlap.unwrap_or(100)),
        }
    }

    pub async fn embed_text(&self, text: &str) -> Result<Vec<f32>> {
        self.embedding_provider.embed_text(text).await
    }

    pub async fn add_document(
        &mut self,
        id: String,
        content: String,
        metadata: HashMap<String, serde_json::Value>,
    ) -> Result<String> {
        info!("Adding document to RAG system: {}", id);

        // Chunk the document
        let mut chunks = self.chunker.chunk_text(&content, &id);

        // Generate embeddings for chunks
        let chunk_texts: Vec<&str> = chunks.iter().map(|c| c.content.as_str()).collect();
        let embeddings = self.embedding_provider.embed_batch(chunk_texts).await?;

        // Assign embeddings to chunks
        for (chunk, embedding) in chunks.iter_mut().zip(embeddings.iter()) {
            chunk.embedding = Some(embedding.clone());
        }

        // Create document with embeddings
        let document = Document {
            id: id.clone(),
            content,
            metadata,
            embedding: None, // Could generate document-level embedding if needed
            chunks: chunks.clone(),
        };

        // Store in vector store
        self.vector_store.store_document(document).await?;

        info!("Added document {} with {} chunks", id, chunks.len());
        Ok(id)
    }

    pub async fn search(
        &self,
        query: &str,
        limit: Option<usize>,
        similarity_threshold: Option<f32>,
    ) -> Result<SearchResponse> {
        debug!("Searching RAG system for: {}", query);

        // Generate query embedding
        let query_embedding = self.embedding_provider.embed_text(query).await?;

        // Search vector store
        let request = QueryRequest {
            query: query.to_string(),
            limit,
            similarity_threshold,
            filters: HashMap::new(),
            include_metadata: true,
        };

        let response = self.vector_store.search(query_embedding, request).await?;

        info!(
            "Found {} results for query: {}",
            response.results.len(),
            query
        );
        Ok(response)
    }

    pub async fn get_context_for_query(
        &self,
        query: &str,
        max_context_length: usize,
    ) -> Result<String> {
        let search_response = self.search(query, Some(10), Some(0.7)).await?;

        let mut context = String::new();
        let mut current_length = 0;

        for result in search_response.results {
            let chunk_content = &result.chunk.content;
            if current_length + chunk_content.len() > max_context_length {
                break;
            }

            if !context.is_empty() {
                context.push_str("\n\n");
                current_length += 2;
            }

            context.push_str(chunk_content);
            current_length += chunk_content.len();
        }

        Ok(context)
    }

    pub async fn delete_document(&mut self, document_id: &str) -> Result<()> {
        self.vector_store.delete_document(document_id).await
    }

    pub async fn list_documents(&self, offset: usize, limit: usize) -> Result<Vec<String>> {
        self.vector_store.list_documents(offset, limit).await
    }
}

/// Create a default RAG system with in-memory storage
pub fn create_default_rag_system() -> Result<RagSystem> {
    let vector_store = Box::new(InMemoryVectorStore::new());

    // Try to create OpenAI embedding provider if API key is available
    let embedding_provider: Box<dyn EmbeddingProvider> =
        if let Ok(api_key) = std::env::var("OPENAI_API_KEY") {
            Box::new(OpenAIEmbeddingProvider::new(api_key))
        } else {
            return Err(anyhow!(
                "No embedding provider available. Set OPENAI_API_KEY environment variable."
            ));
        };

    Ok(RagSystem::new(
        vector_store,
        embedding_provider,
        Some(1000), // chunk_size
        Some(200),  // overlap
    ))
}
