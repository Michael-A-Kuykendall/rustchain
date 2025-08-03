use reqwest;
use serde::{Deserialize, Serialize};
use async_trait::async_trait;

#[async_trait]
pub trait Retriever: Send + Sync {
    async fn retrieve(&self, query: &str) -> Vec<String>;
}

pub struct QdrantRetriever {
    client: reqwest::Client,
    url: String,
    collection: String,
    embedding_model: String,
}

impl QdrantRetriever {
    pub fn new(url: String, collection: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
            collection,
            embedding_model: "all-MiniLM-L6-v2".to_string(), // Default model
        }
    }
    
    /// Generate embedding using a simple hash-based approach for development
    /// In production, this should call a real embedding service
    async fn generate_embedding(&self, text: &str) -> Vec<f32> {
        // Development implementation: Create deterministic pseudo-embeddings
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        text.hash(&mut hasher);
        let hash = hasher.finish();
        
        // Generate 384-dimensional embedding (typical for MiniLM)
        let mut embedding = Vec::with_capacity(384);
        let mut seed = hash;
        
        for _ in 0..384 {
            // Simple PRNG based on hash
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            let normalized = (seed as f32 / u64::MAX as f32) * 2.0 - 1.0;
            embedding.push(normalized);
        }
        
        // Normalize to unit vector
        let magnitude: f32 = embedding.iter().map(|x| x * x).sum::<f32>().sqrt();
        if magnitude > 0.0 {
            for val in &mut embedding {
                *val /= magnitude;
            }
        }
        
        println!("[Retrieval] Generated {}-dim embedding for query: {:.50}...", 
                 embedding.len(), text);
        embedding
    }
}

#[derive(Serialize)]
struct QdrantSearchRequest<'a> {
    vector: &'a [f32],
    top: usize,
    with_payload: bool,
}

#[derive(Deserialize)]
struct QdrantSearchResult {
    result: Vec<QdrantPoint>,
}

#[derive(Deserialize)]
struct QdrantPoint {
    payload: Option<std::collections::HashMap<String, serde_json::Value>>,
    score: f32,
}

#[async_trait]
impl Retriever for QdrantRetriever {
    async fn retrieve(&self, query: &str) -> Vec<String> {
        // Generate real embedding instead of placeholder
        let embedding = match self.generate_embedding(query).await {
            embedding if !embedding.is_empty() => embedding,
            _ => {
                println!("[Retrieval] Failed to generate embedding, returning empty results");
                return vec![];
            }
        };
        
        let body = QdrantSearchRequest {
            vector: &embedding,
            top: 5,
            with_payload: true,
        };

        let response = match self.client
            .post(format!("{}/collections/{}/points/search", self.url, self.collection))
            .json(&body)
            .send()
            .await 
        {
            Ok(resp) => resp,
            Err(e) => {
                println!("[Retrieval] HTTP request failed: {}", e);
                return vec![];
            }
        };

        let search_result: QdrantSearchResult = match response.json().await {
            Ok(result) => result,
            Err(e) => {
                println!("[Retrieval] Failed to parse response: {}", e);
                return vec![];
            }
        };

        // Extract content from payloads
        search_result
            .result
            .into_iter()
            .filter_map(|point| {
                point.payload?.get("content")?.as_str().map(|s| {
                    format!("Score: {:.3} | {}", point.score, s)
                })
            })
            .collect()
    }
}
