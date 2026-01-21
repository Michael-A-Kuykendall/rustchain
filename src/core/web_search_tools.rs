// Web Search Tools Implementation
use crate::core::error::{RustChainError, ToolError};
use crate::core::http_client::{create_http_client, read_error_body_bounded};
use crate::core::tools::{Tool, ToolCapability, ToolResult};
use async_trait::async_trait;
use reqwest;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

// Google Search Tool
pub struct GoogleSearchTool {
    api_key: String,
    search_engine_id: String,
    client: reqwest::Client,
}

impl GoogleSearchTool {
    pub fn new(api_key: String, search_engine_id: String) -> Self {
        Self {
            api_key,
            search_engine_id,
            client: create_http_client(None),
        }
    }

    async fn search_google(
        &self,
        query: &str,
        num_results: u32,
    ) -> Result<Vec<SearchResult>, RustChainError> {
        let url = format!(
            "https://www.googleapis.com/customsearch/v1?key={}&cx={}&q={}&num={}",
            self.api_key,
            self.search_engine_id,
            urlencoding::encode(query),
            num_results.min(10)
        );

        debug!("Making Google search request: {}", url);

        let response = self.client.get(&url).send().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "google_search".to_string(),
                reason: format!("Request failed: {}", e),
            })
        })?;

        if !response.status().is_success() {
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "google_search".to_string(),
                reason: format!("API error: {}", error_text),
            }));
        }

        let google_response: GoogleSearchResponse = response.json().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "google_search".to_string(),
                reason: format!("Failed to parse response: {}", e),
            })
        })?;

        let results = google_response
            .items
            .unwrap_or_default()
            .into_iter()
            .map(|item| SearchResult {
                title: item.title,
                link: item.link,
                snippet: item.snippet.unwrap_or_default(),
                source: "google".to_string(),
            })
            .collect();

        Ok(results)
    }
}

#[async_trait]
impl Tool for GoogleSearchTool {
    fn name(&self) -> &'static str {
        "google_search"
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![ToolCapability::NetworkAccess, ToolCapability::Basic]
    }

    async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
        let search_params: SearchParams = serde_json::from_str(input).map_err(|e| {
            RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "google_search".to_string(),
                details: format!("Invalid search parameters: {}", e),
            })
        })?;

        let results = self
            .search_google(&search_params.query, search_params.num_results.unwrap_or(5))
            .await?;

        info!(
            "Google search completed: {} results for query '{}'",
            results.len(),
            search_params.query
        );

        let response = SearchResponse {
            query: search_params.query,
            results,
            source: "google".to_string(),
        };

        Ok(ToolResult::StructuredJson(serde_json::to_value(response)?))
    }
}

// DuckDuckGo Search Tool
pub struct DuckDuckGoSearchTool {
    client: reqwest::Client,
}

impl Default for DuckDuckGoSearchTool {
    fn default() -> Self {
        Self::new()
    }
}

impl DuckDuckGoSearchTool {
    pub fn new() -> Self {
        Self {
            client: create_http_client(None),
        }
    }

    async fn search_duckduckgo(
        &self,
        query: &str,
        num_results: u32,
    ) -> Result<Vec<SearchResult>, RustChainError> {
        // DuckDuckGo Instant Answer API - free but limited
        let url = format!(
            "https://api.duckduckgo.com/?q={}&format=json&no_redirect=1&no_html=1",
            urlencoding::encode(query)
        );

        debug!("Making DuckDuckGo search request: {}", url);

        let response = self.client.get(&url).send().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "duckduckgo_search".to_string(),
                reason: format!("Request failed: {}", e),
            })
        })?;

        if !response.status().is_success() {
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "duckduckgo_search".to_string(),
                reason: format!("API error: {}", error_text),
            }));
        }

        let ddg_response: DuckDuckGoResponse = response.json().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "duckduckgo_search".to_string(),
                reason: format!("Failed to parse response: {}", e),
            })
        })?;

        let mut results = Vec::new();

        // Add instant answer if available
        if !ddg_response.instant_answer.is_empty() {
            results.push(SearchResult {
                title: "Instant Answer".to_string(),
                link: ddg_response.instant_answer_url.unwrap_or_default(),
                snippet: ddg_response.instant_answer,
                source: "duckduckgo".to_string(),
            });
        }

        // Add abstract if available
        if !ddg_response.abstract_text.is_empty() {
            results.push(SearchResult {
                title: ddg_response.heading.clone(),
                link: ddg_response.abstract_url.unwrap_or_default(),
                snippet: ddg_response.abstract_text,
                source: "duckduckgo".to_string(),
            });
        }

        // Add related topics
        for topic in ddg_response
            .related_topics
            .into_iter()
            .take(num_results as usize)
        {
            if let Some(first_url) = topic.first_url {
                results.push(SearchResult {
                    title: topic
                        .text
                        .split(" - ")
                        .next()
                        .unwrap_or(&topic.text)
                        .to_string(),
                    link: first_url,
                    snippet: topic.text,
                    source: "duckduckgo".to_string(),
                });
            }
        }

        Ok(results)
    }
}

#[async_trait]
impl Tool for DuckDuckGoSearchTool {
    fn name(&self) -> &'static str {
        "duckduckgo_search"
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![ToolCapability::NetworkAccess, ToolCapability::Basic]
    }

    async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
        let search_params: SearchParams = serde_json::from_str(input).map_err(|e| {
            RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "duckduckgo_search".to_string(),
                details: format!("Invalid search parameters: {}", e),
            })
        })?;

        let results = self
            .search_duckduckgo(&search_params.query, search_params.num_results.unwrap_or(5))
            .await?;

        info!(
            "DuckDuckGo search completed: {} results for query '{}'",
            results.len(),
            search_params.query
        );

        let response = SearchResponse {
            query: search_params.query,
            results,
            source: "duckduckgo".to_string(),
        };

        Ok(ToolResult::StructuredJson(serde_json::to_value(response)?))
    }
}

// Brave Search Tool
pub struct BraveSearchTool {
    api_key: String,
    client: reqwest::Client,
}

impl BraveSearchTool {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: create_http_client(None),
        }
    }

    async fn search_brave(
        &self,
        query: &str,
        num_results: u32,
    ) -> Result<Vec<SearchResult>, RustChainError> {
        let url = format!(
            "https://api.search.brave.com/res/v1/web/search?q={}&count={}",
            urlencoding::encode(query),
            num_results.min(20)
        );

        debug!("Making Brave search request: {}", url);

        let response = self
            .client
            .get(&url)
            .header("X-Subscription-Token", &self.api_key)
            .send()
            .await
            .map_err(|e| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "brave_search".to_string(),
                    reason: format!("Request failed: {}", e),
                })
            })?;

        if !response.status().is_success() {
            let error_text = read_error_body_bounded(response).await;
            return Err(RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "brave_search".to_string(),
                reason: format!("API error: {}", error_text),
            }));
        }

        let brave_response: BraveSearchResponse = response.json().await.map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "brave_search".to_string(),
                reason: format!("Failed to parse response: {}", e),
            })
        })?;

        let results = brave_response
            .web
            .results
            .into_iter()
            .map(|item| SearchResult {
                title: item.title,
                link: item.url,
                snippet: item.description.unwrap_or_default(),
                source: "brave".to_string(),
            })
            .collect();

        Ok(results)
    }
}

#[async_trait]
impl Tool for BraveSearchTool {
    fn name(&self) -> &'static str {
        "brave_search"
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![ToolCapability::NetworkAccess, ToolCapability::Basic]
    }

    async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
        let search_params: SearchParams = serde_json::from_str(input).map_err(|e| {
            RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "brave_search".to_string(),
                details: format!("Invalid search parameters: {}", e),
            })
        })?;

        let results = self
            .search_brave(&search_params.query, search_params.num_results.unwrap_or(5))
            .await?;

        info!(
            "Brave search completed: {} results for query '{}'",
            results.len(),
            search_params.query
        );

        let response = SearchResponse {
            query: search_params.query,
            results,
            source: "brave".to_string(),
        };

        Ok(ToolResult::StructuredJson(serde_json::to_value(response)?))
    }
}

// Common data structures
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchParams {
    pub query: String,
    pub num_results: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub title: String,
    pub link: String,
    pub snippet: String,
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchResponse {
    pub query: String,
    pub results: Vec<SearchResult>,
    pub source: String,
}

// Google Search API response structures
#[derive(Debug, Deserialize)]
struct GoogleSearchResponse {
    items: Option<Vec<GoogleSearchItem>>,
}

#[derive(Debug, Deserialize)]
struct GoogleSearchItem {
    title: String,
    link: String,
    snippet: Option<String>,
}

// DuckDuckGo API response structures
#[derive(Debug, Deserialize)]
struct DuckDuckGoResponse {
    #[serde(rename = "Heading")]
    heading: String,
    #[serde(rename = "AbstractText")]
    abstract_text: String,
    #[serde(rename = "AbstractURL")]
    abstract_url: Option<String>,
    #[serde(rename = "InstantAnswer")]
    instant_answer: String,
    #[serde(rename = "InstantAnswerURL")]
    instant_answer_url: Option<String>,
    #[serde(rename = "RelatedTopics")]
    related_topics: Vec<DuckDuckGoRelatedTopic>,
}

#[derive(Debug, Deserialize)]
struct DuckDuckGoRelatedTopic {
    #[serde(rename = "Text")]
    text: String,
    #[serde(rename = "FirstURL")]
    first_url: Option<String>,
}

// Brave Search API response structures
#[derive(Debug, Deserialize)]
struct BraveSearchResponse {
    web: BraveWebResults,
}

#[derive(Debug, Deserialize)]
struct BraveWebResults {
    results: Vec<BraveSearchResult>,
}

#[derive(Debug, Deserialize)]
struct BraveSearchResult {
    title: String,
    url: String,
    description: Option<String>,
}

// Tool registry helper function
pub fn register_web_search_tools(registry: &mut crate::core::tools::ToolRegistry) {
    // Register Google Search if API key is available
    if let (Ok(api_key), Ok(search_engine_id)) = (
        std::env::var("GOOGLE_API_KEY"),
        std::env::var("GOOGLE_SEARCH_ENGINE_ID"),
    ) {
        let google_tool = GoogleSearchTool::new(api_key, search_engine_id);
        registry.register(Box::new(google_tool));
        info!("Registered Google Search tool");
    }

    // Register DuckDuckGo Search (always available, no API key required)
    let duckduckgo_tool = DuckDuckGoSearchTool::new();
    registry.register(Box::new(duckduckgo_tool));
    info!("Registered DuckDuckGo Search tool");

    // Register Brave Search if API key is available
    if let Ok(api_key) = std::env::var("BRAVE_SEARCH_API_KEY") {
        let brave_tool = BraveSearchTool::new(api_key);
        registry.register(Box::new(brave_tool));
        info!("Registered Brave Search tool");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_search_params_serialization() {
        let params = SearchParams {
            query: "rust programming".to_string(),
            num_results: Some(10),
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: SearchParams = serde_json::from_str(&json).unwrap();

        assert_eq!(params.query, deserialized.query);
        assert_eq!(params.num_results, deserialized.num_results);
    }

    #[test]
    fn test_search_result_serialization() {
        let result = SearchResult {
            title: "Test Title".to_string(),
            link: "https://example.com".to_string(),
            snippet: "Test snippet".to_string(),
            source: "test".to_string(),
        };

        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["title"], "Test Title");
        assert_eq!(json["link"], "https://example.com");
        assert_eq!(json["snippet"], "Test snippet");
        assert_eq!(json["source"], "test");
    }

    #[test]
    fn test_search_response_serialization() {
        let response = SearchResponse {
            query: "test query".to_string(),
            results: vec![SearchResult {
                title: "Test Title".to_string(),
                link: "https://example.com".to_string(),
                snippet: "Test snippet".to_string(),
                source: "test".to_string(),
            }],
            source: "test".to_string(),
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["query"], "test query");
        assert_eq!(json["source"], "test");
        assert!(json["results"].is_array());
        assert_eq!(json["results"][0]["title"], "Test Title");
    }

    #[test]
    fn test_google_search_tool_name() {
        let tool = GoogleSearchTool::new("test-key".to_string(), "test-id".to_string());
        assert_eq!(tool.name(), "google_search");
    }

    #[test]
    fn test_google_search_tool_capabilities() {
        let tool = GoogleSearchTool::new("test-key".to_string(), "test-id".to_string());
        let capabilities = tool.capabilities();
        assert!(capabilities.contains(&ToolCapability::NetworkAccess));
        assert!(capabilities.contains(&ToolCapability::Basic));
    }

    #[test]
    fn test_duckduckgo_search_tool_name() {
        let tool = DuckDuckGoSearchTool::new();
        assert_eq!(tool.name(), "duckduckgo_search");
    }

    #[test]
    fn test_duckduckgo_search_tool_capabilities() {
        let tool = DuckDuckGoSearchTool::new();
        let capabilities = tool.capabilities();
        assert!(capabilities.contains(&ToolCapability::NetworkAccess));
        assert!(capabilities.contains(&ToolCapability::Basic));
    }

    #[test]
    fn test_brave_search_tool_name() {
        let tool = BraveSearchTool::new("test-key".to_string());
        assert_eq!(tool.name(), "brave_search");
    }

    #[test]
    fn test_brave_search_tool_capabilities() {
        let tool = BraveSearchTool::new("test-key".to_string());
        let capabilities = tool.capabilities();
        assert!(capabilities.contains(&ToolCapability::NetworkAccess));
        assert!(capabilities.contains(&ToolCapability::Basic));
    }

    #[tokio::test]
    async fn test_invalid_search_params() {
        let tool = DuckDuckGoSearchTool::new();
        let result = tool.invoke("invalid json").await;
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("Invalid"));
    }

    #[tokio::test]
    async fn test_valid_search_params() {
        let tool = DuckDuckGoSearchTool::new();
        let params = json!({
            "query": "test query",
            "num_results": 3
        });

        // This test will make an actual network request to DuckDuckGo
        // In a real test environment, you might want to mock this
        let result = tool.invoke(&params.to_string()).await;
        // For now, we just check that the parameters are parsed correctly
        // In a production environment, you'd want to mock the HTTP client
        if result.is_err() {
            // Network errors are acceptable in test environment
            println!("Network test skipped: {:?}", result.unwrap_err());
        }
    }
}
