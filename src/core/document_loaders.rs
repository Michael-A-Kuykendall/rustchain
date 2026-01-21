// Document Loaders Implementation
use crate::core::error::{RustChainError, ToolError};
use crate::core::tools::{Tool, ToolCapability, ToolResult};
use async_trait::async_trait;
use csv::ReaderBuilder;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{debug, info};

// PDF Document Loader
pub struct PdfDocumentLoader;

impl Default for PdfDocumentLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl PdfDocumentLoader {
    pub fn new() -> Self {
        Self
    }

    async fn load_pdf(&self, file_path: &str) -> Result<DocumentContent, RustChainError> {
        let path = Path::new(file_path);

        if !path.exists() {
            return Err(RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "pdf_loader".to_string(),
                details: format!("File does not exist: {}", file_path),
            }));
        }

        if !path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("pdf"))
        {
            return Err(RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "pdf_loader".to_string(),
                details: format!("File is not a PDF: {}", file_path),
            }));
        }

        let file_content = fs::read(file_path).map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "pdf_loader".to_string(),
                reason: format!("Failed to read file: {}", e),
            })
        })?;

        // Try to extract text using basic PDF text extraction
        let text = self.extract_text_from_pdf(&file_content)?;

        let metadata = DocumentMetadata {
            file_path: file_path.to_string(),
            file_size: file_content.len(),
            content_type: "application/pdf".to_string(),
            pages: self.count_pdf_pages(&file_content)?,
            created_at: None,
            modified_at: None,
        };

        Ok(DocumentContent {
            text,
            metadata,
            source: "pdf_loader".to_string(),
        })
    }

    fn extract_text_from_pdf(&self, pdf_data: &[u8]) -> Result<String, RustChainError> {
        // Basic PDF text extraction using simple string parsing
        // Note: This is a simplified approach. In production, you'd want to use a proper PDF library like pdf-extract
        let pdf_string = String::from_utf8_lossy(pdf_data);

        // Look for text objects in the PDF stream
        let mut extracted_text = String::new();
        let mut in_text_object = false;

        for line in pdf_string.lines() {
            if line.contains("BT") {
                // Begin Text object
                in_text_object = true;
                continue;
            }
            if line.contains("ET") {
                // End Text object
                in_text_object = false;
                continue;
            }

            if in_text_object && line.contains("Tj") {
                // Extract text from Tj operators
                if let Some(start) = line.find('(') {
                    if let Some(end) = line.rfind(')') {
                        let text_part = &line[start + 1..end];
                        extracted_text.push_str(text_part);
                        extracted_text.push(' ');
                    }
                }
            }
        }

        // If basic extraction fails, provide a fallback message
        if extracted_text.trim().is_empty() {
            extracted_text = format!(
                "[PDF content detected - {} bytes. Basic text extraction did not find readable text. Consider using a specialized PDF processing library for better results.]",
                pdf_data.len()
            );
        }

        Ok(extracted_text.trim().to_string())
    }

    fn count_pdf_pages(&self, pdf_data: &[u8]) -> Result<usize, RustChainError> {
        let pdf_string = String::from_utf8_lossy(pdf_data);

        // Count /Type /Page occurrences as a simple page count method
        let page_count = pdf_string.matches("/Type /Page").count();

        // If no pages found, assume at least 1 page
        Ok(page_count.max(1))
    }
}

#[async_trait]
impl Tool for PdfDocumentLoader {
    fn name(&self) -> &'static str {
        "pdf_loader"
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![ToolCapability::Basic, ToolCapability::SystemAccess]
    }

    async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
        let load_params: DocumentLoadParams = serde_json::from_str(input).map_err(|e| {
            RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "pdf_loader".to_string(),
                details: format!("Invalid parameters: {}", e),
            })
        })?;

        debug!("Loading PDF document: {}", load_params.file_path);

        let document = self.load_pdf(&load_params.file_path).await?;

        info!(
            "PDF loaded successfully: {} characters, {} pages",
            document.text.len(),
            document.metadata.pages
        );

        Ok(ToolResult::StructuredJson(serde_json::to_value(document)?))
    }
}

// CSV Document Loader
pub struct CsvDocumentLoader;

impl Default for CsvDocumentLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl CsvDocumentLoader {
    pub fn new() -> Self {
        Self
    }

    async fn load_csv(
        &self,
        file_path: &str,
        delimiter: Option<char>,
        has_headers: bool,
    ) -> Result<DocumentContent, RustChainError> {
        let path = Path::new(file_path);

        if !path.exists() {
            return Err(RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "csv_loader".to_string(),
                details: format!("File does not exist: {}", file_path),
            }));
        }

        let file_content = fs::read_to_string(file_path).map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "csv_loader".to_string(),
                reason: format!("Failed to read file: {}", e),
            })
        })?;

        let delimiter = delimiter.unwrap_or(',');
        let csv_data = self.parse_csv(&file_content, delimiter, has_headers)?;

        let metadata = DocumentMetadata {
            file_path: file_path.to_string(),
            file_size: file_content.len(),
            content_type: "text/csv".to_string(),
            pages: 1, // CSV files have 1 "page"
            created_at: None,
            modified_at: None,
        };

        Ok(DocumentContent {
            text: csv_data.formatted_text,
            metadata,
            source: "csv_loader".to_string(),
        })
    }

    fn parse_csv(
        &self,
        content: &str,
        delimiter: char,
        has_headers: bool,
    ) -> Result<CsvData, RustChainError> {
        // Use the csv crate for parsing
        let mut reader = ReaderBuilder::new()
            .delimiter(delimiter as u8)
            .has_headers(has_headers)
            .flexible(true) // Allow records with varying lengths
            .from_reader(content.as_bytes());

        let mut headers = Vec::new();
        let mut rows = Vec::new();
        let mut formatted_text = String::new();

        // Get headers if they exist
        if has_headers {
            if let Ok(header_record) = reader.headers() {
                headers = header_record.iter().map(|h| h.to_string()).collect();
                formatted_text.push_str(&format!("Headers: {}\n\n", headers.join(" | ")));
            }
        }

        // If no headers, generate column names based on first record
        if headers.is_empty() {
            if let Some(Ok(record)) = reader.records().next() {
                headers = (1..=record.len())
                    .map(|i| format!("Column_{}", i))
                    .collect();
                // Reset reader to beginning since we consumed the first record
                reader = ReaderBuilder::new()
                    .delimiter(delimiter as u8)
                    .has_headers(false)
                    .flexible(true)
                    .from_reader(content.as_bytes());
            }
        }

        // Parse all records
        for (row_index, record_result) in reader.records().enumerate() {
            match record_result {
                Ok(record) => {
                    let row: Vec<String> = record.iter().map(|field| field.to_string()).collect();

                    // Format row for text representation
                    if !headers.is_empty() && headers.len() == row.len() {
                        formatted_text.push_str(&format!("Row {}:\n", row_index + 1));
                        for (header, value) in headers.iter().zip(row.iter()) {
                            formatted_text.push_str(&format!("  {}: {}\n", header, value));
                        }
                        formatted_text.push('\n');
                    } else {
                        formatted_text.push_str(&format!(
                            "Row {}: {}\n",
                            row_index + 1,
                            row.join(" | ")
                        ));
                    }

                    rows.push(row);
                }
                Err(e) => {
                    // Log parsing errors but continue processing
                    tracing::warn!("CSV parsing error on row {}: {}", row_index + 1, e);
                    formatted_text.push_str(&format!(
                        "Row {} (parsing error): {}\n",
                        row_index + 1,
                        e
                    ));
                }
            }
        }

        // Add summary information
        formatted_text.push_str("\nSummary:\n");
        formatted_text.push_str(&format!("  Columns: {}\n", headers.len()));
        formatted_text.push_str(&format!("  Rows: {}\n", rows.len()));

        if !headers.is_empty() {
            formatted_text.push_str(&format!("  Column Names: {}\n", headers.join(", ")));
        }

        Ok(CsvData {
            headers,
            rows,
            formatted_text,
        })
    }
}

#[async_trait]
impl Tool for CsvDocumentLoader {
    fn name(&self) -> &'static str {
        "csv_loader"
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![ToolCapability::Basic, ToolCapability::SystemAccess]
    }

    async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
        let load_params: CsvLoadParams = serde_json::from_str(input).map_err(|e| {
            RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "csv_loader".to_string(),
                details: format!("Invalid parameters: {}", e),
            })
        })?;

        debug!("Loading CSV document: {}", load_params.file_path);

        let document = self
            .load_csv(
                &load_params.file_path,
                load_params
                    .delimiter
                    .map(|s| s.chars().next().unwrap_or(',')),
                load_params.has_headers.unwrap_or(true),
            )
            .await?;

        info!(
            "CSV loaded successfully: {} characters, {} rows",
            document.text.len(),
            document.text.lines().count()
        );

        Ok(ToolResult::StructuredJson(serde_json::to_value(document)?))
    }
}

// Common data structures
#[derive(Debug, Serialize, Deserialize)]
pub struct DocumentLoadParams {
    pub file_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CsvLoadParams {
    pub file_path: String,
    pub delimiter: Option<String>,
    pub has_headers: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentContent {
    pub text: String,
    pub metadata: DocumentMetadata,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentMetadata {
    pub file_path: String,
    pub file_size: usize,
    pub content_type: String,
    pub pages: usize,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CsvData {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub formatted_text: String,
}

// JSON/YAML Document Loader
pub struct JsonYamlDocumentLoader;

impl Default for JsonYamlDocumentLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonYamlDocumentLoader {
    pub fn new() -> Self {
        Self
    }

    async fn load_json_yaml(
        &self,
        file_path: &str,
        format: Option<&str>,
    ) -> Result<DocumentContent, RustChainError> {
        let path = Path::new(file_path);

        if !path.exists() {
            return Err(RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "json_yaml_loader".to_string(),
                details: format!("File does not exist: {}", file_path),
            }));
        }

        // Auto-detect format from file extension if not specified
        let detected_format = if let Some(fmt) = format {
            fmt.to_lowercase()
        } else {
            match path.extension().and_then(|ext| ext.to_str()) {
                Some("json") => "json".to_string(),
                Some("yaml") | Some("yml") => "yaml".to_string(),
                _ => return Err(RustChainError::Tool(ToolError::InvalidParameters {
                    tool_name: "json_yaml_loader".to_string(),
                    details: format!("Cannot auto-detect format for file: {}. Supported extensions: .json, .yaml, .yml", file_path),
                })),
            }
        };

        let file_content = fs::read_to_string(file_path).map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "json_yaml_loader".to_string(),
                reason: format!("Failed to read file: {}", e),
            })
        })?;

        // Parse the structured data based on format
        let structured_data = match detected_format.as_str() {
            "json" => self.parse_json(&file_content)?,
            "yaml" => self.parse_yaml(&file_content)?,
            _ => {
                return Err(RustChainError::Tool(ToolError::InvalidParameters {
                    tool_name: "json_yaml_loader".to_string(),
                    details: format!(
                        "Unsupported format: {}. Supported formats: json, yaml",
                        detected_format
                    ),
                }))
            }
        };

        let file_size = file_content.len();
        let content_type = match detected_format.as_str() {
            "json" => "application/json",
            "yaml" => "application/yaml",
            _ => "text/plain",
        };

        // Generate human-readable text from structured data
        let formatted_text = self.format_structured_data(&structured_data, &detected_format);

        let metadata = DocumentMetadata {
            file_path: file_path.to_string(),
            file_size,
            content_type: content_type.to_string(),
            pages: 1, // JSON/YAML files are single-page documents
            created_at: None,
            modified_at: None,
        };

        info!(
            "JSON/YAML loaded successfully: {} characters, format: {}",
            formatted_text.len(),
            detected_format
        );

        Ok(DocumentContent {
            text: formatted_text,
            metadata,
            source: "json_yaml_loader".to_string(),
        })
    }

    fn parse_json(&self, content: &str) -> Result<serde_json::Value, RustChainError> {
        serde_json::from_str(content).map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "json_yaml_loader".to_string(),
                reason: format!("JSON parsing error: {}", e),
            })
        })
    }

    fn parse_yaml(&self, content: &str) -> Result<serde_json::Value, RustChainError> {
        serde_yaml::from_str(content).map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "json_yaml_loader".to_string(),
                reason: format!("YAML parsing error: {}", e),
            })
        })
    }

    fn format_structured_data(&self, data: &serde_json::Value, format: &str) -> String {
        let mut result = String::new();

        result.push_str(&format!("Document Format: {}\n", format.to_uppercase()));
        result.push_str("Structure Analysis:\n");

        match data {
            serde_json::Value::Object(map) => {
                result.push_str("  Type: Object\n");
                result.push_str(&format!("  Keys: {}\n", map.len()));
                result.push_str(&format!(
                    "  Top-level keys: {}\n",
                    map.keys().take(10).cloned().collect::<Vec<_>>().join(", ")
                ));

                // Add structured content
                result.push_str("\nContent:\n");
                result.push_str(
                    &serde_json::to_string_pretty(data)
                        .unwrap_or_else(|_| "Invalid JSON".to_string()),
                );
            }
            serde_json::Value::Array(arr) => {
                result.push_str("  Type: Array\n");
                result.push_str(&format!("  Length: {}\n", arr.len()));

                if !arr.is_empty() {
                    if let Some(first) = arr.first() {
                        result.push_str(&format!(
                            "  First element type: {}\n",
                            match first {
                                serde_json::Value::Object(_) => "Object",
                                serde_json::Value::Array(_) => "Array",
                                serde_json::Value::String(_) => "String",
                                serde_json::Value::Number(_) => "Number",
                                serde_json::Value::Bool(_) => "Boolean",
                                serde_json::Value::Null => "Null",
                            }
                        ));
                    }
                }

                // Add structured content
                result.push_str("\nContent:\n");
                result.push_str(
                    &serde_json::to_string_pretty(data)
                        .unwrap_or_else(|_| "Invalid JSON".to_string()),
                );
            }
            _ => {
                result.push_str(&format!(
                    "  Type: {}\n",
                    match data {
                        serde_json::Value::String(_) => "String",
                        serde_json::Value::Number(_) => "Number",
                        serde_json::Value::Bool(_) => "Boolean",
                        serde_json::Value::Null => "Null",
                        _ => "Unknown",
                    }
                ));

                result.push_str("\nContent:\n");
                result.push_str(
                    &serde_json::to_string_pretty(data)
                        .unwrap_or_else(|_| "Invalid JSON".to_string()),
                );
            }
        }

        result
    }
}

#[async_trait]
impl Tool for JsonYamlDocumentLoader {
    fn name(&self) -> &'static str {
        "json_yaml_loader"
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![ToolCapability::Basic, ToolCapability::SystemAccess]
    }

    async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
        let load_params: JsonYamlLoadParams = serde_json::from_str(input).map_err(|e| {
            RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "json_yaml_loader".to_string(),
                details: format!("Invalid parameters: {}", e),
            })
        })?;

        let document = self
            .load_json_yaml(&load_params.file_path, load_params.format.as_deref())
            .await?;

        Ok(ToolResult::StructuredJson(serde_json::to_value(document)?))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonYamlLoadParams {
    pub file_path: String,
    pub format: Option<String>, // "json" or "yaml" - auto-detects if not specified
}

// HTML Document Loader
pub struct HtmlDocumentLoader;

impl Default for HtmlDocumentLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl HtmlDocumentLoader {
    pub fn new() -> Self {
        Self
    }

    async fn load_html(
        &self,
        file_path: &str,
        extract_mode: Option<&str>,
    ) -> Result<DocumentContent, RustChainError> {
        let path = Path::new(file_path);

        if !path.exists() {
            return Err(RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "html_loader".to_string(),
                details: format!("File does not exist: {}", file_path),
            }));
        }

        // Check file extension for HTML files
        let is_html_file = matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("html") | Some("htm")
        );

        let file_content = fs::read_to_string(file_path).map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "html_loader".to_string(),
                reason: format!("Failed to read file: {}", e),
            })
        })?;

        // Parse the HTML content
        let parsed_content = self.parse_html(&file_content, extract_mode.unwrap_or("text"))?;

        let file_size = file_content.len();
        let content_type = if is_html_file {
            "text/html"
        } else {
            "text/plain"
        };

        let metadata = DocumentMetadata {
            file_path: file_path.to_string(),
            file_size,
            content_type: content_type.to_string(),
            pages: 1, // HTML files are single-page documents
            created_at: None,
            modified_at: None,
        };

        info!(
            "HTML loaded successfully: {} characters, mode: {}",
            parsed_content.len(),
            extract_mode.unwrap_or("text")
        );

        Ok(DocumentContent {
            text: parsed_content,
            metadata,
            source: "html_loader".to_string(),
        })
    }

    fn parse_html(&self, content: &str, extract_mode: &str) -> Result<String, RustChainError> {
        use scraper::Html;

        let document = Html::parse_document(content);

        match extract_mode {
            "text" => self.extract_text_content(&document),
            "structure" => self.extract_structural_analysis(&document),
            "links" => self.extract_links(&document),
            "metadata" => self.extract_metadata(&document),
            "all" => {
                let text = self.extract_text_content(&document)?;
                let structure = self.extract_structural_analysis(&document)?;
                let links = self.extract_links(&document)?;
                let metadata = self.extract_metadata(&document)?;

                Ok(format!(
                    "=== HTML DOCUMENT ANALYSIS ===\n\n{}\n\n=== STRUCTURAL ANALYSIS ===\n\n{}\n\n=== EXTRACTED LINKS ===\n\n{}\n\n=== PAGE METADATA ===\n\n{}",
                    text, structure, links, metadata
                ))
            },
            _ => Err(RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "html_loader".to_string(),
                details: format!("Unsupported extract mode: {}. Supported modes: text, structure, links, metadata, all", extract_mode),
            })),
        }
    }

    fn extract_text_content(&self, document: &scraper::Html) -> Result<String, RustChainError> {
        use scraper::Selector;

        // Extract meaningful text content
        let body_selector = Selector::parse("body").map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "html_loader".to_string(),
                reason: format!("CSS selector error: {}", e),
            })
        })?;

        let text_content = if let Some(body) = document.select(&body_selector).next() {
            self.extract_element_text(body)
        } else {
            // Fallback to entire document
            document.root_element().text().collect::<Vec<_>>().join(" ")
        };

        // Clean up whitespace
        let cleaned = text_content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join("\n");

        Ok(cleaned)
    }

    fn extract_element_text(&self, element: scraper::ElementRef) -> String {
        element.text().collect::<Vec<_>>().join(" ")
    }

    fn extract_structural_analysis(
        &self,
        document: &scraper::Html,
    ) -> Result<String, RustChainError> {
        use scraper::Selector;

        let mut analysis = String::new();

        // Count different HTML elements
        let selectors = [
            ("Headings (h1)", "h1"),
            ("Headings (h2)", "h2"),
            ("Headings (h3)", "h3"),
            ("Headings (h4-h6)", "h4, h5, h6"),
            ("Paragraphs", "p"),
            ("Lists", "ul, ol"),
            ("List Items", "li"),
            ("Links", "a"),
            ("Images", "img"),
            ("Tables", "table"),
            ("Forms", "form"),
            ("Divs", "div"),
            ("Spans", "span"),
        ];

        analysis.push_str("HTML Structure Analysis:\n");

        for (name, selector_str) in &selectors {
            let selector = Selector::parse(selector_str).map_err(|e| {
                RustChainError::Tool(ToolError::ExecutionFailed {
                    tool_name: "html_loader".to_string(),
                    reason: format!("CSS selector error: {}", e),
                })
            })?;

            let count = document.select(&selector).count();
            if count > 0 {
                analysis.push_str(&format!("  • {}: {}\n", name, count));
            }
        }

        // Extract title
        // SAFETY: "title" is a valid CSS selector (compile-time constant)
        let title_selector = Selector::parse("title").expect("valid CSS selector");
        if let Some(title_element) = document.select(&title_selector).next() {
            let title_text = title_element.text().collect::<String>();
            if !title_text.trim().is_empty() {
                analysis.push_str(&format!("\nPage Title: {}\n", title_text.trim()));
            }
        }

        // Extract headings structure
        analysis.push_str("\nHeading Structure:\n");
        for level in 1..=6 {
            // SAFETY: h1-h6 are valid CSS selectors
            let heading_selector =
                Selector::parse(&format!("h{}", level)).expect("valid CSS selector");
            let headings: Vec<String> = document
                .select(&heading_selector)
                .map(|h| h.text().collect::<String>().trim().to_string())
                .filter(|h| !h.is_empty())
                .collect();

            if !headings.is_empty() {
                analysis.push_str(&format!("  H{}: {}\n", level, headings.join(", ")));
            }
        }

        Ok(analysis)
    }

    fn extract_links(&self, document: &scraper::Html) -> Result<String, RustChainError> {
        use scraper::Selector;

        let link_selector = Selector::parse("a[href]").map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "html_loader".to_string(),
                reason: format!("CSS selector error: {}", e),
            })
        })?;

        let mut links_text = String::new();
        links_text.push_str("Extracted Links:\n");

        let links: Vec<(String, String)> = document
            .select(&link_selector)
            .filter_map(|link| {
                let href = link.value().attr("href")?;
                let text = link.text().collect::<String>().trim().to_string();
                Some((href.to_string(), text))
            })
            .collect();

        if links.is_empty() {
            links_text.push_str("  No links found\n");
        } else {
            for (href, text) in links {
                let display_text = if text.is_empty() { "(no text)" } else { &text };
                links_text.push_str(&format!("  • {} → {}\n", display_text, href));
            }
        }

        Ok(links_text)
    }

    fn extract_metadata(&self, document: &scraper::Html) -> Result<String, RustChainError> {
        use scraper::Selector;

        let mut metadata = String::new();
        metadata.push_str("HTML Metadata:\n");

        // Extract meta tags
        let meta_selector = Selector::parse("meta").map_err(|e| {
            RustChainError::Tool(ToolError::ExecutionFailed {
                tool_name: "html_loader".to_string(),
                reason: format!("CSS selector error: {}", e),
            })
        })?;

        let meta_tags: Vec<(String, String)> = document
            .select(&meta_selector)
            .filter_map(|meta| {
                let name = meta
                    .value()
                    .attr("name")
                    .or_else(|| meta.value().attr("property"))
                    .or_else(|| meta.value().attr("http-equiv"))?;
                let content = meta.value().attr("content")?;
                Some((name.to_string(), content.to_string()))
            })
            .collect();

        if meta_tags.is_empty() {
            metadata.push_str("  No meta tags found\n");
        } else {
            for (name, content) in meta_tags {
                metadata.push_str(&format!("  • {}: {}\n", name, content));
            }
        }

        // Extract title
        // SAFETY: "title" is a valid CSS selector (compile-time constant)
        let title_selector = Selector::parse("title").expect("valid CSS selector");
        if let Some(title_element) = document.select(&title_selector).next() {
            let title_text = title_element.text().collect::<String>();
            if !title_text.trim().is_empty() {
                metadata.push_str(&format!("\nTitle: {}\n", title_text.trim()));
            }
        }

        // Extract language
        // SAFETY: "html" is a valid CSS selector (compile-time constant)
        let html_selector = Selector::parse("html").expect("valid CSS selector");
        if let Some(html_element) = document.select(&html_selector).next() {
            if let Some(lang) = html_element.value().attr("lang") {
                metadata.push_str(&format!("Language: {}\n", lang));
            }
        }

        Ok(metadata)
    }
}

#[async_trait]
impl Tool for HtmlDocumentLoader {
    fn name(&self) -> &'static str {
        "html_loader"
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![ToolCapability::Basic, ToolCapability::SystemAccess]
    }

    async fn invoke(&self, input: &str) -> Result<ToolResult, RustChainError> {
        let load_params: HtmlLoadParams = serde_json::from_str(input).map_err(|e| {
            RustChainError::Tool(ToolError::InvalidParameters {
                tool_name: "html_loader".to_string(),
                details: format!("Invalid parameters: {}", e),
            })
        })?;

        let document = self
            .load_html(&load_params.file_path, load_params.extract_mode.as_deref())
            .await?;

        Ok(ToolResult::StructuredJson(serde_json::to_value(document)?))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct HtmlLoadParams {
    pub file_path: String,
    pub extract_mode: Option<String>, // "text", "structure", "links", "metadata", "all" - defaults to "text"
}

// Tool registry helper function
pub fn register_document_loaders(registry: &mut crate::core::tools::ToolRegistry) {
    info!("Starting document loader registration...");

    // Register PDF loader
    let pdf_loader = PdfDocumentLoader::new();
    registry.register(Box::new(pdf_loader));
    info!("Registered PDF Document Loader");

    // Register CSV loader
    let csv_loader = CsvDocumentLoader::new();
    registry.register(Box::new(csv_loader));
    info!("Registered CSV Document Loader");

    // Register JSON/YAML loader
    let json_yaml_loader = JsonYamlDocumentLoader::new();
    registry.register(Box::new(json_yaml_loader));
    info!("Registered JSON/YAML Document Loader");

    // Register HTML loader
    let html_loader = HtmlDocumentLoader::new();
    registry.register(Box::new(html_loader));
    info!("Registered HTML Document Loader");

    info!("Document loader registration complete");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_document_load_params_serialization() {
        let params = DocumentLoadParams {
            file_path: "/path/to/document.pdf".to_string(),
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: DocumentLoadParams = serde_json::from_str(&json).unwrap();

        assert_eq!(params.file_path, deserialized.file_path);
    }

    #[test]
    fn test_csv_load_params_serialization() {
        let params = CsvLoadParams {
            file_path: "/path/to/data.csv".to_string(),
            delimiter: Some(";".to_string()),
            has_headers: Some(true),
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: CsvLoadParams = serde_json::from_str(&json).unwrap();

        assert_eq!(params.file_path, deserialized.file_path);
        assert_eq!(params.delimiter, deserialized.delimiter);
        assert_eq!(params.has_headers, deserialized.has_headers);
    }

    #[test]
    fn test_document_content_serialization() {
        let content = DocumentContent {
            text: "Sample document content".to_string(),
            metadata: DocumentMetadata {
                file_path: "/path/to/doc.pdf".to_string(),
                file_size: 1024,
                content_type: "application/pdf".to_string(),
                pages: 5,
                created_at: None,
                modified_at: None,
            },
            source: "pdf_loader".to_string(),
        };

        let json = serde_json::to_value(&content).unwrap();
        assert_eq!(json["text"], "Sample document content");
        assert_eq!(json["source"], "pdf_loader");
        assert_eq!(json["metadata"]["pages"], 5);
    }

    #[test]
    fn test_pdf_loader_name() {
        let loader = PdfDocumentLoader::new();
        assert_eq!(loader.name(), "pdf_loader");
    }

    #[test]
    fn test_pdf_loader_capabilities() {
        let loader = PdfDocumentLoader::new();
        let capabilities = loader.capabilities();
        assert!(capabilities.contains(&ToolCapability::Basic));
        assert!(capabilities.contains(&ToolCapability::SystemAccess));
    }

    #[test]
    fn test_csv_loader_name() {
        let loader = CsvDocumentLoader::new();
        assert_eq!(loader.name(), "csv_loader");
    }

    #[test]
    fn test_csv_loader_capabilities() {
        let loader = CsvDocumentLoader::new();
        let capabilities = loader.capabilities();
        assert!(capabilities.contains(&ToolCapability::Basic));
        assert!(capabilities.contains(&ToolCapability::SystemAccess));
    }

    #[test]
    fn test_csv_parsing_with_headers() {
        let loader = CsvDocumentLoader::new();

        // Test CSV with headers
        let csv_content = "name,age,city\nAlice,28,NYC\nBob,35,LA";
        let result = loader.parse_csv(csv_content, ',', true);

        assert!(result.is_ok());
        let csv_data = result.unwrap();
        assert_eq!(csv_data.headers, vec!["name", "age", "city"]);
        assert_eq!(csv_data.rows.len(), 2);
        assert_eq!(csv_data.rows[0], vec!["Alice", "28", "NYC"]);
        assert_eq!(csv_data.rows[1], vec!["Bob", "35", "LA"]);
    }

    #[test]
    fn test_csv_parsing_with_quotes() {
        let loader = CsvDocumentLoader::new();

        // Test CSV with quoted fields and commas within quotes
        let csv_content =
            "name,location\n\"John Doe\",\"New York, NY\"\n\"Jane Smith\",\"Los Angeles, CA\"";
        let result = loader.parse_csv(csv_content, ',', true);

        assert!(result.is_ok());
        let csv_data = result.unwrap();
        assert_eq!(csv_data.headers, vec!["name", "location"]);
        assert_eq!(csv_data.rows[0], vec!["John Doe", "New York, NY"]);
        assert_eq!(csv_data.rows[1], vec!["Jane Smith", "Los Angeles, CA"]);
    }

    #[test]
    fn test_csv_parsing_without_headers() {
        let loader = CsvDocumentLoader::new();

        // Test CSV without headers
        let csv_content = "Alice,28,NYC\nBob,35,LA";
        let result = loader.parse_csv(csv_content, ',', false);

        assert!(result.is_ok());
        let csv_data = result.unwrap();
        assert_eq!(csv_data.headers, vec!["Column_1", "Column_2", "Column_3"]);
        assert_eq!(csv_data.rows.len(), 2);
        assert_eq!(csv_data.rows[0], vec!["Alice", "28", "NYC"]);
    }

    #[tokio::test]
    async fn test_pdf_loader_invalid_file() {
        let loader = PdfDocumentLoader::new();
        let result = loader
            .invoke(r#"{"file_path": "/nonexistent/file.pdf"}"#)
            .await;

        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("does not exist"));
    }

    #[tokio::test]
    async fn test_csv_loader_with_temp_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.csv");

        let csv_content = "name,age,city\nJohn,30,New York\nJane,25,Los Angeles";
        let mut file = File::create(&file_path).unwrap();
        file.write_all(csv_content.as_bytes()).unwrap();

        let loader = CsvDocumentLoader::new();
        let params = serde_json::json!({
            "file_path": file_path.to_string_lossy(),
            "delimiter": ",",
            "has_headers": true
        });

        let result = loader.invoke(&params.to_string()).await;
        assert!(result.is_ok());

        if let Ok(ToolResult::StructuredJson(response)) = result {
            let doc: DocumentContent = serde_json::from_value(response).unwrap();
            assert!(doc.text.contains("John"));
            assert!(doc.text.contains("Jane"));
            assert_eq!(doc.metadata.content_type, "text/csv");
        }
    }

    #[tokio::test]
    async fn test_invalid_params() {
        let loader = PdfDocumentLoader::new();
        let result = loader.invoke("invalid json").await;
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("Invalid parameters"));
    }

    // JSON/YAML Loader Tests
    #[test]
    fn test_json_yaml_loader_name() {
        let loader = JsonYamlDocumentLoader::new();
        assert_eq!(loader.name(), "json_yaml_loader");
    }

    #[test]
    fn test_json_yaml_loader_capabilities() {
        let loader = JsonYamlDocumentLoader::new();
        let capabilities = loader.capabilities();
        assert!(capabilities.contains(&ToolCapability::Basic));
        assert!(capabilities.contains(&ToolCapability::SystemAccess));
    }

    #[test]
    fn test_json_yaml_load_params_serialization() {
        let params = JsonYamlLoadParams {
            file_path: "/path/to/data.json".to_string(),
            format: Some("json".to_string()),
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: JsonYamlLoadParams = serde_json::from_str(&json).unwrap();

        assert_eq!(params.file_path, deserialized.file_path);
        assert_eq!(params.format, deserialized.format);
    }

    #[test]
    fn test_json_parsing() {
        let loader = JsonYamlDocumentLoader::new();

        // Test valid JSON
        let json_content = r#"{"name": "Alice", "age": 30, "active": true}"#;
        let result = loader.parse_json(json_content);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed["name"], "Alice");
        assert_eq!(parsed["age"], 30);
        assert_eq!(parsed["active"], true);
    }

    #[test]
    fn test_json_parsing_invalid() {
        let loader = JsonYamlDocumentLoader::new();

        // Test invalid JSON
        let invalid_json = r#"{"name": "Alice", "age": 30, "active": true"#; // Missing closing brace
        let result = loader.parse_json(invalid_json);
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("JSON parsing error"));
    }

    #[test]
    fn test_yaml_parsing() {
        let loader = JsonYamlDocumentLoader::new();

        // Test valid YAML
        let yaml_content = r#"
name: Alice
age: 30
active: true
skills:
  - rust
  - python
  - javascript
"#;
        let result = loader.parse_yaml(yaml_content);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(parsed["name"], "Alice");
        assert_eq!(parsed["age"], 30);
        assert_eq!(parsed["active"], true);
        assert!(parsed["skills"].is_array());
    }

    #[test]
    fn test_yaml_parsing_invalid() {
        let loader = JsonYamlDocumentLoader::new();

        // Test invalid YAML (invalid indentation)
        let invalid_yaml = r#"
name: Alice
  age: 30
active: true
"#;
        let result = loader.parse_yaml(invalid_yaml);
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("YAML parsing error"));
    }

    #[test]
    fn test_format_structured_data_object() {
        let loader = JsonYamlDocumentLoader::new();

        let data = serde_json::json!({
            "name": "Alice",
            "age": 30,
            "location": "New York"
        });

        let formatted = loader.format_structured_data(&data, "json");
        assert!(formatted.contains("Document Format: JSON"));
        assert!(formatted.contains("Type: Object"));
        assert!(formatted.contains("Keys: 3"));
        assert!(formatted.contains("Top-level keys: "));
        assert!(formatted.contains("Alice"));
    }

    #[test]
    fn test_format_structured_data_array() {
        let loader = JsonYamlDocumentLoader::new();

        let data = serde_json::json!([
            {"name": "Alice", "age": 30},
            {"name": "Bob", "age": 35}
        ]);

        let formatted = loader.format_structured_data(&data, "json");
        assert!(formatted.contains("Document Format: JSON"));
        assert!(formatted.contains("Type: Array"));
        assert!(formatted.contains("Length: 2"));
        assert!(formatted.contains("First element type: Object"));
        assert!(formatted.contains("Alice"));
    }

    #[test]
    fn test_format_structured_data_string() {
        let loader = JsonYamlDocumentLoader::new();

        let data = serde_json::json!("Hello World");

        let formatted = loader.format_structured_data(&data, "yaml");
        assert!(formatted.contains("Document Format: YAML"));
        assert!(formatted.contains("Type: String"));
        assert!(formatted.contains("Hello World"));
    }

    #[tokio::test]
    async fn test_json_loader_with_temp_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.json");

        let json_content = r#"{
    "users": [
        {"name": "Alice", "age": 28, "department": "Engineering"},
        {"name": "Bob", "age": 35, "department": "Marketing"}
    ],
    "total": 2
}"#;
        let mut file = File::create(&file_path).unwrap();
        file.write_all(json_content.as_bytes()).unwrap();

        let loader = JsonYamlDocumentLoader::new();
        let params = serde_json::json!({
            "file_path": file_path.to_string_lossy(),
            "format": "json"
        });

        let result = loader.invoke(&params.to_string()).await;
        assert!(result.is_ok());

        if let Ok(ToolResult::StructuredJson(response)) = result {
            let doc: DocumentContent = serde_json::from_value(response).unwrap();
            assert!(doc.text.contains("Document Format: JSON"));
            assert!(doc.text.contains("Type: Object"));
            assert!(doc.text.contains("Alice"));
            assert!(doc.text.contains("Bob"));
            assert_eq!(doc.metadata.content_type, "application/json");
            assert_eq!(doc.source, "json_yaml_loader");
        }
    }

    #[tokio::test]
    async fn test_yaml_loader_with_temp_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.yaml");

        let yaml_content = r#"
config:
  name: "RustChain Test"
  version: "1.0.0"
  features:
    - llm
    - tools
    - rag
users:
  - name: Alice
    role: admin
    active: true
  - name: Bob  
    role: user
    active: false
"#;
        let mut file = File::create(&file_path).unwrap();
        file.write_all(yaml_content.as_bytes()).unwrap();

        let loader = JsonYamlDocumentLoader::new();
        let params = serde_json::json!({
            "file_path": file_path.to_string_lossy()
            // No format specified - should auto-detect from .yaml extension
        });

        let result = loader.invoke(&params.to_string()).await;
        assert!(result.is_ok());

        if let Ok(ToolResult::StructuredJson(response)) = result {
            let doc: DocumentContent = serde_json::from_value(response).unwrap();
            assert!(doc.text.contains("Document Format: YAML"));
            assert!(doc.text.contains("Type: Object"));
            assert!(doc.text.contains("RustChain Test"));
            assert!(doc.text.contains("Alice"));
            assert!(doc.text.contains("admin"));
            assert_eq!(doc.metadata.content_type, "application/yaml");
            assert_eq!(doc.source, "json_yaml_loader");
        }
    }

    #[tokio::test]
    async fn test_json_loader_auto_detect() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("auto.json");

        let json_content = r#"{"message": "Auto-detection test", "success": true}"#;
        let mut file = File::create(&file_path).unwrap();
        file.write_all(json_content.as_bytes()).unwrap();

        let loader = JsonYamlDocumentLoader::new();
        let params = serde_json::json!({
            "file_path": file_path.to_string_lossy()
            // No format - should auto-detect from .json extension
        });

        let result = loader.invoke(&params.to_string()).await;
        assert!(result.is_ok());

        if let Ok(ToolResult::StructuredJson(response)) = result {
            let doc: DocumentContent = serde_json::from_value(response).unwrap();
            assert!(doc.text.contains("Document Format: JSON"));
            assert!(doc.text.contains("Auto-detection test"));
            assert_eq!(doc.metadata.content_type, "application/json");
        }
    }

    #[tokio::test]
    async fn test_json_yaml_loader_invalid_file() {
        let loader = JsonYamlDocumentLoader::new();
        let result = loader
            .invoke(r#"{"file_path": "/nonexistent/file.json"}"#)
            .await;

        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("does not exist"));
    }

    #[tokio::test]
    async fn test_json_yaml_loader_unsupported_extension() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"some text content").unwrap();

        let loader = JsonYamlDocumentLoader::new();
        let params = serde_json::json!({
            "file_path": file_path.to_string_lossy()
        });

        let result = loader.invoke(&params.to_string()).await;
        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("Cannot auto-detect format"));
    }

    #[tokio::test]
    async fn test_json_yaml_loader_format_override() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("data.txt"); // Wrong extension

        let json_content = r#"{"override": "test", "format": "json"}"#;
        let mut file = File::create(&file_path).unwrap();
        file.write_all(json_content.as_bytes()).unwrap();

        let loader = JsonYamlDocumentLoader::new();
        let params = serde_json::json!({
            "file_path": file_path.to_string_lossy(),
            "format": "json" // Override auto-detection
        });

        let result = loader.invoke(&params.to_string()).await;
        assert!(result.is_ok());

        if let Ok(ToolResult::StructuredJson(response)) = result {
            let doc: DocumentContent = serde_json::from_value(response).unwrap();
            assert!(doc.text.contains("Document Format: JSON"));
            assert!(doc.text.contains("override"));
            assert_eq!(doc.metadata.content_type, "application/json");
        }
    }

    // HTML Loader Tests
    #[test]
    fn test_html_loader_name() {
        let loader = HtmlDocumentLoader::new();
        assert_eq!(loader.name(), "html_loader");
    }

    #[test]
    fn test_html_loader_capabilities() {
        let loader = HtmlDocumentLoader::new();
        let capabilities = loader.capabilities();
        assert!(capabilities.contains(&ToolCapability::Basic));
        assert!(capabilities.contains(&ToolCapability::SystemAccess));
    }

    #[test]
    fn test_html_load_params_serialization() {
        let params = HtmlLoadParams {
            file_path: "/path/to/page.html".to_string(),
            extract_mode: Some("all".to_string()),
        };

        let json = serde_json::to_string(&params).unwrap();
        let deserialized: HtmlLoadParams = serde_json::from_str(&json).unwrap();

        assert_eq!(params.file_path, deserialized.file_path);
        assert_eq!(params.extract_mode, deserialized.extract_mode);
    }

    #[test]
    fn test_html_text_extraction() {
        let loader = HtmlDocumentLoader::new();

        let html_content = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
    <script>console.log("should be ignored");</script>
    <style>body { color: red; }</style>
</head>
<body>
    <h1>Main Heading</h1>
    <p>This is a paragraph with <strong>bold text</strong>.</p>
    <ul>
        <li>List item 1</li>
        <li>List item 2</li>
    </ul>
</body>
</html>
        "#;

        let result = loader.parse_html(html_content, "text");
        assert!(result.is_ok());

        let extracted_text = result.unwrap();
        assert!(extracted_text.contains("Main Heading"));
        assert!(extracted_text.contains("This is a paragraph"));
        assert!(extracted_text.contains("bold text"));
        assert!(extracted_text.contains("List item 1"));
        assert!(extracted_text.contains("List item 2"));
        // Should not contain script or style content
        assert!(!extracted_text.contains("console.log"));
        assert!(!extracted_text.contains("color: red"));
    }

    #[test]
    fn test_html_structure_analysis() {
        let loader = HtmlDocumentLoader::new();

        let html_content = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Structure Test</title>
</head>
<body>
    <h1>Main Title</h1>
    <h2>Section 1</h2>
    <p>First paragraph</p>
    <p>Second paragraph</p>
    <h2>Section 2</h2>
    <ul>
        <li>Item 1</li>
        <li>Item 2</li>
        <li>Item 3</li>
    </ul>
    <a href="http://example.com">External Link</a>
    <img src="image.jpg" alt="Test Image">
    <div>
        <span>Nested content</span>
    </div>
</body>
</html>
        "#;

        let result = loader.parse_html(html_content, "structure");
        assert!(result.is_ok());

        let structure = result.unwrap();
        assert!(structure.contains("HTML Structure Analysis:"));
        assert!(structure.contains("Headings (h1): 1"));
        assert!(structure.contains("Headings (h2): 2"));
        assert!(structure.contains("Paragraphs: 2"));
        assert!(structure.contains("List Items: 3"));
        assert!(structure.contains("Links: 1"));
        assert!(structure.contains("Images: 1"));
        assert!(structure.contains("Page Title: Structure Test"));
        assert!(structure.contains("H1: Main Title"));
        assert!(structure.contains("H2: Section 1, Section 2"));
    }

    #[test]
    fn test_html_links_extraction() {
        let loader = HtmlDocumentLoader::new();

        let html_content = "<html><body><a href=\"https://example.com\">Example Website</a><a href=\"/internal/page\">Internal Page</a><a href=\"mailto:test@example.com\">Email Link</a><a href=\"#section1\">Anchor Link</a><a href=\"http://blank.com\"></a><span>Not a link</span></body></html>";

        let result = loader.parse_html(html_content, "links");
        assert!(result.is_ok());

        let links = result.unwrap();
        assert!(links.contains("Extracted Links:"));
        assert!(links.contains("Example Website → https://example.com"));
        assert!(links.contains("Internal Page → /internal/page"));
        assert!(links.contains("Email Link → mailto:test@example.com"));
        assert!(links.contains("Anchor Link → #section1"));
        assert!(links.contains("(no text)")); // Empty href should be captured
        assert!(!links.contains("Not a link")); // Should not include non-links
    }

    #[test]
    fn test_html_metadata_extraction() {
        let loader = HtmlDocumentLoader::new();

        let html_content = r#"
<!DOCTYPE html>
<html lang="en-US">
<head>
    <title>Metadata Test Page</title>
    <meta name="description" content="A test page for metadata extraction">
    <meta name="keywords" content="test, html, metadata">
    <meta name="author" content="Test Author">
    <meta property="og:title" content="Open Graph Title">
    <meta http-equiv="content-type" content="text/html; charset=utf-8">
</head>
<body>
    <h1>Content</h1>
</body>
</html>
        "#;

        let result = loader.parse_html(html_content, "metadata");
        assert!(result.is_ok());

        let metadata = result.unwrap();
        assert!(metadata.contains("HTML Metadata:"));
        assert!(metadata.contains("description: A test page for metadata extraction"));
        assert!(metadata.contains("keywords: test, html, metadata"));
        assert!(metadata.contains("author: Test Author"));
        assert!(metadata.contains("og:title: Open Graph Title"));
        assert!(metadata.contains("content-type: text/html; charset=utf-8"));
        assert!(metadata.contains("Title: Metadata Test Page"));
        assert!(metadata.contains("Language: en-US"));
    }

    #[test]
    fn test_html_all_extraction_mode() {
        let loader = HtmlDocumentLoader::new();

        let html_content = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Complete Test</title>
    <meta name="description" content="Complete test page">
</head>
<body>
    <h1>Main Content</h1>
    <p>Some text content</p>
    <a href="http://example.com">Test Link</a>
</body>
</html>
        "#;

        let result = loader.parse_html(html_content, "all");
        assert!(result.is_ok());

        let all_content = result.unwrap();
        assert!(all_content.contains("=== HTML DOCUMENT ANALYSIS ==="));
        assert!(all_content.contains("=== STRUCTURAL ANALYSIS ==="));
        assert!(all_content.contains("=== EXTRACTED LINKS ==="));
        assert!(all_content.contains("=== PAGE METADATA ==="));
        assert!(all_content.contains("Main Content"));
        assert!(all_content.contains("Test Link → http://example.com"));
        assert!(all_content.contains("description: Complete test page"));
    }

    #[test]
    fn test_html_invalid_extract_mode() {
        let loader = HtmlDocumentLoader::new();

        let html_content = "<html><body>Test</body></html>";
        let result = loader.parse_html(html_content, "invalid_mode");

        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("Unsupported extract mode"));
    }

    #[tokio::test]
    async fn test_html_loader_with_temp_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.html");

        let html_content = "<!DOCTYPE html>
<html lang=\"en\">
<head>
    <title>Test HTML Document</title>
    <meta name=\"description\" content=\"A test HTML document for RustChain\">
    <meta name=\"keywords\" content=\"rust, html, parsing, test\">
</head>
<body>
    <header>
        <h1>Welcome to RustChain HTML Loader</h1>
        <nav>
            <a href=\"#about\">About</a>
            <a href=\"#features\">Features</a>
            <a href=\"https://github.com/rustchain/rustchain\">GitHub</a>
        </nav>
    </header>
    
    <main>
        <section id=\"about\">
            <h2>About RustChain</h2>
            <p>RustChain is an AI agent framework built in Rust.</p>
            <p>It provides document processing capabilities.</p>
        </section>
        
        <section id=\"features\">
            <h2>Key Features</h2>
            <ul>
                <li>High performance document parsing</li>
                <li>Multiple format support</li>
                <li>Extensible architecture</li>
            </ul>
        </section>
    </main>
    
    <footer>
        <p>© 2025 RustChain Project</p>
    </footer>
</body>
</html>";

        let mut file = File::create(&file_path).unwrap();
        file.write_all(html_content.as_bytes()).unwrap();

        let loader = HtmlDocumentLoader::new();
        let params = serde_json::json!({
            "file_path": file_path.to_string_lossy(),
            "extract_mode": "text"
        });

        let result = loader.invoke(&params.to_string()).await;
        assert!(result.is_ok());

        if let Ok(ToolResult::StructuredJson(response)) = result {
            let doc: DocumentContent = serde_json::from_value(response).unwrap();
            assert!(doc.text.contains("Welcome to RustChain HTML Loader"));
            assert!(doc.text.contains("About RustChain"));
            assert!(doc.text.contains("AI agent framework"));
            assert!(doc.text.contains("High performance document parsing"));
            assert!(!doc.text.contains("DOCTYPE")); // Should not contain HTML markup
            assert_eq!(doc.metadata.content_type, "text/html");
            assert_eq!(doc.source, "html_loader");
        }
    }

    #[tokio::test]
    async fn test_html_loader_structure_mode() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("structure.html");

        let html_content = "<html><head><title>Structure Analysis Test</title></head><body><h1>Main Title</h1><h2>Section A</h2><h2>Section B</h2><h3>Subsection B.1</h3><p>Paragraph 1</p><p>Paragraph 2</p><p>Paragraph 3</p><ul><li>Item 1</li><li>Item 2</li></ul><ol><li>Ordered Item 1</li></ol><table><tr><td>Cell</td></tr></table><form><input type=\"text\"></form><img src=\"test.jpg\" alt=\"Test\"><a href=\"#\">Link</a></body></html>";

        let mut file = File::create(&file_path).unwrap();
        file.write_all(html_content.as_bytes()).unwrap();

        let loader = HtmlDocumentLoader::new();
        let params = serde_json::json!({
            "file_path": file_path.to_string_lossy(),
            "extract_mode": "structure"
        });

        let result = loader.invoke(&params.to_string()).await;
        assert!(result.is_ok());

        if let Ok(ToolResult::StructuredJson(response)) = result {
            let doc: DocumentContent = serde_json::from_value(response).unwrap();
            assert!(doc.text.contains("HTML Structure Analysis:"));
            assert!(doc.text.contains("Headings (h1): 1"));
            assert!(doc.text.contains("Headings (h2): 2"));
            assert!(doc.text.contains("Headings (h3): 1"));
            assert!(doc.text.contains("Paragraphs: 3"));
            assert!(doc.text.contains("Lists: 2"));
            assert!(doc.text.contains("List Items: 3"));
            assert!(doc.text.contains("Tables: 1"));
            assert!(doc.text.contains("Forms: 1"));
            assert!(doc.text.contains("Images: 1"));
            assert!(doc.text.contains("Links: 1"));
            assert!(doc.text.contains("Page Title: Structure Analysis Test"));
        }
    }

    #[tokio::test]
    async fn test_html_loader_invalid_file() {
        let loader = HtmlDocumentLoader::new();
        let result = loader
            .invoke(r#"{"file_path": "/nonexistent/file.html"}"#)
            .await;

        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("does not exist"));
    }

    #[tokio::test]
    async fn test_html_loader_non_html_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let html_content = "<html><body>HTML content in txt file</body></html>";
        let mut file = File::create(&file_path).unwrap();
        file.write_all(html_content.as_bytes()).unwrap();

        let loader = HtmlDocumentLoader::new();
        let params = serde_json::json!({
            "file_path": file_path.to_string_lossy(),
            "extract_mode": "text"
        });

        let result = loader.invoke(&params.to_string()).await;
        assert!(result.is_ok());

        if let Ok(ToolResult::StructuredJson(response)) = result {
            let doc: DocumentContent = serde_json::from_value(response).unwrap();
            assert!(doc.text.contains("HTML content in txt file"));
            assert_eq!(doc.metadata.content_type, "text/plain"); // Should be text/plain for .txt files
            assert_eq!(doc.source, "html_loader");
        }
    }

    #[tokio::test]
    async fn test_html_loader_all_mode() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("complete.html");

        let html_content = "<html><head><title>Complete HTML Test</title><meta name=\"description\" content=\"Complete test for all extraction modes\"></head><body><h1>Main Title</h1><p>Content paragraph with <a href=\"https://example.com\">external link</a>.</p></body></html>";

        let mut file = File::create(&file_path).unwrap();
        file.write_all(html_content.as_bytes()).unwrap();

        let loader = HtmlDocumentLoader::new();
        let params = serde_json::json!({
            "file_path": file_path.to_string_lossy(),
            "extract_mode": "all"
        });

        let result = loader.invoke(&params.to_string()).await;
        assert!(result.is_ok());

        if let Ok(ToolResult::StructuredJson(response)) = result {
            let doc: DocumentContent = serde_json::from_value(response).unwrap();

            // Check that all sections are present
            assert!(doc.text.contains("=== HTML DOCUMENT ANALYSIS ==="));
            assert!(doc.text.contains("=== STRUCTURAL ANALYSIS ==="));
            assert!(doc.text.contains("=== EXTRACTED LINKS ==="));
            assert!(doc.text.contains("=== PAGE METADATA ==="));

            // Check content from each section
            assert!(doc.text.contains("Main Title")); // Text extraction
            assert!(doc.text.contains("HTML Structure Analysis:")); // Structure
            assert!(doc.text.contains("external link")); // Links
            assert!(doc.text.contains("description: Complete test")); // Metadata

            assert_eq!(doc.metadata.content_type, "text/html");
            assert_eq!(doc.source, "html_loader");
        }
    }
}
