//! Centralized HTTP client with timeouts and bounded response handling.
//!
//! This module provides a factory for creating reqwest clients with proper
//! timeout configuration, and helpers for reading response bodies with
//! size limits to prevent memory exhaustion.

use crate::core::error::RustChainError;
use futures::StreamExt;
use reqwest::{Client, Response};
use std::time::Duration;

/// Default timeout for HTTP requests (30 seconds)
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Default connect timeout (10 seconds)
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;

/// Maximum error body size to read (64KB)
pub const MAX_ERROR_BODY_SIZE: usize = 64 * 1024;

/// Maximum response body size for general reads (10MB)
pub const MAX_RESPONSE_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Create an HTTP client with standard timeout configuration.
///
/// This is the only approved way to create reqwest clients in this codebase.
/// Direct use of `reqwest::Client::new()` is forbidden by pre-commit hooks.
///
/// # Arguments
/// * `timeout_secs` - Optional request timeout in seconds (defaults to 30)
///
/// # Returns
/// A configured `reqwest::Client` with:
/// - Request timeout
/// - Connect timeout
/// - Redirect policy (max 10 redirects)
///
/// # Panics
/// This function uses `.expect()` on client builder which should never fail
/// with valid static configuration. If it fails, it indicates a serious
/// environment issue (e.g., TLS backend unavailable).
pub fn create_http_client(timeout_secs: Option<u64>) -> Client {
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS));
    let connect_timeout = Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS);

    Client::builder()
        .timeout(timeout)
        .connect_timeout(connect_timeout)
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .expect("Failed to build HTTP client - check TLS backend availability")
}

/// Create an HTTP client, returning Result instead of panicking.
///
/// Use this variant when you need to handle client creation failures gracefully.
///
/// # Arguments
/// * `timeout_secs` - Optional request timeout in seconds (defaults to 30)
///
/// # Returns
/// `Ok(Client)` on success, or `Err(RustChainError)` if client creation fails.
pub fn try_create_http_client(timeout_secs: Option<u64>) -> Result<Client, RustChainError> {
    let timeout = Duration::from_secs(timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS));
    let connect_timeout = Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS);

    Client::builder()
        .timeout(timeout)
        .connect_timeout(connect_timeout)
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|e| {
            RustChainError::Config(crate::core::error::ConfigError::PluginError {
                message: format!("Failed to create HTTP client: {}", e),
            })
        })
}

/// Create an HTTP client with custom timeouts.
///
/// # Arguments
/// * `request_timeout_secs` - Request timeout in seconds
/// * `connect_timeout_secs` - Connect timeout in seconds
pub fn create_http_client_custom(request_timeout_secs: u64, connect_timeout_secs: u64) -> Client {
    Client::builder()
        .timeout(Duration::from_secs(request_timeout_secs))
        .connect_timeout(Duration::from_secs(connect_timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .expect("Failed to build HTTP client - check TLS backend availability")
}

/// Read response body with STREAMING size limit.
///
/// This function streams the response and stops reading once the limit
/// is reached, preventing memory exhaustion from large responses.
/// Unlike naive implementations that read the full body then truncate,
/// this truly bounds memory usage.
///
/// # Arguments
/// * `response` - The HTTP response to read
/// * `max_size` - Maximum bytes to read (defaults to MAX_RESPONSE_BODY_SIZE)
///
/// # Returns
/// The response body as a string, truncated if necessary with indicator
pub async fn read_response_body_bounded(
    response: Response,
    max_size: Option<usize>,
) -> Result<String, reqwest::Error> {
    let limit = max_size.unwrap_or(MAX_RESPONSE_BODY_SIZE);

    // Check Content-Length header first for early rejection
    if let Some(content_length) = response.content_length() {
        if content_length as usize > limit * 2 {
            // Very large response - don't even start streaming
            return Ok(format!(
                "[Response too large: {} bytes, limit {} bytes]",
                content_length, limit
            ));
        }
    }

    // Stream the response body with bounded accumulation
    let mut stream = response.bytes_stream();
    let mut buffer = Vec::with_capacity(limit.min(1024 * 1024)); // Cap initial alloc at 1MB
    let mut total_size: usize = 0;
    let mut was_truncated = false;

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result?;
        let remaining = limit.saturating_sub(buffer.len());

        if remaining == 0 {
            // Already at limit, just track total size for reporting
            total_size += chunk.len();
            was_truncated = true;
            continue;
        }

        if chunk.len() <= remaining {
            buffer.extend_from_slice(&chunk);
        } else {
            // Partial chunk to reach limit
            buffer.extend_from_slice(&chunk[..remaining]);
            total_size = buffer.len() + (chunk.len() - remaining);
            was_truncated = true;
        }
    }

    if !was_truncated {
        total_size = buffer.len();
    }

    let body = String::from_utf8_lossy(&buffer).into_owned();

    if was_truncated {
        Ok(format!(
            "{}... [truncated at {} bytes, total ~{} bytes]",
            body,
            limit,
            total_size + limit
        ))
    } else {
        Ok(body)
    }
}

/// Read error body with strict size limit.
///
/// For error responses, we use a smaller limit to prevent log bloat.
///
/// # Arguments
/// * `response` - The HTTP error response to read
///
/// # Returns
/// The error body as a string, truncated to MAX_ERROR_BODY_SIZE
pub async fn read_error_body_bounded(response: Response) -> String {
    match read_response_body_bounded(response, Some(MAX_ERROR_BODY_SIZE)).await {
        Ok(body) => body,
        Err(e) => format!("[Failed to read error body: {}]", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_http_client_default() {
        let client = create_http_client(None);
        // Client should be created successfully
        assert!(client.get("http://example.com").build().is_ok());
    }

    #[test]
    fn test_create_http_client_custom_timeout() {
        let client = create_http_client(Some(60));
        assert!(client.get("http://example.com").build().is_ok());
    }

    #[test]
    fn test_create_http_client_custom_timeouts() {
        let client = create_http_client_custom(120, 30);
        assert!(client.get("http://example.com").build().is_ok());
    }
}
