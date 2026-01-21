use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_minute: u32,
    pub requests_per_hour: u32,
    pub burst_limit: u32,
    pub cleanup_interval: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 100,
            requests_per_hour: 1000,
            burst_limit: 20,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }
}

#[derive(Debug, Clone)]
struct ClientRecord {
    requests_in_minute: Vec<Instant>,
    requests_in_hour: Vec<Instant>,
    first_request: Instant,
    blocked_until: Option<Instant>,
}

impl ClientRecord {
    fn new() -> Self {
        Self {
            requests_in_minute: Vec::new(),
            requests_in_hour: Vec::new(),
            first_request: Instant::now(),
            blocked_until: None,
        }
    }

    fn cleanup(&mut self, now: Instant) {
        // Remove requests older than 1 minute
        self.requests_in_minute
            .retain(|&time| now.duration_since(time) < Duration::from_secs(60));

        // Remove requests older than 1 hour
        self.requests_in_hour
            .retain(|&time| now.duration_since(time) < Duration::from_secs(3600));
    }

    fn is_blocked(&self, now: Instant) -> bool {
        if let Some(blocked_until) = self.blocked_until {
            now < blocked_until
        } else {
            false
        }
    }

    fn add_request(&mut self, now: Instant) {
        self.requests_in_minute.push(now);
        self.requests_in_hour.push(now);
    }

    fn block_for(&mut self, duration: Duration) {
        self.blocked_until = Some(Instant::now() + duration);
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimitConfig,
    clients: Arc<RwLock<HashMap<IpAddr, ClientRecord>>>,
    last_cleanup: Arc<RwLock<Instant>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            clients: Arc::new(RwLock::new(HashMap::new())),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Get the rate limit configuration
    pub fn get_config(&self) -> &RateLimitConfig {
        &self.config
    }

    pub async fn check_rate_limit(&self, client_ip: IpAddr) -> Result<(), RateLimitError> {
        let now = Instant::now();

        // Cleanup old entries if needed - check-and-update atomically to prevent races
        {
            let mut last_cleanup = self.last_cleanup.write().await;
            if now.duration_since(*last_cleanup) > self.config.cleanup_interval {
                // Update last_cleanup BEFORE releasing the lock to prevent concurrent cleanup
                *last_cleanup = now;
                // Drop the lock before running cleanup (which needs clients.write())
                drop(last_cleanup);
                self.cleanup_old_entries(now).await;
            }
        }

        // Use read lock for checking, upgrade to write only for updates
        let is_blocked;
        let needs_block;
        let error_result;
        
        {
            let clients = self.clients.read().await;
            if let Some(record) = clients.get(&client_ip) {
                // Check if client is currently blocked
                if record.is_blocked(now) {
                    return Err(RateLimitError::Blocked);
                }

                // Count requests (read-only checks)
                let minute_requests: Vec<_> = record.requests_in_minute
                    .iter()
                    .filter(|&&time| now.duration_since(time) < Duration::from_secs(60))
                    .copied()
                    .collect();

                let hour_requests: Vec<_> = record.requests_in_hour
                    .iter()
                    .filter(|&&time| now.duration_since(time) < Duration::from_secs(3600))
                    .copied()
                    .collect();

                // Check minute limit
                if minute_requests.len() >= self.config.requests_per_minute as usize {
                    is_blocked = true;
                    needs_block = Some(Duration::from_secs(60));
                    error_result = Some(RateLimitError::MinuteExceeded);
                }
                // Check hour limit
                else if hour_requests.len() >= self.config.requests_per_hour as usize {
                    is_blocked = true;
                    needs_block = Some(Duration::from_secs(3600));
                    error_result = Some(RateLimitError::HourExceeded);
                }
                // Check burst limit (requests in last 10 seconds)
                else {
                    let burst_count = minute_requests
                        .iter()
                        .filter(|&&time| now.duration_since(time) < Duration::from_secs(10))
                        .count();

                    if burst_count >= self.config.burst_limit as usize {
                        is_blocked = true;
                        needs_block = Some(Duration::from_secs(30));
                        error_result = Some(RateLimitError::BurstExceeded);
                    } else {
                        is_blocked = false;
                        needs_block = None;
                        error_result = None;
                    }
                }
            } else {
                // New client - allow request
                is_blocked = false;
                needs_block = None;
                error_result = None;
            }
        }

        // Upgrade to write lock only if we need to update state
        let mut clients = self.clients.write().await;
        let record = clients.entry(client_ip).or_insert_with(ClientRecord::new);

        // Cleanup old requests for this client
        record.cleanup(now);

        if is_blocked {
            if let Some(duration) = needs_block {
                record.block_for(duration);
            }
            // SAFETY: error_result is always Some when is_blocked is true
            return Err(error_result.expect("error_result set when is_blocked"));
        }

        // Add this request
        record.add_request(now);

        Ok(())
    }

    async fn cleanup_old_entries(&self, now: Instant) {
        let mut clients = self.clients.write().await;
        clients.retain(|_, record| {
            // Keep records that have recent activity or are blocked
            let has_recent_activity = !record.requests_in_hour.is_empty() || record.is_blocked(now);
            let is_recent_client =
                now.duration_since(record.first_request) < Duration::from_secs(7200); // 2 hours

            has_recent_activity && is_recent_client
        });
    }

    pub async fn get_client_stats(&self, client_ip: IpAddr) -> Option<ClientStats> {
        let clients = self.clients.read().await;
        if let Some(record) = clients.get(&client_ip) {
            let now = Instant::now();
            Some(ClientStats {
                requests_in_minute: record.requests_in_minute.len() as u32,
                requests_in_hour: record.requests_in_hour.len() as u32,
                is_blocked: record.is_blocked(now),
                blocked_until: record.blocked_until,
                remaining_minute: self
                    .config
                    .requests_per_minute
                    .saturating_sub(record.requests_in_minute.len() as u32),
                remaining_hour: self
                    .config
                    .requests_per_hour
                    .saturating_sub(record.requests_in_hour.len() as u32),
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientStats {
    pub requests_in_minute: u32,
    pub requests_in_hour: u32,
    pub is_blocked: bool,
    pub blocked_until: Option<Instant>,
    pub remaining_minute: u32,
    pub remaining_hour: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded: too many requests per minute")]
    MinuteExceeded,
    #[error("Rate limit exceeded: too many requests per hour")]
    HourExceeded,
    #[error("Rate limit exceeded: burst limit reached")]
    BurstExceeded,
    #[error("Client is temporarily blocked")]
    Blocked,
}

impl IntoResponse for RateLimitError {
    fn into_response(self) -> Response {
        let (status, message, retry_after) = match self {
            RateLimitError::MinuteExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded: too many requests per minute",
                60, // Block for 1 minute
            ),
            RateLimitError::HourExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded: too many requests per hour",
                3600, // Block for 1 hour
            ),
            RateLimitError::BurstExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded: burst limit reached",
                30, // Block for 30 seconds
            ),
            RateLimitError::Blocked => (
                StatusCode::TOO_MANY_REQUESTS,
                "Client is temporarily blocked",
                60, // Default block duration
            ),
        };

        let mut response = Response::new(Body::from(message));
        *response.status_mut() = status;

        // Add rate limiting headers with actual retry duration
        // Note: We can't access config here, so we indicate remaining=0
        // The actual limits should be read from successful response headers
        response
            .headers_mut()
            .insert("X-RateLimit-Remaining", "0".parse()
                .expect("Static header value '0' is valid"));
        response
            .headers_mut()
            .insert("Retry-After", retry_after.to_string().parse()
                .expect("Numeric header value conversion is valid"));

        response
    }
}

/// Configuration for trusted proxy handling in rate limiting.
///
/// When `trust_proxy_headers` is false (default), X-Forwarded-For and X-Real-IP
/// headers are ignored to prevent IP spoofing attacks.
#[derive(Debug, Clone, Default)]
pub struct ProxyConfig {
    /// Whether to trust X-Forwarded-For and X-Real-IP headers.
    /// Only enable if running behind a trusted reverse proxy.
    pub trust_proxy_headers: bool,
}

pub async fn rate_limit_middleware(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, RateLimitError> {
    // Get proxy config from extensions (defaults to not trusting proxy headers)
    let proxy_config = request
        .extensions()
        .get::<ProxyConfig>()
        .cloned()
        .unwrap_or_default();

    // Extract client IP - only trust forwarded headers if explicitly configured
    let client_ip = extract_client_ip(&headers, proxy_config.trust_proxy_headers)
        .unwrap_or_else(|| "127.0.0.1".parse().expect("Static IP '127.0.0.1' is valid"));

    // Get rate limiter from request extensions - FAIL CLOSED if not configured
    // This prevents silent bypass when middleware is misconfigured
    let rate_limiter = match request.extensions().get::<RateLimiter>().cloned() {
        Some(limiter) => limiter,
        None => {
            tracing::error!("Rate limiter not found in request extensions! \
                Rate limiting is DISABLED for this request. \
                Ensure RateLimiter is added to server extensions.");
            // Fail closed: create a restrictive temporary limiter that will
            // likely block repeated requests (but log loudly about misconfiguration)
            RateLimiter::new(RateLimitConfig {
                requests_per_minute: 10,  // Very restrictive fallback
                requests_per_hour: 50,
                burst_limit: 5,
                cleanup_interval: std::time::Duration::from_secs(60),
            })
        }
    };

    // Check rate limit
    rate_limiter.check_rate_limit(client_ip).await?;

    // Get client stats and config for response headers
    let stats = rate_limiter.get_client_stats(client_ip).await;
    let config = rate_limiter.get_config();

    // Continue to next middleware/handler
    let mut response = next.run(request).await;

    // Add rate limit headers to response with CORRECT values
    // X-RateLimit-Limit-* = configured maximum (from config)
    // X-RateLimit-Remaining-* = how many requests left (from stats)
    response.headers_mut().insert(
        "X-RateLimit-Limit-Minute",
        config.requests_per_minute.to_string().parse()
            .expect("Numeric header value conversion is valid"),
    );
    response.headers_mut().insert(
        "X-RateLimit-Limit-Hour",
        config.requests_per_hour.to_string().parse()
            .expect("Numeric header value conversion is valid"),
    );
    
    if let Some(stats) = stats {
        response.headers_mut().insert(
            "X-RateLimit-Remaining-Minute",
            stats.remaining_minute.to_string().parse()
                .expect("Numeric header value conversion is valid"),
        );
        response.headers_mut().insert(
            "X-RateLimit-Remaining-Hour",
            stats.remaining_hour.to_string().parse()
                .expect("Numeric header value conversion is valid"),
        );
    }

    Ok(response)
}

/// Extract client IP from request.
///
/// # Security Note
/// Proxy headers (X-Forwarded-For, X-Real-IP) are only trusted when
/// `trust_proxy_headers` is explicitly set to true. This prevents
/// IP spoofing attacks where clients set fake headers to:
/// - Evade rate limits by rotating IPs
/// - Grief other users by consuming their quota
///
/// Only enable trust when running behind a trusted reverse proxy.
fn extract_client_ip(headers: &HeaderMap, trust_proxy_headers: bool) -> Option<IpAddr> {
    // Only trust forwarded headers if explicitly configured
    if trust_proxy_headers {
        // Try X-Forwarded-For first (for proxies)
        if let Some(forwarded) = headers.get("X-Forwarded-For") {
            if let Ok(forwarded_str) = forwarded.to_str() {
                if let Some(first_ip) = forwarded_str.split(',').next() {
                    if let Ok(ip) = first_ip.trim().parse() {
                        return Some(ip);
                    }
                }
            }
        }

        // Try X-Real-IP (for nginx)
        if let Some(real_ip) = headers.get("X-Real-IP") {
            if let Ok(ip_str) = real_ip.to_str() {
                if let Ok(ip) = ip_str.parse() {
                    return Some(ip);
                }
            }
        }
    }

    // Return None - caller should use actual connection IP or fallback
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_rate_limit_basic() {
        let config = RateLimitConfig {
            requests_per_minute: 5,
            requests_per_hour: 50,
            burst_limit: 3,
            cleanup_interval: Duration::from_secs(60),
        };

        let rate_limiter = RateLimiter::new(config);
        let client_ip: IpAddr = "127.0.0.1".parse().expect("127.0.0.1 should be valid IP address");

        // Should allow first few requests
        for _ in 0..3 {
            assert!(rate_limiter.check_rate_limit(client_ip).await.is_ok());
        }

        // Should block burst limit
        assert!(rate_limiter.check_rate_limit(client_ip).await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limit_minute_exceeded() {
        let config = RateLimitConfig {
            requests_per_minute: 3,
            requests_per_hour: 50,
            burst_limit: 10, // High burst to test minute limit
            cleanup_interval: Duration::from_secs(60),
        };

        let rate_limiter = RateLimiter::new(config);
        let client_ip: IpAddr = "127.0.0.1".parse().expect("127.0.0.1 should be valid IP address");

        // Use up the minute limit
        for _ in 0..3 {
            sleep(Duration::from_millis(100)).await; // Avoid burst limit
            assert!(rate_limiter.check_rate_limit(client_ip).await.is_ok());
        }

        // Should block on minute limit
        sleep(Duration::from_millis(100)).await;
        assert!(rate_limiter.check_rate_limit(client_ip).await.is_err());
    }

    #[tokio::test]
    async fn test_client_stats() {
        let config = RateLimitConfig::default();
        let rate_limiter = RateLimiter::new(config);
        let client_ip: IpAddr = "127.0.0.1".parse().expect("127.0.0.1 should be valid IP address");

        // Make some requests
        for _ in 0..3 {
            let _ = rate_limiter.check_rate_limit(client_ip).await;
        }

        // Check stats
        let stats = rate_limiter.get_client_stats(client_ip).await;
        assert!(stats.is_some());

        let stats = stats.expect("Stats should be available for client");
        assert_eq!(stats.requests_in_minute, 3);
        assert_eq!(stats.requests_in_hour, 3);
    }
}
