use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Performance metrics collector for RustChain operations
#[derive(Debug, Clone)]
pub struct PerformanceMonitor {
    mission_times: Arc<AtomicU64>,
    tool_times: Arc<AtomicU64>,
    llm_times: Arc<AtomicU64>,
    memory_operations: Arc<AtomicU64>,
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        Self {
            mission_times: Arc::new(AtomicU64::new(0)),
            tool_times: Arc::new(AtomicU64::new(0)),
            llm_times: Arc::new(AtomicU64::new(0)),
            memory_operations: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_mission_time(&self, duration: Duration) {
        self.mission_times
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn record_tool_time(&self, duration: Duration) {
        self.tool_times
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn record_llm_time(&self, duration: Duration) {
        self.llm_times
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn record_memory_operation(&self) {
        self.memory_operations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> PerformanceStats {
        PerformanceStats {
            total_mission_time_ms: self.mission_times.load(Ordering::Relaxed),
            total_tool_time_ms: self.tool_times.load(Ordering::Relaxed),
            total_llm_time_ms: self.llm_times.load(Ordering::Relaxed),
            memory_operations_count: self.memory_operations.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStats {
    pub total_mission_time_ms: u64,
    pub total_tool_time_ms: u64,
    pub total_llm_time_ms: u64,
    pub memory_operations_count: u64,
}

/// Timer for measuring operation performance
pub struct Timer {
    start: Instant,
    name: String,
}

impl Timer {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            start: Instant::now(),
            name: name.into(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn finish(self) -> Duration {
        let duration = self.elapsed();
        tracing::debug!(
            "Operation '{}' completed in {}ms",
            self.name,
            duration.as_millis()
        );
        duration
    }
}

/// Macro for easy performance timing
#[macro_export]
macro_rules! time_operation {
    ($name:expr, $block:block) => {{
        let timer = $crate::performance::Timer::new($name);
        let result = $block;
        timer.finish();
        result
    }};
}

/// Performance optimization configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    pub enable_async_batching: bool,
    pub batch_size: usize,
    pub timeout_ms: u64,
    pub max_concurrent_operations: usize,
    pub enable_caching: bool,
    pub cache_ttl_seconds: u64,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enable_async_batching: true,
            batch_size: 10,
            timeout_ms: 5000,
            max_concurrent_operations: 100,
            enable_caching: true,
            cache_ttl_seconds: 300,
        }
    }
}

/// Batch processor for high-throughput operations
pub struct BatchProcessor<T> {
    config: PerformanceConfig,
    batch: Vec<T>,
}

impl<T> BatchProcessor<T> {
    pub fn new(config: PerformanceConfig) -> Self {
        let batch_size = config.batch_size;
        Self {
            config,
            batch: Vec::with_capacity(batch_size),
        }
    }

    pub fn add(&mut self, item: T) -> bool {
        self.batch.push(item);
        self.batch.len() >= self.config.batch_size
    }

    pub fn flush(&mut self) -> Vec<T> {
        std::mem::take(&mut self.batch)
    }

    pub fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }

    pub fn len(&self) -> usize {
        self.batch.len()
    }
}

/// Connection pool for database and HTTP connections
pub struct ConnectionPool<T> {
    connections: Vec<T>,
    max_size: usize,
    current_size: usize,
}

impl<T> ConnectionPool<T> {
    pub fn new(max_size: usize) -> Self {
        Self {
            connections: Vec::with_capacity(max_size),
            max_size,
            current_size: 0,
        }
    }

    pub fn get(&mut self) -> Option<T> {
        self.connections.pop()
    }

    pub fn return_connection(&mut self, conn: T) {
        if self.current_size < self.max_size {
            self.connections.push(conn);
        }
        // If at capacity, drop the connection
    }

    pub fn size(&self) -> usize {
        self.current_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_performance_monitor() {
        let monitor = PerformanceMonitor::new();

        monitor.record_mission_time(Duration::from_millis(100));
        monitor.record_tool_time(Duration::from_millis(50));
        monitor.record_llm_time(Duration::from_millis(200));
        monitor.record_memory_operation();

        let stats = monitor.get_stats();
        assert_eq!(stats.total_mission_time_ms, 100);
        assert_eq!(stats.total_tool_time_ms, 50);
        assert_eq!(stats.total_llm_time_ms, 200);
        assert_eq!(stats.memory_operations_count, 1);
    }

    #[test]
    fn test_timer() {
        let timer = Timer::new("test_operation");
        thread::sleep(Duration::from_millis(10));
        let elapsed = timer.finish();
        assert!(elapsed >= Duration::from_millis(10));
    }

    #[test]
    fn test_batch_processor() {
        let config = PerformanceConfig {
            batch_size: 3,
            ..Default::default()
        };
        let mut processor = BatchProcessor::new(config);

        assert!(!processor.add("item1"));
        assert!(!processor.add("item2"));
        assert!(processor.add("item3")); // Should trigger batch full

        let batch = processor.flush();
        assert_eq!(batch.len(), 3);
        assert!(processor.is_empty());
    }

    #[test]
    fn test_connection_pool() {
        let mut pool = ConnectionPool::new(2);

        // Pool starts empty
        assert_eq!(pool.size(), 0);
        assert!(pool.get().is_none());

        // Add connections
        pool.return_connection("conn1");
        pool.return_connection("conn2");

        // Get connections
        assert!(pool.get().is_some());
        assert!(pool.get().is_some());
        assert!(pool.get().is_none()); // Empty again
    }
}
