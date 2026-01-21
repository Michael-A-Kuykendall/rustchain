use crate::core::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

pub trait MemoryStore: Send + Sync {
    fn store(&mut self, key: &str, value: &str) -> Result<()>;
    fn retrieve(&self, key: &str) -> Result<Option<String>>;
    fn list_keys(&self) -> Result<Vec<String>>;
}

/// Enhanced memory entry with TTL support
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemoryEntry {
    value: String,
    created_at: u64,
    expires_at: Option<u64>,
}

impl MemoryEntry {
    fn new(value: String, ttl_seconds: Option<u64>) -> Self {
        let now_duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System clock set before UNIX epoch - time misconfigured");
        let now = now_duration.as_nanos() as u64;

        Self {
            value,
            created_at: now,
            expires_at: ttl_seconds.map(|ttl| now + (ttl * 1_000_000_000)), // Convert seconds to nanoseconds
        }
    }

    fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("System clock set before UNIX epoch - time misconfigured")
                .as_nanos() as u64;
            now > expires_at
        } else {
            false
        }
    }
}

/// Enhanced in-memory store with TTL, cleanup, and additional operations
#[derive(Default)]
pub struct InMemoryStore {
    data: HashMap<String, MemoryEntry>,
    default_ttl: Option<u64>,
    max_entries: Option<usize>,
}

impl InMemoryStore {
    /// Create a new in-memory store with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new in-memory store with TTL (overloaded for tests)
    pub fn with_ttl(ttl_seconds: u64) -> Self {
        Self {
            data: HashMap::new(),
            default_ttl: Some(ttl_seconds),
            max_entries: None,
        }
    }

    /// Create a new in-memory store with capacity limit
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            data: HashMap::new(),
            default_ttl: None,
            max_entries: Some(max_entries),
        }
    }

    /// Create a new in-memory store with both TTL and capacity limit
    pub fn with_ttl_and_capacity(ttl_seconds: u64, max_entries: usize) -> Self {
        Self {
            data: HashMap::new(),
            default_ttl: Some(ttl_seconds),
            max_entries: Some(max_entries),
        }
    }

    /// Clean up expired entries
    pub fn cleanup(&mut self) -> Result<()> {
        let expired_keys: Vec<String> = self
            .data
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_keys {
            self.data.remove(&key);
        }

        Ok(())
    }

    /// Clear all entries
    pub fn clear(&mut self) -> Result<()> {
        self.data.clear();
        Ok(())
    }

    /// Get summary of memory store
    pub fn summarize(&self) -> Result<String> {
        let total_entries = self.data.len();
        let expired_entries = self
            .data
            .values()
            .filter(|entry| entry.is_expired())
            .count();
        let active_entries = total_entries - expired_entries;

        let total_size: usize = self.data.values().map(|entry| entry.value.len()).sum();

        Ok(format!(
            "Memory Store Summary: {} entries ({} active, {} expired), {} bytes total",
            total_entries, active_entries, expired_entries, total_size
        ))
    }

    /// Check if an entry exists and is not expired
    pub fn contains_key(&self, key: &str) -> bool {
        if let Some(entry) = self.data.get(key) {
            !entry.is_expired()
        } else {
            false
        }
    }

    /// Get memory usage statistics
    pub fn stats(&self) -> MemoryStats {
        let total_entries = self.data.len();
        let expired_entries = self
            .data
            .values()
            .filter(|entry| entry.is_expired())
            .count();
        let total_size: usize = self.data.values().map(|entry| entry.value.len()).sum();

        MemoryStats {
            total_entries,
            active_entries: total_entries - expired_entries,
            expired_entries,
            total_size_bytes: total_size,
            max_entries: self.max_entries,
            default_ttl: self.default_ttl,
        }
    }

    fn ensure_capacity(&mut self) -> Result<()> {
        if let Some(max_entries) = self.max_entries {
            // First try cleanup to free space
            self.cleanup()?;

            // If would exceed capacity after adding new entry, make room by removing oldest
            while self.data.len() >= max_entries {
                if let Some(oldest_key) = self
                    .data
                    .iter()
                    .min_by_key(|(_, entry)| entry.created_at)
                    .map(|(key, _)| key.clone())
                {
                    self.data.remove(&oldest_key);
                } else {
                    break;
                }
            }
        }
        Ok(())
    }
}

impl MemoryStore for InMemoryStore {
    fn store(&mut self, key: &str, value: &str) -> Result<()> {
        // Ensure we don't exceed capacity
        self.ensure_capacity()?;

        let entry = MemoryEntry::new(value.to_string(), self.default_ttl);
        self.data.insert(key.to_string(), entry);
        Ok(())
    }

    fn retrieve(&self, key: &str) -> Result<Option<String>> {
        if let Some(entry) = self.data.get(key) {
            if entry.is_expired() {
                Ok(None)
            } else {
                Ok(Some(entry.value.clone()))
            }
        } else {
            Ok(None)
        }
    }

    fn list_keys(&self) -> Result<Vec<String>> {
        Ok(self
            .data
            .iter()
            .filter(|(_, entry)| !entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect())
    }
}

/// Memory usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    pub total_entries: usize,
    pub active_entries: usize,
    pub expired_entries: usize,
    pub total_size_bytes: usize,
    pub max_entries: Option<usize>,
    pub default_ttl: Option<u64>,
}

/// Conversation-specific memory for storing and managing chat history
#[derive(Debug, Clone)]
pub struct ConversationMemory {
    messages: VecDeque<ConversationMessage>,
    max_messages: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMessage {
    pub role: String,
    pub content: String,
    pub timestamp: u64,
}

impl ConversationMessage {
    fn new(role: &str, content: &str) -> Self {
        Self {
            role: role.to_string(),
            content: content.to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("System clock set before UNIX epoch - time misconfigured")
                .as_secs(),
        }
    }
}

impl ConversationMemory {
    /// Create a new conversation memory with specified capacity
    pub fn new(max_messages: usize) -> Self {
        Self {
            messages: VecDeque::new(),
            max_messages,
        }
    }

    /// Add a message to the conversation
    pub fn add_message(&mut self, role: &str, content: &str) -> Result<()> {
        // If max_messages is 0, don't store anything
        if self.max_messages == 0 {
            return Ok(());
        }

        let message = ConversationMessage::new(role, content);

        // Remove oldest message if at capacity
        if self.messages.len() >= self.max_messages {
            self.messages.pop_front();
        }

        self.messages.push_back(message);
        Ok(())
    }

    /// Get the entire conversation as formatted strings
    pub fn get_conversation(&self) -> Result<Vec<String>> {
        Ok(self
            .messages
            .iter()
            .map(|msg| format!("{}: {}", msg.role, msg.content))
            .collect())
    }

    /// Get the most recent N messages
    pub fn get_recent(&self, count: usize) -> Result<Vec<String>> {
        Ok(self
            .messages
            .iter()
            .rev()
            .take(count)
            .rev()
            .map(|msg| format!("{}: {}", msg.role, msg.content))
            .collect())
    }

    /// Search for messages containing a specific term
    pub fn search(&self, term: &str) -> Result<Vec<String>> {
        let term_lower = term.to_lowercase();
        Ok(self
            .messages
            .iter()
            .filter(|msg| {
                msg.content.to_lowercase().contains(&term_lower)
                    || msg.role.to_lowercase().contains(&term_lower)
            })
            .map(|msg| format!("{}: {}", msg.role, msg.content))
            .collect())
    }

    /// Clear all messages
    pub fn clear(&mut self) -> Result<()> {
        self.messages.clear();
        Ok(())
    }

    /// Get summary of the conversation
    pub fn summarize(&self) -> Result<String> {
        let total_messages = self.messages.len();
        let roles: std::collections::HashSet<String> =
            self.messages.iter().map(|msg| msg.role.clone()).collect();

        Ok(format!(
            "Conversation summary: {} messages from {} participants",
            total_messages,
            roles.len()
        ))
    }

    /// Get conversation statistics
    pub fn stats(&self) -> ConversationStats {
        let mut role_counts: HashMap<String, usize> = HashMap::new();
        let mut total_chars = 0;

        for msg in &self.messages {
            *role_counts.entry(msg.role.clone()).or_insert(0) += 1;
            total_chars += msg.content.len();
        }

        ConversationStats {
            total_messages: self.messages.len(),
            role_counts,
            total_characters: total_chars,
            max_capacity: self.max_messages,
        }
    }
}

/// Conversation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationStats {
    pub total_messages: usize,
    pub role_counts: HashMap<String, usize>,
    pub total_characters: usize,
    pub max_capacity: usize,
}

// Include the tests module
#[cfg(test)]
mod tests;
