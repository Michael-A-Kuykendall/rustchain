#[cfg(test)]
mod memory_tests {
    use crate::core::memory::MemoryStore;
    use crate::core::{ConversationMemory, InMemoryStore};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_in_memory_store_basic_operations() {
        let mut store = InMemoryStore::with_ttl(60); // 60 second TTL

        // Test store and retrieve
        assert!(store.store("key1", "value1").is_ok());
        assert_eq!(store.retrieve("key1").unwrap(), Some("value1".to_string()));

        // Test non-existent key
        assert_eq!(store.retrieve("nonexistent").unwrap(), None);

        // Test overwrite
        assert!(store.store("key1", "new_value").is_ok());
        assert_eq!(
            store.retrieve("key1").unwrap(),
            Some("new_value".to_string())
        );
    }

    #[test]
    fn test_in_memory_store_ttl() {
        let mut store = InMemoryStore::with_ttl(1); // 1 second TTL

        store.store("key1", "value1").unwrap();
        assert_eq!(store.retrieve("key1").unwrap(), Some("value1".to_string()));

        // Wait for expiry
        thread::sleep(Duration::from_secs(2));
        assert_eq!(store.retrieve("key1").unwrap(), None);
    }

    #[test]
    fn test_in_memory_store_cleanup() {
        let mut store = InMemoryStore::with_ttl(1); // 1 second TTL

        store.store("key1", "value1").unwrap();
        store.store("key2", "value2").unwrap();

        // Wait for expiry
        thread::sleep(Duration::from_secs(2));

        // Cleanup should remove expired entries
        assert!(store.cleanup().is_ok());

        // Both keys should be gone after cleanup
        assert_eq!(store.retrieve("key1").unwrap(), None);
        assert_eq!(store.retrieve("key2").unwrap(), None);
    }

    #[test]
    fn test_in_memory_store_list_keys() {
        let mut store = InMemoryStore::with_ttl(60);

        store.store("key1", "value1").unwrap();
        store.store("key2", "value2").unwrap();
        store.store("key3", "value3").unwrap();

        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
        assert!(keys.contains(&"key3".to_string()));
    }

    #[test]
    fn test_in_memory_store_clear() {
        let mut store = InMemoryStore::with_ttl(60);

        store.store("key1", "value1").unwrap();
        store.store("key2", "value2").unwrap();

        assert_eq!(store.list_keys().unwrap().len(), 2);

        assert!(store.clear().is_ok());
        assert_eq!(store.list_keys().unwrap().len(), 0);
    }

    #[test]
    fn test_in_memory_store_summarize() {
        let mut store = InMemoryStore::with_ttl(60);

        store.store("key1", "short").unwrap();
        store.store("key2", "longer value").unwrap();

        let summary = store.summarize().unwrap();
        assert!(summary.contains("2 entries"));
    }

    #[test]
    fn test_conversation_memory_operations() {
        let mut memory = ConversationMemory::new(100); // Max 100 entries

        memory.add_message("user", "Hello").unwrap();
        memory.add_message("assistant", "Hi there!").unwrap();

        let conversation = memory.get_conversation().unwrap();
        assert_eq!(conversation.len(), 2);
        assert!(conversation.contains(&"user: Hello".to_string()));
        assert!(conversation.contains(&"assistant: Hi there!".to_string()));
    }

    #[test]
    fn test_conversation_memory_capacity_limit() {
        let mut memory = ConversationMemory::new(2); // Max 2 entries

        memory.add_message("user", "Message 1").unwrap();
        memory.add_message("assistant", "Response 1").unwrap();
        memory.add_message("user", "Message 2").unwrap(); // Should evict oldest

        let conversation = memory.get_conversation().unwrap();
        assert_eq!(conversation.len(), 2);
        assert!(!conversation.iter().any(|s| s.contains("Message 1"))); // Should be evicted
        assert!(conversation.iter().any(|s| s.contains("Response 1")));
        assert!(conversation.iter().any(|s| s.contains("Message 2")));
    }

    #[test]
    fn test_conversation_memory_clear() {
        let mut memory = ConversationMemory::new(100);

        memory.add_message("user", "Hello").unwrap();
        memory.add_message("assistant", "Hi").unwrap();

        assert_eq!(memory.get_conversation().unwrap().len(), 2);

        memory.clear().unwrap();
        assert_eq!(memory.get_conversation().unwrap().len(), 0);
    }

    #[test]
    fn test_conversation_memory_get_recent() {
        let mut memory = ConversationMemory::new(100);

        for i in 1..=10 {
            memory
                .add_message("user", &format!("Message {}", i))
                .unwrap();
        }

        let recent = memory.get_recent(3).unwrap();
        assert_eq!(recent.len(), 3);
        assert!(recent.iter().any(|s| s.contains("Message 8")));
        assert!(recent.iter().any(|s| s.contains("Message 9")));
        assert!(recent.iter().any(|s| s.contains("Message 10")));
    }

    #[test]
    fn test_conversation_memory_search() {
        let mut memory = ConversationMemory::new(100);

        memory.add_message("user", "Tell me about cats").unwrap();
        memory
            .add_message("assistant", "Cats are wonderful pets")
            .unwrap();
        memory.add_message("user", "What about dogs?").unwrap();
        memory
            .add_message("assistant", "Dogs are loyal companions")
            .unwrap();

        let results = memory.search("cats").unwrap();
        assert_eq!(results.len(), 2); // Should find both messages about cats

        let results = memory.search("dogs").unwrap();
        assert_eq!(results.len(), 2); // Should find both messages about dogs

        let results = memory.search("birds").unwrap();
        assert_eq!(results.len(), 0); // Should find no messages about birds
    }

    #[test]
    fn test_conversation_memory_summarize() {
        let mut memory = ConversationMemory::new(100);

        memory.add_message("user", "Hello").unwrap();
        memory.add_message("assistant", "Hi there!").unwrap();

        let summary = memory.summarize().unwrap();
        assert!(summary.contains("2 messages"));
        assert!(summary.contains("Conversation"));
    }

    // Additional tests for coverage

    #[test]
    fn test_in_memory_store_constructors() {
        // Test default constructor
        let store1 = InMemoryStore::new();
        let stats1 = store1.stats();
        assert_eq!(stats1.total_entries, 0);
        assert_eq!(stats1.default_ttl, None);
        assert_eq!(stats1.max_entries, None);

        // Test with_ttl constructor
        let store2 = InMemoryStore::with_ttl(3600);
        let stats2 = store2.stats();
        assert_eq!(stats2.default_ttl, Some(3600));
        assert_eq!(stats2.max_entries, None);

        // Test with_capacity constructor
        let store3 = InMemoryStore::with_capacity(100);
        let stats3 = store3.stats();
        assert_eq!(stats3.default_ttl, None);
        assert_eq!(stats3.max_entries, Some(100));

        // Test with_ttl_and_capacity constructor
        let store4 = InMemoryStore::with_ttl_and_capacity(1800, 50);
        let stats4 = store4.stats();
        assert_eq!(stats4.default_ttl, Some(1800));
        assert_eq!(stats4.max_entries, Some(50));
    }

    #[test]
    fn test_in_memory_store_capacity_management() {
        let mut store = InMemoryStore::with_capacity(3);

        // Fill to capacity
        assert!(store.store("key1", "value1").is_ok());
        assert!(store.store("key2", "value2").is_ok());
        assert!(store.store("key3", "value3").is_ok());

        // Adding one more should evict oldest
        assert!(store.store("key4", "value4").is_ok());

        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 3);
        assert!(!keys.contains(&"key1".to_string())); // Should be evicted
        assert!(keys.contains(&"key4".to_string())); // Should be present
    }

    #[test]
    fn test_in_memory_store_stats() {
        let mut store = InMemoryStore::with_ttl_and_capacity(3600, 100);

        store.store("key1", "short").unwrap();
        store.store("key2", "a much longer value").unwrap();

        let stats = store.stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.active_entries, 2);
        assert_eq!(stats.expired_entries, 0);
        assert_eq!(
            stats.total_size_bytes,
            "short".len() + "a much longer value".len()
        );
        assert_eq!(stats.max_entries, Some(100));
        assert_eq!(stats.default_ttl, Some(3600));
    }

    #[test]
    fn test_in_memory_store_stats_with_expired() {
        let mut store = InMemoryStore::with_ttl(1); // 1 second TTL

        store.store("active_key", "active_value").unwrap();
        store.store("expiring_key", "expiring_value").unwrap();

        // Wait for one key to expire
        thread::sleep(Duration::from_secs(2));

        let stats = store.stats();
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.active_entries, 0); // Both should be expired
        assert_eq!(stats.expired_entries, 2);
    }

    #[test]
    fn test_in_memory_store_contains_key() {
        let mut store = InMemoryStore::with_ttl(60);

        // Test non-existent key
        assert!(!store.contains_key("nonexistent"));

        // Store key and test
        store.store("existing_key", "value").unwrap();
        assert!(store.contains_key("existing_key"));

        // Test with expired key
        let mut expired_store = InMemoryStore::with_ttl(1);
        expired_store.store("expiring_key", "value").unwrap();
        thread::sleep(Duration::from_secs(2));
        assert!(!expired_store.contains_key("expiring_key"));
    }

    #[test]
    fn test_in_memory_store_list_keys_filters_expired() {
        let mut store = InMemoryStore::with_ttl(1); // 1 second TTL

        store.store("key1", "value1").unwrap();
        store.store("key2", "value2").unwrap();

        // Initially all keys present
        assert_eq!(store.list_keys().unwrap().len(), 2);

        // Wait for expiry
        thread::sleep(Duration::from_secs(2));

        // list_keys should filter out expired entries
        assert_eq!(store.list_keys().unwrap().len(), 0);
    }

    #[test]
    fn test_in_memory_store_retrieve_expired() {
        let mut store = InMemoryStore::with_ttl(1); // 1 second TTL

        store.store("key", "value").unwrap();

        // Should retrieve while still valid
        assert_eq!(store.retrieve("key").unwrap(), Some("value".to_string()));

        // Wait for expiry
        thread::sleep(Duration::from_secs(2));

        // Should return None for expired key
        assert_eq!(store.retrieve("key").unwrap(), None);
    }

    #[test]
    fn test_in_memory_store_cleanup_with_mixed_expiry() {
        let mut store = InMemoryStore::with_ttl(2); // 2 second TTL

        store.store("key1", "value1").unwrap();
        thread::sleep(Duration::from_secs(1));
        store.store("key2", "value2").unwrap(); // This won't expire as quickly

        thread::sleep(Duration::from_secs(2)); // key1 should expire, key2 may still be valid

        let keys_before = store.list_keys().unwrap();
        store.cleanup().unwrap();
        let keys_after = store.list_keys().unwrap();

        // Should clean up expired entries
        assert!(keys_before.len() >= keys_after.len());
    }

    #[test]
    fn test_in_memory_store_ensure_capacity_cleanup_first() {
        let mut store = InMemoryStore::with_ttl_and_capacity(1, 2); // 1 second TTL, 2 entry limit

        store.store("key1", "value1").unwrap();
        store.store("key2", "value2").unwrap();

        // Wait for expiry
        thread::sleep(Duration::from_secs(2));

        // Adding new entry should cleanup first, then add
        store.store("key3", "value3").unwrap();

        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&"key3".to_string()));
    }

    #[test]
    fn test_memory_entry_creation_and_expiry() {
        use crate::core::memory::MemoryEntry;

        // Test entry without TTL
        let entry_no_ttl = MemoryEntry::new("test_value".to_string(), None);
        assert!(!entry_no_ttl.is_expired());
        assert_eq!(entry_no_ttl.value, "test_value");
        assert!(entry_no_ttl.expires_at.is_none());

        // Test entry with TTL
        let entry_with_ttl = MemoryEntry::new("test_value".to_string(), Some(1));
        assert!(!entry_with_ttl.is_expired()); // Should not be expired immediately
        assert!(entry_with_ttl.expires_at.is_some());

        thread::sleep(Duration::from_secs(2));
        assert!(entry_with_ttl.is_expired()); // Should be expired after waiting
    }

    #[test]
    fn test_memory_entry_serialization() {
        use crate::core::memory::MemoryEntry;

        let entry = MemoryEntry::new("serializable_value".to_string(), Some(3600));

        // Test serialization
        let serialized = serde_json::to_string(&entry).unwrap();
        assert!(serialized.contains("serializable_value"));

        // Test deserialization
        let deserialized: MemoryEntry = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.value, "serializable_value");
        assert_eq!(deserialized.expires_at, entry.expires_at);
    }

    #[test]
    fn test_conversation_message_creation() {
        use crate::core::memory::ConversationMessage;

        let message = ConversationMessage::new("user", "Hello world");
        assert_eq!(message.role, "user");
        assert_eq!(message.content, "Hello world");
        assert!(message.timestamp > 0);
    }

    #[test]
    fn test_conversation_message_serialization() {
        use crate::core::memory::ConversationMessage;

        let message = ConversationMessage::new("assistant", "Hello there!");

        // Test serialization
        let serialized = serde_json::to_string(&message).unwrap();
        assert!(serialized.contains("assistant"));
        assert!(serialized.contains("Hello there!"));

        // Test deserialization
        let deserialized: ConversationMessage = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.role, "assistant");
        assert_eq!(deserialized.content, "Hello there!");
    }

    #[test]
    fn test_conversation_memory_stats() {
        let mut memory = ConversationMemory::new(100);

        memory.add_message("user", "First message").unwrap();
        memory.add_message("assistant", "Response").unwrap();
        memory.add_message("user", "Second message").unwrap();

        let stats = memory.stats();
        assert_eq!(stats.total_messages, 3);
        assert_eq!(stats.max_capacity, 100);
        assert_eq!(stats.role_counts.get("user"), Some(&2));
        assert_eq!(stats.role_counts.get("assistant"), Some(&1));
        assert!(stats.total_characters > 0);
    }

    #[test]
    fn test_conversation_memory_stats_serialization() {
        let mut memory = ConversationMemory::new(50);
        memory.add_message("system", "System message").unwrap();

        let stats = memory.stats();

        // Test serialization
        let serialized = serde_json::to_string(&stats).unwrap();
        assert!(serialized.contains("total_messages"));

        // Test deserialization
        let deserialized: crate::core::memory::ConversationStats =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.total_messages, 1);
        assert_eq!(deserialized.max_capacity, 50);
    }

    #[test]
    fn test_memory_stats_serialization() {
        let store = InMemoryStore::with_ttl_and_capacity(7200, 200);
        let stats = store.stats();

        // Test serialization
        let serialized = serde_json::to_string(&stats).unwrap();
        assert!(serialized.contains("total_entries"));
        assert!(serialized.contains("7200"));
        assert!(serialized.contains("200"));

        // Test deserialization
        let deserialized: crate::core::memory::MemoryStats =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.total_entries, 0);
        assert_eq!(deserialized.default_ttl, Some(7200));
        assert_eq!(deserialized.max_entries, Some(200));
    }

    #[test]
    fn test_conversation_memory_get_recent_edge_cases() {
        let mut memory = ConversationMemory::new(5);

        // Test with empty conversation
        let recent = memory.get_recent(3).unwrap();
        assert_eq!(recent.len(), 0);

        // Add fewer messages than requested
        memory.add_message("user", "Only message").unwrap();
        let recent = memory.get_recent(5).unwrap();
        assert_eq!(recent.len(), 1);
        assert!(recent[0].contains("Only message"));

        // Test with exactly the number requested
        memory.add_message("assistant", "Second message").unwrap();
        memory.add_message("user", "Third message").unwrap();
        let recent = memory.get_recent(3).unwrap();
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn test_conversation_memory_search_case_insensitive() {
        let mut memory = ConversationMemory::new(100);

        memory.add_message("user", "I love CATS").unwrap();
        memory.add_message("assistant", "Cats are great").unwrap();

        let results = memory.search("cats").unwrap(); // lowercase search
        assert_eq!(results.len(), 2);

        let results = memory.search("LOVE").unwrap(); // uppercase search
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_conversation_memory_search_role_matching() {
        let mut memory = ConversationMemory::new(100);

        memory.add_message("user", "Hello").unwrap();
        memory.add_message("assistant", "Hi").unwrap();

        let results = memory.search("user").unwrap(); // Search for role
        assert_eq!(results.len(), 1);
        assert!(results[0].contains("user: Hello"));

        let results = memory.search("assistant").unwrap(); // Search for role
        assert_eq!(results.len(), 1);
        assert!(results[0].contains("assistant: Hi"));
    }

    #[test]
    fn test_conversation_memory_summarize_multiple_participants() {
        let mut memory = ConversationMemory::new(100);

        memory.add_message("user", "Hello").unwrap();
        memory.add_message("assistant", "Hi").unwrap();
        memory.add_message("system", "Status update").unwrap();
        memory.add_message("user", "Another message").unwrap();

        let summary = memory.summarize().unwrap();
        assert!(summary.contains("4 messages"));
        assert!(summary.contains("3 participants")); // user, assistant, system
    }

    #[test]
    fn test_edge_case_empty_values() {
        let mut store = InMemoryStore::new();

        // Test storing empty string
        store.store("empty_key", "").unwrap();
        assert_eq!(store.retrieve("empty_key").unwrap(), Some("".to_string()));

        // Test empty key handling
        store.store("", "empty_key_value").unwrap();
        assert_eq!(
            store.retrieve("").unwrap(),
            Some("empty_key_value".to_string())
        );

        let mut memory = ConversationMemory::new(10);

        // Test empty role and content
        memory.add_message("", "").unwrap();
        let conversation = memory.get_conversation().unwrap();
        assert_eq!(conversation.len(), 1);
        assert_eq!(conversation[0], ": ");
    }

    #[test]
    fn test_large_capacity_conversation_memory() {
        let mut memory = ConversationMemory::new(1000);

        // Add many messages
        for i in 0..500 {
            memory
                .add_message("user", &format!("Message {}", i))
                .unwrap();
        }

        assert_eq!(memory.get_conversation().unwrap().len(), 500);

        let stats = memory.stats();
        assert_eq!(stats.total_messages, 500);
        assert_eq!(stats.max_capacity, 1000);
    }

    #[test]
    fn test_zero_capacity_conversation_memory() {
        let mut memory = ConversationMemory::new(0);

        // Adding to zero capacity should still work but immediately evict
        memory.add_message("user", "This will be evicted").unwrap();
        assert_eq!(memory.get_conversation().unwrap().len(), 0);
    }

    #[test]
    fn test_single_capacity_conversation_memory() {
        let mut memory = ConversationMemory::new(1);

        memory.add_message("user", "First").unwrap();
        assert_eq!(memory.get_conversation().unwrap().len(), 1);

        memory.add_message("assistant", "Second").unwrap(); // Should evict first
        let conversation = memory.get_conversation().unwrap();
        assert_eq!(conversation.len(), 1);
        assert!(conversation[0].contains("Second"));
        assert!(!conversation[0].contains("First"));
    }

    #[test]
    fn test_memory_trait_object() {
        let mut store: Box<dyn MemoryStore> = Box::new(InMemoryStore::new());

        store.store("trait_key", "trait_value").unwrap();
        assert_eq!(
            store.retrieve("trait_key").unwrap(),
            Some("trait_value".to_string())
        );

        let keys = store.list_keys().unwrap();
        assert!(keys.contains(&"trait_key".to_string()));
    }

    #[test]
    fn test_memory_store_ttl_boundary_conditions() {
        let mut store = InMemoryStore::with_ttl(1);

        store.store("boundary_key", "boundary_value").unwrap();
        assert_eq!(
            store.retrieve("boundary_key").unwrap(),
            Some("boundary_value".to_string())
        );

        thread::sleep(Duration::from_millis(1100));
        assert_eq!(store.retrieve("boundary_key").unwrap(), None);
    }

    #[test]
    fn test_memory_store_capacity_lru_eviction() {
        let mut store = InMemoryStore::with_capacity(2);

        store.store("oldest", "1").unwrap();
        store.store("middle", "2").unwrap();
        store.store("newest", "3").unwrap();

        assert_eq!(store.retrieve("oldest").unwrap(), None);
        assert_eq!(store.retrieve("middle").unwrap(), Some("2".to_string()));
        assert_eq!(store.retrieve("newest").unwrap(), Some("3".to_string()));
    }
}
