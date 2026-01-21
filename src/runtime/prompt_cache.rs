use crate::core::error::RustChainError;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

pub fn hash_prompt(prompt: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    prompt.hash(&mut hasher);
    hasher.finish()
}

pub fn cache_lookup(prompt: &str) -> Option<String> {
    let key = hash_prompt(prompt);
    let path = PathBuf::from(format!("cache/prompts/{}.txt", key));
    fs::read_to_string(path).ok()
}

pub fn cache_store(prompt: &str, result: &str) -> Result<(), RustChainError> {
    let key = hash_prompt(prompt);
    let path = PathBuf::from("cache/prompts");
    fs::create_dir_all(&path)?;
    fs::write(path.join(format!("{}.txt", key)), result)?;
    Ok(())
}
