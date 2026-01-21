use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Resolves mission file paths with smart shortcuts and discovery
pub struct PathResolver {
    workspace_root: PathBuf,
    mission_dirs: Vec<PathBuf>,
    aliases: HashMap<String, PathBuf>,
}

impl PathResolver {
    pub fn new() -> Result<Self> {
        let workspace_root = find_workspace_root()?;
        let mission_dirs = vec![
            workspace_root.join("examples"),
            workspace_root.join("missions"),
            workspace_root.join("mission-stacks-current"),
            workspace_root.join("mission-stacks-done"),
            workspace_root.join("docs/mission-stacks/current/new"),
        ];

        let mut resolver = Self {
            workspace_root,
            mission_dirs,
            aliases: HashMap::new(),
        };

        resolver.discover_missions()?;
        resolver.setup_aliases();

        Ok(resolver)
    }

    /// Resolve a mission path from various input formats
    pub fn resolve_mission_path(&self, input: &str) -> Result<PathBuf> {
        // 1. Check aliases first
        if let Some(path) = self.aliases.get(input) {
            return Ok(path.clone());
        }

        // 2. Try as absolute path
        if Path::new(input).is_absolute() && Path::new(input).exists() {
            return Ok(PathBuf::from(input));
        }

        // 3. Try relative to current directory
        if Path::new(input).exists() {
            return Ok(std::env::current_dir()?.join(input).canonicalize()?);
        }

        // 4. Try mission shorthand (just filename)
        if !input.contains('/') && !input.contains('\\') {
            for dir in &self.mission_dirs {
                for ext in &["yaml", "yml", "json"] {
                    let path = dir.join(format!("{}.{}", input, ext));
                    if path.exists() {
                        return Ok(path);
                    }
                }
            }
        }

        // 5. Try partial path search
        for dir in &self.mission_dirs {
            let path = dir.join(input);
            if path.exists() {
                return Ok(path);
            }
        }

        // 6. Fuzzy search for similar names
        let suggestions = self.find_similar_missions(input);
        if !suggestions.is_empty() {
            let suggestion_text = suggestions
                .iter()
                .take(3)
                .map(|s| format!("  - {}", s))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(anyhow!(
                "Mission file not found: {}\n\nDid you mean:\n{}",
                input,
                suggestion_text
            ));
        }

        Err(anyhow!("Mission file not found: {}", input))
    }

    /// List all available missions
    pub fn list_missions(&self) -> Vec<MissionInfo> {
        let mut missions = Vec::new();

        for dir in &self.mission_dirs {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(ext) = path.extension() {
                        if matches!(ext.to_str(), Some("yaml" | "yml" | "json")) {
                            let relative_path = path
                                .strip_prefix(&self.workspace_root)
                                .unwrap_or(&path)
                                .to_path_buf();

                            let info = MissionInfo {
                                name: path
                                    .file_stem()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string(),
                                path: relative_path.clone(),
                                full_path: path.clone(),
                                directory: dir
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string(),
                                aliases: self.get_aliases_for_path(&path),
                            };
                            missions.push(info);
                        }
                    }
                }
            }
        }

        missions.sort_by(|a, b| a.name.cmp(&b.name));
        missions
    }

    /// Get aliases that point to a specific path
    pub fn get_aliases_for_path(&self, path: &Path) -> Vec<String> {
        self.aliases
            .iter()
            .filter_map(|(alias, alias_path)| {
                if alias_path == path {
                    Some(alias.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Find missions with similar names (fuzzy matching)
    fn find_similar_missions(&self, input: &str) -> Vec<String> {
        let input_lower = input.to_lowercase();
        let mut suggestions = Vec::new();

        // Check aliases
        for alias in self.aliases.keys() {
            if alias.to_lowercase().contains(&input_lower) {
                suggestions.push(alias.clone());
            }
        }

        // Check mission files
        for mission in self.list_missions() {
            if mission.name.to_lowercase().contains(&input_lower) {
                suggestions.push(mission.name);
            }
        }

        suggestions.sort();
        suggestions.dedup();
        suggestions
    }

    /// Discover missions and build shortcuts
    fn discover_missions(&mut self) -> Result<()> {
        for dir in &self.mission_dirs.clone() {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(stem) = path.file_stem() {
                        let name = stem.to_string_lossy().to_string();
                        // Don't override existing aliases
                        if !self.aliases.contains_key(&name) {
                            self.aliases.insert(name, path);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Setup common aliases
    fn setup_aliases(&mut self) {
        let common_aliases = vec![
            ("demo", "examples/working_demo.yaml"),
            ("test", "examples/test_mission.yaml"),
            ("hello", "examples/hello_world.yaml"),
            ("ai-analysis", "ai-development-analysis.yaml"),
        ];

        for (alias, path) in common_aliases {
            // Try to find the actual file
            for dir in &self.mission_dirs {
                let full_path = dir.join(path);
                if full_path.exists() {
                    self.aliases.insert(alias.to_string(), full_path);
                    break;
                }
            }
        }
    }
}

/// Information about a discovered mission
#[derive(Debug, Clone)]
pub struct MissionInfo {
    pub name: String,
    pub path: PathBuf,
    pub full_path: PathBuf,
    pub directory: String,
    pub aliases: Vec<String>,
}

/// Find the workspace root by looking for Cargo.toml
fn find_workspace_root() -> Result<PathBuf> {
    let mut current = std::env::current_dir()?;

    loop {
        if current.join("Cargo.toml").exists() {
            return Ok(current);
        }

        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            break;
        }
    }

    // Fallback to current directory
    Ok(std::env::current_dir()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_path_resolution() {
        let temp_dir = TempDir::new().unwrap();
        let examples_dir = temp_dir.path().join("examples");
        std::fs::create_dir_all(&examples_dir).unwrap();

        let demo_file = examples_dir.join("demo.yaml");
        std::fs::write(&demo_file, "# Demo mission").unwrap();

        // This would need more setup for a full test
        // but demonstrates the testing approach
    }
}
