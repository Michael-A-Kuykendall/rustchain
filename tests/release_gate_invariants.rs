use std::fs;

/// Release gate invariants - lightweight validation tests
/// These verify release-critical properties WITHOUT spawning cargo processes
#[cfg(test)]
mod release_gate_tests {
    use super::*;

    /// Version in Cargo.toml must be valid semver
    #[test]
    fn test_version_is_valid_semver() {
        let cargo_toml = fs::read_to_string("Cargo.toml").expect("Cargo.toml must exist");
        let version = extract_cargo_version(&cargo_toml);

        assert!(!version.is_empty(), "Version must not be empty");

        let parts: Vec<&str> = version.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "Version must have 3 parts (major.minor.patch)"
        );

        for part in parts {
            assert!(part.parse::<u32>().is_ok(), "Version parts must be numeric");
        }
    }

    /// Required files must exist for packaging
    #[test]
    fn test_required_files_exist() {
        let required = [
            "Cargo.toml",
            "src/lib.rs",
            "src/main.rs",
            "README.md",
            "LICENSE-MIT",
            "LICENSE-APACHE",
        ];

        for file in required {
            assert!(
                std::path::Path::new(file).exists(),
                "Required file missing: {}",
                file
            );
        }
    }

    /// Cargo.toml must have required metadata
    #[test]
    fn test_cargo_metadata_complete() {
        let cargo_toml = fs::read_to_string("Cargo.toml").expect("Cargo.toml must exist");

        assert!(cargo_toml.contains("name = "), "Package name required");
        assert!(
            cargo_toml.contains("version = "),
            "Package version required"
        );
        assert!(cargo_toml.contains("edition = "), "Edition required");
        assert!(cargo_toml.contains("license"), "License required");
        assert!(cargo_toml.contains("description"), "Description required");
    }

    /// No placeholder text in critical files
    #[test]
    fn test_no_placeholder_text() {
        let files_to_check = ["README.md", "Cargo.toml"];
        let placeholders = ["TODO:", "FIXME:", "XXX:", "PLACEHOLDER"];

        for file in files_to_check {
            if let Ok(content) = fs::read_to_string(file) {
                for placeholder in placeholders {
                    assert!(
                        !content.contains(placeholder),
                        "Found '{}' in {}",
                        placeholder,
                        file
                    );
                }
            }
        }
    }

    fn extract_cargo_version(cargo_toml: &str) -> String {
        for line in cargo_toml.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("version = ") {
                return trimmed.split('"').nth(1).unwrap_or("").to_string();
            }
        }
        String::new()
    }
}
