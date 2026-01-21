use rustchain::engine::{sanitize_command, sanitize_file_path};

#[test]
fn test_security_fixes() {
    // Test that path traversal is blocked
    assert!(sanitize_file_path("../etc/passwd").is_err());
    assert!(sanitize_file_path("../../../windows/system32").is_err());

    // Test that valid paths work
    assert!(sanitize_file_path("valid_file.txt").is_ok());
    assert!(sanitize_file_path("subdir/valid_file.txt").is_ok());

    // Test that allowed commands now work (previously blocked by dangerous_patterns)
    assert!(sanitize_command("cat", &[]).is_ok());
    assert!(sanitize_command("grep", &["pattern", "file.txt"]).is_ok());
    assert!(sanitize_command("curl", &["https://example.com"]).is_ok());

    // Test that truly dangerous patterns are still blocked
    assert!(sanitize_command("rm -rf /", &[]).is_err());
    assert!(sanitize_command("echo", &["$(rm -rf /)"]).is_err());
}
