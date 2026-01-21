use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Internal build dashboard for tracking RustChain system health
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildDashboard {
    pub last_updated: DateTime<Utc>,
    pub modules: HashMap<String, ModuleStatus>,
    pub overall_health: SystemHealth,
}

/// Status tracking for individual modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStatus {
    pub name: String,
    pub compilation_status: CompilationStatus,
    pub test_status: TestStatus,
    pub coverage_info: CoverageInfo,
    pub dependencies: Vec<String>,
    pub last_modified: DateTime<Utc>,
    pub issues: Vec<ModuleIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompilationStatus {
    Clean,
    Warnings(u32),
    Errors(u32),
    NotCompiled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestStatus {
    pub total_tests: u32,
    pub passed: u32,
    pub failed: u32,
    pub ignored: u32,
    pub last_run: DateTime<Utc>,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageInfo {
    pub lines_covered: u32,
    pub lines_total: u32,
    pub coverage_percentage: f64,
    pub critical_paths_covered: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleIssue {
    pub severity: IssueSeverity,
    pub description: String,
    pub component: String,
    pub detected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IssueSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHealth {
    pub build_passing: bool,
    pub all_tests_passing: bool,
    pub coverage_threshold_met: bool,
    pub no_critical_issues: bool,
    pub regression_tests_passing: bool,
    pub overall_score: f64, // 0.0 - 100.0
}

impl Default for BuildDashboard {
    fn default() -> Self {
        Self {
            last_updated: Utc::now(),
            modules: HashMap::new(),
            overall_health: SystemHealth::default(),
        }
    }
}

impl BuildDashboard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update module status from build/test results
    pub fn update_module(&mut self, module_name: &str, status: ModuleStatus) {
        self.modules.insert(module_name.to_string(), status);
        self.last_updated = Utc::now();
        self.calculate_overall_health();
    }

    /// Calculate overall system health based on module statuses
    pub fn calculate_overall_health(&mut self) {
        let total_modules = self.modules.len() as f64;
        if total_modules == 0.0 {
            self.overall_health = SystemHealth::default();
            return;
        }

        let build_passing = self.modules.values().all(|m| {
            matches!(
                m.compilation_status,
                CompilationStatus::Clean | CompilationStatus::Warnings(_)
            )
        });
        let all_tests_passing = self.modules.values().all(|m| m.test_status.failed == 0);
        let coverage_threshold_met = self
            .modules
            .values()
            .all(|m| m.coverage_info.coverage_percentage >= 80.0);
        let no_critical_issues = self.modules.values().all(|m| {
            !m.issues
                .iter()
                .any(|issue| matches!(issue.severity, IssueSeverity::Critical))
        });

        // Calculate overall score
        let mut score = 0.0;
        if build_passing {
            score += 25.0;
        }
        if all_tests_passing {
            score += 25.0;
        }
        if coverage_threshold_met {
            score += 25.0;
        }
        if no_critical_issues {
            score += 25.0;
        }

        self.overall_health = SystemHealth {
            build_passing,
            all_tests_passing,
            coverage_threshold_met,
            no_critical_issues,
            regression_tests_passing: all_tests_passing, // For now, assume regression tests are part of all tests
            overall_score: score,
        };
    }

    /// Get modules that need attention
    pub fn get_problematic_modules(&self) -> Vec<&ModuleStatus> {
        self.modules
            .values()
            .filter(|module| {
                matches!(module.compilation_status, CompilationStatus::Errors(_))
                    || module.test_status.failed > 0
                    || module.coverage_info.coverage_percentage < 80.0
                    || module.issues.iter().any(|issue| {
                        matches!(
                            issue.severity,
                            IssueSeverity::Critical | IssueSeverity::High
                        )
                    })
            })
            .collect()
    }

    /// Generate a simple text dashboard
    pub fn generate_dashboard(&self) -> String {
        let mut dashboard = String::new();

        dashboard.push_str("🏗️ RUSTCHAIN BUILD DASHBOARD\n");
        dashboard.push_str("============================\n\n");

        // Overall health
        dashboard.push_str(&format!(
            "Overall Health Score: {:.1}%\n",
            self.overall_health.overall_score
        ));
        dashboard.push_str(&format!(
            "Build Status: {}\n",
            if self.overall_health.build_passing {
                "✅ PASSING"
            } else {
                "❌ FAILING"
            }
        ));
        dashboard.push_str(&format!(
            "Tests Status: {}\n",
            if self.overall_health.all_tests_passing {
                "✅ ALL PASSING"
            } else {
                "❌ SOME FAILING"
            }
        ));
        dashboard.push_str(&format!(
            "Coverage: {}\n",
            if self.overall_health.coverage_threshold_met {
                "✅ ABOVE THRESHOLD"
            } else {
                "⚠️ BELOW THRESHOLD"
            }
        ));
        dashboard.push_str(&format!(
            "Issues: {}\n\n",
            if self.overall_health.no_critical_issues {
                "✅ NO CRITICAL ISSUES"
            } else {
                "❌ CRITICAL ISSUES PRESENT"
            }
        ));

        // Module summary
        dashboard.push_str("📊 MODULE SUMMARY\n");
        dashboard.push_str("-----------------\n");

        let mut modules: Vec<_> = self.modules.values().collect();
        modules.sort_by(|a, b| a.name.cmp(&b.name));

        for module in modules {
            let status_icon = match module.compilation_status {
                CompilationStatus::Clean => "✅",
                CompilationStatus::Warnings(_) => "⚠️",
                CompilationStatus::Errors(_) => "❌",
                CompilationStatus::NotCompiled => "⏸️",
            };

            let test_ratio = if module.test_status.total_tests > 0 {
                format!(
                    "{}/{}",
                    module.test_status.passed, module.test_status.total_tests
                )
            } else {
                "0/0".to_string()
            };

            dashboard.push_str(&format!(
                "{} {} | Tests: {} | Coverage: {:.1}%\n",
                status_icon, module.name, test_ratio, module.coverage_info.coverage_percentage
            ));
        }

        // Problematic modules
        let problems = self.get_problematic_modules();
        if !problems.is_empty() {
            dashboard.push_str("\n🚨 MODULES NEEDING ATTENTION\n");
            dashboard.push_str("---------------------------\n");

            for module in problems {
                dashboard.push_str(&format!("❌ {}\n", module.name));

                if let CompilationStatus::Errors(count) = module.compilation_status {
                    dashboard.push_str(&format!("   • {} compilation errors\n", count));
                }

                if module.test_status.failed > 0 {
                    dashboard.push_str(&format!(
                        "   • {} failing tests\n",
                        module.test_status.failed
                    ));
                }

                if module.coverage_info.coverage_percentage < 80.0 {
                    dashboard.push_str(&format!(
                        "   • Low coverage: {:.1}%\n",
                        module.coverage_info.coverage_percentage
                    ));
                }

                let critical_issues: Vec<_> = module
                    .issues
                    .iter()
                    .filter(|issue| {
                        matches!(
                            issue.severity,
                            IssueSeverity::Critical | IssueSeverity::High
                        )
                    })
                    .collect();

                for issue in critical_issues {
                    dashboard.push_str(&format!(
                        "   • {:?}: {}\n",
                        issue.severity, issue.description
                    ));
                }
            }
        }

        dashboard.push_str(&format!(
            "\nLast Updated: {}\n",
            self.last_updated.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        dashboard
    }

    /// Save dashboard to file
    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load dashboard from file
    pub fn load_from_file(path: &str) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let dashboard = serde_json::from_str(&json)?;
        Ok(dashboard)
    }
}

impl Default for SystemHealth {
    fn default() -> Self {
        Self {
            build_passing: false,
            all_tests_passing: false,
            coverage_threshold_met: false,
            no_critical_issues: true,
            regression_tests_passing: false,
            overall_score: 0.0,
        }
    }
}

impl Default for TestStatus {
    fn default() -> Self {
        Self {
            total_tests: 0,
            passed: 0,
            failed: 0,
            ignored: 0,
            last_run: Utc::now(),
            execution_time_ms: 0,
        }
    }
}

impl Default for CoverageInfo {
    fn default() -> Self {
        Self {
            lines_covered: 0,
            lines_total: 0,
            coverage_percentage: 0.0,
            critical_paths_covered: false,
        }
    }
}

/// Helper to collect current system status by running actual cargo commands
pub fn collect_current_status() -> BuildDashboard {
    let mut dashboard = BuildDashboard::new();

    // Run cargo check to get compilation status
    let compilation_status = run_cargo_check();

    // Run cargo test to get test status
    let test_status = run_cargo_test();

    // Add core module with actual status
    let status = ModuleStatus {
        name: "core".to_string(),
        compilation_status,
        test_status,
        coverage_info: CoverageInfo {
            lines_covered: 0,
            lines_total: 0,
            coverage_percentage: 0.0,
            critical_paths_covered: false,
        }, // TODO: Implement coverage parsing from cargo tarpaulin or similar
        dependencies: vec!["tokio".to_string(), "serde".to_string()],
        last_modified: Utc::now(),
        issues: vec![],
    };

    dashboard.update_module("core", status);
    dashboard
}

/// Run cargo check and parse error count from output
fn run_cargo_check() -> CompilationStatus {
    use std::process::Command;

    match Command::new("cargo").arg("check").output() {
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let error_count = count_cargo_errors(&stderr);
            if error_count > 0 {
                CompilationStatus::Errors(error_count)
            } else {
                CompilationStatus::Clean
            }
        }
        Err(_) => CompilationStatus::NotCompiled,
    }
}

/// Run cargo test and parse test results
fn run_cargo_test() -> TestStatus {
    use std::process::Command;
    use std::time::Instant;

    let start = Instant::now();
    match Command::new("cargo").arg("test").arg("--lib").output() {
        Ok(output) => {
            let execution_time = start.elapsed().as_millis() as u64;
            let stdout = String::from_utf8_lossy(&output.stdout);

            // Parse test results from output like "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
            let (passed, failed, ignored) = parse_test_output(&stdout);
            let total_tests = passed + failed + ignored;

            TestStatus {
                total_tests,
                passed,
                failed,
                ignored,
                last_run: Utc::now(),
                execution_time_ms: execution_time,
            }
        }
        Err(_) => TestStatus {
            total_tests: 0,
            passed: 0,
            failed: 0,
            ignored: 0,
            last_run: Utc::now(),
            execution_time_ms: 0,
        },
    }
}

/// Count compilation errors from cargo check stderr
fn count_cargo_errors(stderr: &str) -> u32 {
    stderr
        .lines()
        .filter(|line| line.contains("error[E") || line.starts_with("error:"))
        .count() as u32
}

/// Parse test results from cargo test stdout
fn parse_test_output(output: &str) -> (u32, u32, u32) {
    for line in output.lines() {
        if line.contains("test result:") {
            // Parse "ok. 5 passed; 0 failed; 0 ignored"
            let parts: Vec<&str> = line.split(';').collect();
            if parts.len() >= 3 {
                let passed = parse_count(parts[0], "passed");
                let failed = parse_count(parts[1], "failed");
                let ignored = parse_count(parts[2], "ignored");
                return (passed, failed, ignored);
            }
        }
    }
    (0, 0, 0)
}

/// Parse count from string like " 5 passed"
fn parse_count(part: &str, keyword: &str) -> u32 {
    if let Some(idx) = part.find(keyword) {
        let num_str: String = part[..idx]
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        num_str.parse().unwrap_or(0)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_creation() {
        let dashboard = BuildDashboard::new();
        assert_eq!(dashboard.modules.len(), 0);
        assert_eq!(dashboard.overall_health.overall_score, 0.0);
    }

    #[test]
    fn test_module_update() {
        let mut dashboard = BuildDashboard::new();

        let status = ModuleStatus {
            name: "test_module".to_string(),
            compilation_status: CompilationStatus::Clean,
            test_status: TestStatus {
                total_tests: 10,
                passed: 10,
                failed: 0,
                ignored: 0,
                last_run: Utc::now(),
                execution_time_ms: 1000,
            },
            coverage_info: CoverageInfo {
                lines_covered: 80,
                lines_total: 100,
                coverage_percentage: 80.0,
                critical_paths_covered: true,
            },
            dependencies: vec!["core".to_string()],
            last_modified: Utc::now(),
            issues: vec![],
        };

        dashboard.update_module("test_module", status);

        assert_eq!(dashboard.modules.len(), 1);
        assert!(dashboard.overall_health.build_passing);
        assert!(dashboard.overall_health.all_tests_passing);
        assert!(dashboard.overall_health.coverage_threshold_met);
        assert_eq!(dashboard.overall_health.overall_score, 100.0);
    }

    #[test]
    fn test_problematic_modules() {
        let mut dashboard = BuildDashboard::new();

        let problematic_status = ModuleStatus {
            name: "problematic_module".to_string(),
            compilation_status: CompilationStatus::Errors(5),
            test_status: TestStatus {
                total_tests: 10,
                passed: 5,
                failed: 5,
                ignored: 0,
                last_run: Utc::now(),
                execution_time_ms: 2000,
            },
            coverage_info: CoverageInfo {
                lines_covered: 30,
                lines_total: 100,
                coverage_percentage: 30.0,
                critical_paths_covered: false,
            },
            dependencies: vec![],
            last_modified: Utc::now(),
            issues: vec![ModuleIssue {
                severity: IssueSeverity::Critical,
                description: "Memory leak detected".to_string(),
                component: "memory_manager".to_string(),
                detected_at: Utc::now(),
            }],
        };

        dashboard.update_module("problematic_module", problematic_status);

        let problems = dashboard.get_problematic_modules();
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].name, "problematic_module");
        assert_eq!(dashboard.overall_health.overall_score, 0.0);
    }

    #[test]
    fn test_dashboard_generation() {
        let dashboard = collect_current_status();
        let dashboard_text = dashboard.generate_dashboard();

        assert!(dashboard_text.contains("RUSTCHAIN BUILD DASHBOARD"));
        assert!(dashboard_text.contains("Overall Health Score"));
        assert!(dashboard_text.contains("MODULE SUMMARY"));
    }
}
