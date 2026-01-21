use std::io::{self, Write};
use std::time::Instant;

/// CLI output formatting with colors and status indicators
pub struct PrettyOutput {
    #[allow(dead_code)]
    start_time: Instant,
    supports_color: bool,
}

impl PrettyOutput {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            supports_color: supports_color(),
        }
    }

    /// Print the RustChain banner
    pub fn banner(&self) {
        let logo = r#"
   ____            _   _____ _           _       
  |  _ \ _   _ ___| |_/ ____| |__   __ _(_)_ __  
  | |_) | | | / __| __| |   | '_ \ / _` | | '_ \ 
  |  _ <| |_| \__ \ |_| |___| | | | (_| | | | | |
  |_| \_\\__,_|___/\__|\____|_| |_|\__,_|_|_| |_|
                                                 
  🤖 Enterprise AI Agent Framework
"#;

        if self.supports_color {
            println!("{}", self.cyan(logo));
        } else {
            println!("{}", logo);
        }
    }

    /// Print a step with a beautiful icon
    pub fn step(&self, icon: &str, message: &str) {
        let formatted = if self.supports_color {
            format!("{} {}", icon, self.white(message))
        } else {
            format!("{} {}", icon, message)
        };
        println!("{}", formatted);
        let _ = io::stdout().flush();
    }

    /// Print a success message
    pub fn success(&self, message: &str) {
        self.step("✅", message);
    }

    /// Print an info message  
    pub fn info(&self, message: &str) {
        self.step("ℹ️", message);
    }

    /// Print a warning message
    pub fn warning(&self, message: &str) {
        self.step("⚠️", message);
    }

    /// Print an error message
    pub fn error(&self, message: &str) {
        self.step("❌", message);
    }

    /// Print a progress indicator
    pub fn progress(&self, message: &str) {
        self.step("🔄", message);
    }

    /// Print a completion summary
    pub fn completion_summary(
        &self,
        mission_name: &str,
        duration_secs: f64,
        steps: usize,
        status: &str,
    ) {
        println!();
        self.success(&format!("Mission '{}' completed!", mission_name));
        println!();

        let summary = format!(
            "  📊 Summary:\n  ⏱️  Duration: {:.2}s\n  📋 Steps: {}\n  🎯 Status: {}",
            duration_secs, steps, status
        );

        if self.supports_color {
            println!("{}", self.dim(&summary));
        } else {
            println!("{}", summary);
        }
        println!();
    }

    /// Print mission execution start
    pub fn mission_start(&self, mission_name: &str, description: &str) {
        println!();
        self.step("🚀", &format!("Executing mission: {}", mission_name));
        if !description.is_empty() {
            if self.supports_color {
                println!("   {}", self.dim(description));
            } else {
                println!("   {}", description);
            }
        }
        println!();
    }

    /// Print a simple divider
    pub fn divider(&self) {
        if self.supports_color {
            println!("{}", self.dim("────────────────────────────────────────"));
        } else {
            println!("────────────────────────────────────────");
        }
    }

    // Color helpers
    fn cyan(&self, text: &str) -> String {
        if self.supports_color {
            format!("\x1b[36m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    fn white(&self, text: &str) -> String {
        if self.supports_color {
            format!("\x1b[37m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }

    fn dim(&self, text: &str) -> String {
        if self.supports_color {
            format!("\x1b[2m{}\x1b[0m", text)
        } else {
            text.to_string()
        }
    }
}

impl Default for PrettyOutput {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple version without Windows API dependencies for now
fn supports_color_simple() -> bool {
    if cfg!(windows) {
        // Check for modern Windows terminals
        std::env::var("WT_SESSION").is_ok() || // Windows Terminal
        std::env::var("TERM_PROGRAM").as_deref() == Ok("vscode") || // VS Code  
        std::env::var("ConEmuPID").is_ok() || // ConEmu
        std::env::var("ANSICON").is_ok() // ANSICON
    } else {
        // Unix-like systems
        std::env::var("TERM")
            .map(|term| !term.is_empty() && term != "dumb")
            .unwrap_or(false)
    }
}

/// Use the simple version for now to avoid winapi dependency
fn supports_color() -> bool {
    supports_color_simple()
}
