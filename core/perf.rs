use std::collections::HashMap;
use std::time::{Instant};

#[derive(Debug, Clone)]
pub struct PerfMetric {
    pub name: String,
    pub duration_ms: u128,
}

pub struct PerfCollector {
    active: HashMap<String, Instant>,
    pub completed: Vec<PerfMetric>,
}

impl PerfCollector {
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
            completed: vec![],
        }
    }

    pub fn start(&mut self, name: &str) {
        self.active.insert(name.to_string(), Instant::now());
    }

    pub fn end(&mut self, name: &str) {
        if let Some(start) = self.active.remove(name) {
            let duration = start.elapsed().as_millis();
            self.completed.push(PerfMetric {
                name: name.to_string(),
                duration_ms: duration,
            });
        }
    }

    pub fn summary(&self) -> String {
        self.completed.iter()
            .map(|m| format!("{}: {}ms", m.name, m.duration_ms))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
---

file: lib.rs
---
pub mod perf;
---
