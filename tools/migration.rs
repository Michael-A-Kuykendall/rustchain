use serde_yaml::{Value};

pub struct MigrationTask {
    pub from_version: String,
    pub description: String,
    pub patch: fn(Value) -> Value,
}

pub struct Migrator {
    pub tasks: Vec<MigrationTask>,
}

impl Migrator {
    pub fn new() -> Self {
        Self { tasks: vec![] }
    }

    pub fn register(&mut self, task: MigrationTask) {
        self.tasks.push(task);
    }

    pub fn apply(&self, input: Value, version: &str) -> Value {
        self.tasks.iter()
            .filter(|t| t.from_version == version)
            .fold(input, |acc, t| (t.patch)(acc))
    }
}
---

file: lib.rs
---
pub mod migration;
---
