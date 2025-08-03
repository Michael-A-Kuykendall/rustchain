use crate::core::invariant::{SystemInvariant, ToolRegistryNotEmpty};
use crate::engine::context::RuntimeContext;

pub fn handle_invariant_check() {
    let ctx = RuntimeContext::new();

    let invariants: Vec<Box<dyn SystemInvariant>> = vec![
        Box::new(ToolRegistryNotEmpty),
    ];

    for invariant in invariants {
        match invariant.check(&ctx) {
            Ok(_) => println!("✔ [ok] {}", invariant.name()),
            Err(e) => println!("✘ [fail] {}: {}", invariant.name(), e),
        }
    }
}
---

file: lib.rs
---
pub mod invariant;
---
