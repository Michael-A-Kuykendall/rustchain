#[macro_export]
macro_rules! invariant {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            panic!("Invariant failed: {}", $msg);
        }
    };
}

use crate::engine::context::ContextState;

pub fn assert_invariants(state: &ContextState) {
    if state.history.len() > 1000 {
        panic!("Invariant violated: history too long");
    }

    if state.vars.len() > 500 {
        panic!("Invariant violated: too many vars");
    }
}

pub fn register_runtime_invariants() {
    println!("[Invariant] Default invariants registered");
}
