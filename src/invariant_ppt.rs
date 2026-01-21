use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::warn;

#[derive(Clone, Debug)]
pub struct InvariantRecord {
    pub msg: String,
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct TestMetrics {
    pub started_at: Option<Instant>,
    pub elapsed: Option<Duration>,
    pub invariants_logged: u64,
    pub properties_run: u64,
    pub metamorphic_runs: u64,
    pub metamorphic_failures: u64,
}

static INVARIANT_LOG: RwLock<Vec<InvariantRecord>> = RwLock::new(Vec::new());
static METRICS: RwLock<TestMetrics> = RwLock::new(TestMetrics {
    started_at: None,
    elapsed: None,
    invariants_logged: 0,
    properties_run: 0,
    metamorphic_runs: 0,
    metamorphic_failures: 0,
});

#[macro_export]
macro_rules! assert_invariant {
    ($cond:expr, $msg:expr, $scope:expr) => {{
        if !$cond {
            $crate::invariant_ppt::log_invariant(&format!("INVARIANT FAILED: {}", $msg), $scope);
            tracing::error!("Invariant failed: {}", $msg);
            // For production, log error but don't crash
        } else {
            $crate::invariant_ppt::log_invariant($msg, $scope);
            $crate::invariant_ppt::inc_invariants();
        }
    }};
}

pub fn log_invariant(msg: &str, scope: Option<&str>) {
    if let Ok(mut log) = INVARIANT_LOG.write() {
        log.push(InvariantRecord {
            msg: msg.to_string(),
            scope: scope.map(|s| s.to_string()),
        });
    } else {
        // RwLock is poisoned - log error but don't panic
        warn!(
            "INVARIANT_LOG rwlock is poisoned, skipping log entry: {}",
            msg
        );
    }
}

pub fn clear_invariant_log() {
    if let Ok(mut log) = INVARIANT_LOG.write() {
        log.clear();
    } else {
        warn!("INVARIANT_LOG rwlock is poisoned, cannot clear log");
    }
}

pub fn get_invariant_log() -> Vec<InvariantRecord> {
    INVARIANT_LOG
        .read()
        .map(|log| log.clone())
        .unwrap_or_else(|_| {
            warn!("INVARIANT_LOG rwlock is poisoned, returning empty log");
            Vec::new()
        })
}

pub fn start_metrics() {
    if let Ok(mut m) = METRICS.write() {
        m.started_at = Some(Instant::now());
        m.elapsed = None;
        m.invariants_logged = 0;
        m.properties_run = 0;
        m.metamorphic_runs = 0;
        m.metamorphic_failures = 0;
    } else {
        warn!("METRICS rwlock is poisoned, cannot start metrics");
    }
}

pub fn finish_metrics() -> TestMetrics {
    METRICS
        .write()
        .map(|mut m| {
            if let Some(start) = m.started_at {
                m.elapsed = Some(start.elapsed());
            }
            m.clone()
        })
        .unwrap_or_else(|_| {
            warn!("METRICS rwlock is poisoned, returning default metrics");
            TestMetrics::default()
        })
}

pub fn snapshot_metrics() -> TestMetrics {
    METRICS.read().map(|m| m.clone()).unwrap_or_else(|_| {
        warn!("METRICS rwlock is poisoned, returning default metrics");
        TestMetrics::default()
    })
}

pub fn reset_metrics() {
    if let Ok(mut m) = METRICS.write() {
        *m = TestMetrics::default();
    } else {
        warn!("METRICS rwlock is poisoned, cannot reset metrics");
    }
}

pub fn inc_invariants() {
    if let Ok(mut m) = METRICS.write() {
        m.invariants_logged += 1;
    } else {
        warn!("METRICS rwlock is poisoned, cannot increment invariants");
    }
}

pub(crate) fn inc_properties() {
    if let Ok(mut m) = METRICS.write() {
        m.properties_run += 1;
    } else {
        warn!("METRICS rwlock is poisoned, cannot increment properties");
    }
}

pub(crate) fn inc_metamorphic(run_ok: bool) {
    if let Ok(mut m) = METRICS.write() {
        m.metamorphic_runs += 1;
        if !run_ok {
            m.metamorphic_failures += 1;
        }
    } else {
        warn!("METRICS rwlock is poisoned, cannot increment metamorphic");
    }
}

// Contract test helper: ensure named invariants are present in the run
pub fn contract_test(_name: &str, required_msgs: &[&str]) {
    let log = get_invariant_log();
    for req in required_msgs {
        let found = log.iter().any(|r| r.msg == *req);
        assert!(found, "Missing invariant: {}", req);
    }
}

// Simple property test harness (keeps PPT as oracle)
pub fn property_test<F: Fn() -> bool>(f: F) {
    inc_properties();
    assert!(f(), "Property test failed");
}

// Metamorphic testing helper: generate input, transform, and assert relation
pub fn metamorphic_test<T, G, X, P>(iterations: usize, gen: G, transform: X, relation: P)
where
    G: Fn(usize) -> T,
    X: Fn(&T) -> T,
    P: Fn(&T, &T) -> bool,
{
    for i in 0..iterations {
        let base = gen(i);
        let derived = transform(&base);
        let ok = relation(&base, &derived);
        inc_metamorphic(ok);
        assert!(ok, "Metamorphic relation failed at case {}", i);
    }
}

// Optional proptest integration (feature = "proptest")
#[cfg(feature = "proptest")]
pub mod proptest_bridge {
    use super::inc_properties;
    use proptest::prelude::*;

    // Runs a property with shrinking using a provided Strategy
    pub fn check_with<S, F>(strategy: S, predicate: F)
    where
        S: Strategy + 'static,
        F: Fn(S::Value) -> bool + 'static,
    {
        inc_properties();
        proptest!(|(x in strategy)| {
            prop_assert!(predicate(x));
        });
    }
}
