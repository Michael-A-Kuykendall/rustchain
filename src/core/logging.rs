use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("rustchain=info"));
    
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();
}

#[macro_export]
macro_rules! log_step {
    ($step:expr, $message:expr) => {
        tracing::info!(step = $step, message = $message);
    };
}
