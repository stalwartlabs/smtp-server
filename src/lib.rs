pub mod config;
pub mod core;
pub mod inbound;
pub mod outbound;
pub mod queue;
pub mod remote;
pub mod reporting;
#[cfg(test)]
pub mod tests;

pub static USER_AGENT: &str = concat!("StalwartSMTP/", env!("CARGO_PKG_VERSION"),);
