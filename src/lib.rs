pub mod config;
pub mod core;
pub mod inbound;
pub mod lookup;
pub mod outbound;
pub mod queue;
pub mod reporting;
#[cfg(test)]
pub mod tests;

pub static USER_AGENT: &str = concat!("StalwartSMTP/", env!("CARGO_PKG_VERSION"),);

pub trait UnwrapFailure<T> {
    fn failed(self, action: &str) -> T;
}

impl<T> UnwrapFailure<T> for Option<T> {
    fn failed(self, message: &str) -> T {
        match self {
            Some(result) => result,
            None => {
                eprintln!("{message}");
                std::process::exit(1);
            }
        }
    }
}

impl<T, E: std::fmt::Display> UnwrapFailure<T> for Result<T, E> {
    fn failed(self, message: &str) -> T {
        match self {
            Ok(result) => result,
            Err(err) => {
                eprintln!("{message}: {err}");
                std::process::exit(1);
            }
        }
    }
}

pub fn failed(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}
