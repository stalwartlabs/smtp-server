use std::{fs, sync::Arc, time::Duration};

use dashmap::DashMap;
use smtp_server::{
    config::{Config, ConfigContext},
    core::{
        throttle::{ConcurrencyLimiter, ThrottleKeyHasherBuilder},
        Core, QueueCore, SessionCore,
    },
    queue::{self, manager::SpawnQueue},
};
use tokio::sync::{mpsc, watch};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Read configuration parameters
    let config = parse_config();
    let mut config_context = ConfigContext::default();
    config
        .parse_servers(&mut config_context)
        .failed("Configuration error");
    config
        .parse_remote_hosts(&mut config_context)
        .failed("Configuration error");
    config
        .parse_lists(&mut config_context)
        .failed("Configuration error");
    let session_config = config
        .parse_session_config(&config_context)
        .failed("Configuration error");
    let queue_config = config
        .parse_queue(&config_context)
        .failed("Configuration error");

    // Build core
    let (queue_tx, queue_rx) = mpsc::channel(1024);
    let core = Arc::new(Core {
        session: SessionCore {
            config: session_config,
            concurrency: ConcurrencyLimiter::new(
                config
                    .property("global.concurrency")
                    .failed("Failed to parse global concurrency")
                    .unwrap_or(8192),
            ),
            throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                config
                    .property("global.throttle-map.capacity")
                    .failed("Failed to parse throttle map capacity")
                    .unwrap_or(2),
                ThrottleKeyHasherBuilder::default(),
                config
                    .property("global.throttle-map.shard")
                    .failed("Failed to parse throttle map shard amount")
                    .unwrap_or(32),
            ),
        },
        queue: QueueCore {
            config: queue_config,
            throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                config
                    .property("global.throttle-map.capacity")
                    .failed("Failed to parse throttle map capacity")
                    .unwrap_or(2),
                ThrottleKeyHasherBuilder::default(),
                config
                    .property("global.throttle-map.shard")
                    .failed("Failed to parse throttle map shard amount")
                    .unwrap_or(32),
            ),
            id_seq: 0.into(),
            capacity: DashMap::with_capacity_and_hasher_and_shard_amount(
                config
                    .property("global.throttle-map.capacity")
                    .failed("Failed to parse throttle map capacity")
                    .unwrap_or(2),
                ThrottleKeyHasherBuilder::default(),
                config
                    .property("global.throttle-map.shard")
                    .failed("Failed to parse throttle map shard amount")
                    .unwrap_or(32),
            ),
            tx: queue_tx,
        },
    });

    // Enable logging
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(
                config
                    .property("global.log-level")
                    .failed("Failed to parse log level")
                    .unwrap_or(tracing::Level::INFO),
            )
            .finish(),
    )
    .failed("Failed to set subscriber");
    tracing::info!(
        "Starting Stalwart SMTP server v{}...",
        env!("CARGO_PKG_VERSION")
    );

    // Spawn queue manager
    queue_rx
        .spawn(core.clone())
        .failed("Failed to spawn queue manager");

    // Spawn listeners
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    for server in config_context.servers {
        server
            .spawn(core.clone(), shutdown_rx.clone())
            .failed("Failed to start listener");
    }

    // Wait for shutdown signal
    #[cfg(not(target_env = "msvc"))]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut h_term = signal(SignalKind::terminate()).failed("start signal handler");
        let mut h_int = signal(SignalKind::interrupt()).failed("start signal handler");

        tokio::select! {
            _ = h_term.recv() => tracing::debug!("Received SIGTERM."),
            _ = h_int.recv() => tracing::debug!("Received SIGINT."),
        };
    }

    #[cfg(target_env = "msvc")]
    {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(err) => {
                eprintln!("Unable to listen for shutdown signal: {}", err);
            }
        }
    }

    // Shutdown the system
    tracing::info!(
        "Shutting down Stalwart SMTP server v{}...",
        env!("CARGO_PKG_VERSION")
    );

    // Stop services
    shutdown_tx.send(true).ok();
    core.queue.tx.send(queue::Event::Stop).await.ok();

    // Wait for services to finish
    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}

fn parse_config() -> Config {
    let mut config_path = None;
    let mut found_param = false;

    for arg in std::env::args().into_iter().skip(1) {
        if let Some((key, value)) = arg.split_once('=') {
            if key.starts_with("--config") {
                config_path = value.trim().to_string().into();
                break;
            } else {
                failed(&format!("Invalid command line argument: {}", key));
            }
        } else if found_param {
            config_path = arg.into();
            break;
        } else if arg.starts_with("--config") {
            found_param = true;
        } else {
            failed(&format!("Invalid command line argument: {}", arg));
        }
    }

    Config::parse(
        &fs::read_to_string(config_path.failed("Missing parameter --config=<path-to-config>."))
            .failed("Could not read configuration file"),
    )
    .failed("Invalid configuration file")
}

pub trait UnwrapFailure<T> {
    fn failed(self, action: &str) -> T;
}

impl<T> UnwrapFailure<T> for Option<T> {
    fn failed(self, message: &str) -> T {
        match self {
            Some(result) => result,
            None => {
                eprintln!("{}", message);
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
                eprintln!("{}: {}", message, err);
                std::process::exit(1);
            }
        }
    }
}

pub fn failed(message: &str) -> ! {
    eprintln!("{}", message);
    std::process::exit(1);
}
