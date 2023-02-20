use std::sync::Arc;

use tokio::sync::watch;

use crate::{
    config::{Config, ConfigContext, ServerProtocol},
    core::Core,
};

use super::add_test_certs;

pub mod dane;
pub mod extensions;
pub mod lmtp;
pub mod mta_sts;
pub mod smtp;
pub mod throttle;

const SERVER: &str = "
[server]
hostname = 'mx.example.org'
greeting = 'Test SMTP instance'
protocol = 'smtp'

[server.listener.smtp-debug]
bind = ['127.0.0.1:9925']

[server.listener.lmtp-debug]
bind = ['127.0.0.1:9924']
protocol = 'lmtp'
tls.implicit = true

[server.listener.management-debug]
bind = ['127.0.0.1:9980']
protocol = 'http'

[server.socket]
reuse-addr = true

[server.tls]
enable = true
implicit = false
certificate = 'default'

[certificate.default]
cert = 'file://{CERT}'
private-key = 'file://{PK}'
";

pub fn start_test_server(core: Arc<Core>, protocols: &[ServerProtocol]) -> watch::Sender<bool> {
    // Spawn listeners
    let mut ctx = ConfigContext::default();
    let config = Config::parse(&add_test_certs(SERVER)).unwrap();
    config.parse_servers(&mut ctx).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    for server in ctx.servers {
        if protocols.contains(&server.protocol) {
            for listener in &server.listeners {
                listener
                    .socket
                    .bind(listener.addr)
                    .unwrap_or_else(|_| panic!("Failed to bind to {}", listener.addr));
            }

            match &server.protocol {
                ServerProtocol::Smtp | ServerProtocol::Lmtp => {
                    server.spawn(core.clone(), shutdown_rx.clone()).unwrap()
                }
                ServerProtocol::Http => server
                    .spawn_management(core.clone(), shutdown_rx.clone())
                    .unwrap(),
                ServerProtocol::Imap => unreachable!(),
            };
        }
    }
    shutdown_tx
}
