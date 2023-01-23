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

pub fn start_test_server(core: Arc<Core>, smtp: bool) -> watch::Sender<bool> {
    // Spawn listeners
    let mut ctx = ConfigContext::default();
    Config::parse(&add_test_certs(SERVER))
        .unwrap()
        .parse_servers(&mut ctx)
        .unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    for server in ctx.servers {
        if (smtp && server.protocol == ServerProtocol::Smtp)
            || (!smtp && server.protocol == ServerProtocol::Lmtp)
        {
            server.spawn(core.clone(), shutdown_rx.clone()).unwrap();
        }
    }
    shutdown_tx
}
