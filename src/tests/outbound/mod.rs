/*
 * Copyright (c) 2023 Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP Server.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

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
