use std::{sync::Arc, time::Instant};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::watch,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::{
    config::{Server, ServerProtocol},
    core::{Core, ServerInstance, Session, SessionData, SessionParameters, State},
};

use super::IsTls;

impl Server {
    pub fn spawn(self, core: Arc<Core>, shutdown_rx: watch::Receiver<bool>) -> Result<(), String> {
        // Build TLS acceptor
        let tls_acceptor = self.tls.map(|config| TlsAcceptor::from(Arc::new(config)));
        let tls_implicit = self.tls_implicit;

        // Prepare instance
        let instance = Arc::new(ServerInstance {
            greeting: format!("220 {} {}\r\n", self.hostname, self.greeting).into_bytes(),
            id: self.id,
            listener_id: self.internal_id,
            is_smtp: self.protocol == ServerProtocol::Smtp,
            hostname: self.hostname,
        });

        // Spawn listeners
        for listener_config in self.listeners {
            // Bind socket
            let local_ip = listener_config.addr.ip();
            listener_config
                .socket
                .bind(listener_config.addr)
                .map_err(|err| format!("Failed to bind to {}: {}", listener_config.addr, err))?;
            let listener = listener_config
                .socket
                .listen(listener_config.backlog.unwrap_or(1024))
                .map_err(|err| format!("Failed to listen on {}: {}", listener_config.addr, err))?;
            if let Some(ttl) = listener_config.ttl {
                listener.set_ttl(ttl).map_err(|err| {
                    format!("Failed to set TTL on {}: {}", listener_config.addr, err)
                })?;
            }

            // Create tracing span
            let listener_span = tracing::info_span!(
                "listener",
                id = instance.id,
                bind.ip = listener_config.addr.ip().to_string(),
                bind.port = listener_config.addr.port(),
                tls = tls_implicit
            );

            // Spawn listener
            let mut shutdown_rx = shutdown_rx.clone();
            let core = core.clone();
            let instance = instance.clone();
            let tls_acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        stream = listener.accept() => {
                            match stream {
                                Ok((stream, remote_addr)) => {
                                    let span = tracing::info_span!(
                                        "session",
                                        remote.ip = remote_addr.ip().to_string(),
                                        remote.port = remote_addr.port(),
                                    );
                                    span.follows_from(&listener_span);

                                    // Enforce concurrency
                                    let mut in_flight = Vec::new();
                                    if let Some(req) = core.session.concurrency.is_allowed() {
                                        in_flight.push(req);
                                    } else {
                                        tracing::info!(
                                            parent: &span,
                                            context = "throttle",
                                            event = "too-many-requests",
                                            max_concurrent = core.session.concurrency.max_concurrent,
                                            "Too many concurrent connections."
                                        );
                                        continue;
                                    }

                                    // Create session
                                    let mut session = Session {
                                        core: core.clone(),
                                        instance: instance.clone(),
                                        state: State::default(),
                                        span,
                                        stream,
                                        in_flight,
                                        data: SessionData::new(local_ip, remote_addr.ip()),
                                        params: SessionParameters::default(),
                                    };

                                    // Enforce throttle
                                    if !session.is_allowed().await {
                                        continue;
                                    }

                                    // Spawn connection
                                    let shutdown_rx = shutdown_rx.clone();
                                    let tls_acceptor = tls_acceptor.clone();
                                    let instance = instance.clone();

                                    tokio::spawn(async move {
                                        if tls_implicit {
                                            if let Ok(mut session) = session.into_tls(tls_acceptor.unwrap()).await {
                                                if session.write(&instance.greeting).await.is_ok() {
                                                    session.eval_session_params().await;
                                                    session.handle_conn(shutdown_rx).await;
                                                }
                                            }
                                        } else if session.write(&instance.greeting).await.is_ok() {
                                            session.eval_session_params().await;
                                            session.handle_conn(tls_acceptor, shutdown_rx).await;
                                        }
                                    });
                                }
                                Err(err) => {
                                    tracing::debug!(parent: &listener_span,
                                                    context = "io",
                                                    event = "error",
                                                    "Failed to accept TCP connection: {}", err);
                                }
                            }
                        },
                        _ = shutdown_rx.changed() => {
                            tracing::debug!(parent: &listener_span,
                                event = "shutdown",
                                "Listener shutting down.");
                            break;
                        }
                    };
                }
            });
        }

        Ok(())
    }
}

impl Session<TcpStream> {
    pub async fn into_tls(
        self,
        acceptor: TlsAcceptor,
    ) -> Result<Session<TlsStream<TcpStream>>, ()> {
        let span = self.span;
        Ok(Session {
            stream: match acceptor.accept(self.stream).await {
                Ok(stream) => {
                    tracing::info!(
                        parent: &span,
                        context = "tls",
                        event = "handshake",
                        version = ?stream.get_ref().1.protocol_version().unwrap_or(rustls::ProtocolVersion::TLSv1_3),
                        cipher = ?stream.get_ref().1.negotiated_cipher_suite().unwrap_or(rustls::cipher_suite::TLS13_AES_128_GCM_SHA256),
                    );
                    stream
                }
                Err(err) => {
                    tracing::debug!(
                        parent: &span,
                        context = "tls",
                        event = "error",
                        "Failed to accept TLS connection: {}",
                        err
                    );
                    return Err(());
                }
            },
            state: self.state,
            data: self.data,
            instance: self.instance,
            core: self.core,
            in_flight: self.in_flight,
            params: self.params,
            span,
        })
    }

    pub async fn handle_conn(
        mut self,
        tls_acceptor: Option<TlsAcceptor>,
        shutdown_rx: watch::Receiver<bool>,
    ) {
        if let Some(shutdown_rx) = self.handle_conn_(shutdown_rx).await {
            if let Some(tls_acceptor) = tls_acceptor {
                if let Ok(session) = self.into_tls(tls_acceptor).await {
                    session.handle_conn(shutdown_rx).await;
                }
            }
        }
    }
}

impl Session<TlsStream<TcpStream>> {
    pub async fn handle_conn(mut self, shutdown_rx: watch::Receiver<bool>) {
        self.handle_conn_(shutdown_rx).await;
    }
}

impl<T: AsyncRead + AsyncWrite + IsTls + Unpin> Session<T> {
    pub async fn handle_conn_(
        &mut self,
        mut shutdown_rx: watch::Receiver<bool>,
    ) -> Option<watch::Receiver<bool>> {
        let mut buf = vec![0; 8192];

        loop {
            tokio::select! {
                result = tokio::time::timeout(
                    self.params.timeout,
                    self.read(&mut buf)) => {
                        match result {
                            Ok(Ok(bytes_read)) => {
                                if bytes_read > 0 {
                                    if Instant::now() < self.data.valid_until && bytes_read <= self.data.bytes_left  {
                                        self.data.bytes_left -= bytes_read;
                                        match self.ingest(&buf[..bytes_read]).await {
                                            Ok(true) => (),
                                            Ok(false) => {
                                                return (shutdown_rx).into();
                                            }
                                            Err(_) => {
                                                break;
                                            }
                                        }
                                    } else if bytes_read > self.data.bytes_left {
                                        self
                                            .write(format!("451 4.7.28 {} Session exceeded transfer quota.\r\n", self.instance.hostname).as_bytes())
                                            .await
                                            .ok();
                                        tracing::debug!(
                                            parent: &self.span,
                                            event = "disconnect",
                                            reason = "transfer-limit",
                                            "Client exceeded incoming transfer limit."
                                        );
                                        break;
                                    } else {
                                        self
                                            .write(format!("453 4.3.2 {} Session open for too long.\r\n", self.instance.hostname).as_bytes())
                                            .await
                                            .ok();
                                        tracing::debug!(
                                            parent: &self.span,
                                            event = "disconnect",
                                            reason = "loiter",
                                            "Session open for too long."
                                        );
                                        break;
                                    }
                                } else {
                                    tracing::debug!(
                                        parent: &self.span,
                                        event = "disconnect",
                                        reason = "peer",
                                        "Connection closed by peer."
                                    );
                                    break;
                                }
                            }
                            Ok(Err(_)) => {
                                break;
                            }
                            Err(_) => {
                                tracing::debug!(
                                    parent: &self.span,
                                    event = "disconnect",
                                    reason = "timeout",
                                    "Connection timed out."
                                );
                                self
                                    .write(format!("221 2.0.0 {} Disconnecting inactive client.\r\n", self.instance.hostname).as_bytes())
                                    .await
                                    .ok();
                                break;
                            }
                        }
                },
                _ = shutdown_rx.changed() => {
                    tracing::debug!(
                        parent: &self.span,
                        event = "disconnect",
                        reason = "shutdown",
                        "Server shutting down."
                    );
                    self.write(b"421 4.3.0 Server shutting down.\r\n").await.ok();
                    break;
                }
            };
        }

        None
    }
}
