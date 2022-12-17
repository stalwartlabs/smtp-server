use std::{net::IpAddr, time::SystemTime};

use smtp_proto::{
    request::receiver::{BdatReceiver, DataReceiver},
    Capability, EhloResponse, Error, Request,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    config::ServerProtocol,
    core::{Envelope, Session, State},
};

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn ingest(&mut self, bytes: &[u8]) -> Result<bool, ()> {
        let mut iter = bytes.iter();
        let mut state = std::mem::replace(&mut self.state, State::None);

        'outer: loop {
            match &mut state {
                State::Request(receiver) => loop {
                    match receiver.ingest(&mut iter, bytes) {
                        Ok(request) => match request {
                            Request::Rcpt { to, parameters } => todo!(),
                            Request::Mail { from, parameters } => {
                                if !self.data.helo_domain.is_empty() || !self.params.ehlo_require {
                                    if self.data.mail_from.is_empty() {
                                        if !self.params.auth_require
                                            || !self.data.authenticated_as.is_empty()
                                        {
                                            if !from.is_empty() {
                                                self.data.mail_from_lcase = from.to_lowercase();
                                                self.data.mail_from = from;
                                            } else {
                                                self.data.mail_from_lcase = "<>".to_string();
                                            }
                                        } else {
                                            self.write(
                                                b"503 5.7.1 Authentication is required.\r\n",
                                            )
                                            .await?;
                                        }
                                    } else {
                                        self.write(
                                            b"503 5.5.1 Multiple MAIL commands not allowed.\r\n",
                                        )
                                        .await?;
                                    }
                                } else {
                                    self.write(b"503 5.5.1 Polite people say EHLO first.\r\n")
                                        .await?;
                                }
                            }
                            Request::Ehlo { host } => {
                                if self.instance.protocol == ServerProtocol::Smtp {
                                    self.say_ehlo(host).await?;
                                } else {
                                    self.write(b"500 5.5.1 Invalid command.\r\n").await?;
                                }
                            }
                            Request::Data => {
                                self.write(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                                    .await?;
                                state = State::Data(DataReceiver::new());
                                continue 'outer;
                            }
                            Request::Bdat {
                                chunk_size,
                                is_last,
                            } => {
                                state = State::Bdat(BdatReceiver::new(chunk_size, is_last));
                                continue 'outer;
                            }
                            Request::Auth {
                                mechanism,
                                initial_response,
                            } => {
                                if (mechanism & self.params.auth_mechanisms) != 0 {
                                    //TODO
                                } else if self.params.auth_mechanisms == 0 {
                                    self.write(b"503 5.5.1 AUTH not allowed.\r\n").await?;
                                } else {
                                    self.write(
                                        b"554 5.7.8 Authentication mechanism not supported.\r\n",
                                    )
                                    .await?;
                                }
                            }
                            Request::Noop { .. } => {
                                self.write(b"250 2.0.0 OK\r\n").await?;
                            }
                            Request::Vrfy { value } => todo!(),
                            Request::Expn { value } => {
                                if self.params.expn {
                                    //TODO
                                } else {
                                    self.write(b"500 5.5.1 EXPN not allowed.\r\n").await?;
                                }
                            }
                            Request::StartTls => {
                                if self.params.starttls {
                                    self.write(b"220 2.0.0 Ready to start TLS.\r\n").await?;
                                    self.state = State::default();
                                    return Ok(false);
                                } else {
                                    self.write(b"504 5.7.4 Unable to start TLS.\r\n").await?;
                                }
                            }
                            Request::Rset => {
                                self.data.mail_from.clear();
                                self.data.mail_from_lcase.clear();
                                self.data.rcpt_to.clear();
                                self.data.priority = 0;
                                self.write(b"250 2.0.0 OK\r\n").await?;
                            }
                            Request::Quit => {
                                self.write(b"221 2.0.0 Bye.\r\n").await?;
                                return Err(());
                            }
                            Request::Help { .. } => {
                                self.write(
                                    b"250 2.0.0 Help can be found at https://stalw.art/smtp/\r\n",
                                )
                                .await?;
                            }
                            Request::Helo { host } => {
                                if self.instance.protocol == ServerProtocol::Smtp
                                    && self.data.helo_domain.is_empty()
                                    || self.params.ehlo_multiple
                                {
                                    self.data.helo_domain = host;
                                    self.write(
                                        format!("250 {} says hello\r\n", self.instance.hostname)
                                            .as_bytes(),
                                    )
                                    .await?;
                                } else {
                                    self.write(b"503 5.5.1 Invalid command.\r\n").await?;
                                }
                            }
                            Request::Lhlo { host } => {
                                if self.instance.protocol == ServerProtocol::Lmtp {
                                    self.say_ehlo(host).await?;
                                } else {
                                    self.write(b"502 5.5.1 Invalid command.\r\n").await?;
                                }
                            }
                            Request::Etrn { .. } | Request::Atrn { .. } | Request::Burl { .. } => {
                                self.write(b"502 5.5.1 Command not implemented.\r\n")
                                    .await?;
                            }
                        },
                        Err(err) => match err {
                            Error::NeedsMoreData { .. } => break 'outer,
                            Error::UnknownCommand | Error::InvalidResponse { .. } => {
                                self.write(b"500 5.5.1 Invalid command.\r\n").await?;
                            }
                            Error::InvalidSenderAddress => {
                                self.write(b"501 5.1.8 Bad sender's system address.\r\n")
                                    .await?;
                            }
                            Error::InvalidRecipientAddress => {
                                self.write(
                                    b"501 5.1.3 Bad destination mailbox address syntax.\r\n",
                                )
                                .await?;
                            }
                            Error::SyntaxError { syntax } => {
                                self.write(
                                    format!("501 5.5.2 Syntax error, expected: {}\r\n", syntax)
                                        .as_bytes(),
                                )
                                .await?;
                            }
                            Error::InvalidParameter { param } => {
                                self.write(
                                    format!("501 5.5.4 Invalid parameter {:?}.\r\n", param)
                                        .as_bytes(),
                                )
                                .await?;
                            }
                            Error::UnsupportedParameter { param } => {
                                self.write(
                                    format!("504 5.5.4 Unsupported parameter {:?}.\r\n", param)
                                        .as_bytes(),
                                )
                                .await?;
                            }
                        },
                    }
                },
                State::Data(receiver) => {
                    if receiver.ingest(&mut iter) {
                        // TODO finish
                        state = State::default();
                    } else {
                        break 'outer;
                    }
                }
                State::Bdat(receiver) => {
                    if receiver.ingest(&mut iter) {
                        if receiver.is_last {
                            // TODO
                        }
                        state = State::default();
                    } else {
                        break 'outer;
                    }
                }
                State::None => unreachable!(),
            }
        }
        self.state = state;

        Ok(true)
    }

    async fn say_ehlo(&mut self, domain: String) -> Result<(), ()> {
        if self.data.helo_domain.is_empty() || self.params.ehlo_multiple {
            self.data.helo_domain = domain;
            let mut response = EhloResponse::new(self.instance.hostname.as_str());
            response.capabilities.push(Capability::EnhancedStatusCodes);
            response.capabilities.push(Capability::EightBitMime);
            response.capabilities.push(Capability::BinaryMime);
            response.capabilities.push(Capability::SmtpUtf8);
            if self.params.starttls {
                response.capabilities.push(Capability::StartTls);
            }
            if self.params.pipelining {
                response.capabilities.push(Capability::Pipelining);
            }
            if self.params.chunking {
                response.capabilities.push(Capability::Chunking);
            }
            if self.params.expn {
                response.capabilities.push(Capability::Expn);
            }
            if self.params.requiretls {
                response.capabilities.push(Capability::RequireTls);
            }
            if self.params.auth_mechanisms != 0 {
                response.capabilities.push(Capability::Auth {
                    mechanisms: self.params.auth_mechanisms,
                });
            }
            if let Some(value) = &self.params.future_release {
                response.capabilities.push(Capability::FutureRelease {
                    max_interval: value.as_secs(),
                    max_datetime: SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                        + value.as_secs(),
                });
            }
            if let Some(value) = &self.params.deliver_by {
                response.capabilities.push(Capability::DeliverBy {
                    min: value.as_secs(),
                });
            }
            if let Some(value) = &self.params.mt_priority {
                response
                    .capabilities
                    .push(Capability::MtPriority { priority: *value });
            }
            if let Some(value) = &self.params.size {
                response
                    .capabilities
                    .push(Capability::Size { size: *value });
            }
            if let Some(value) = &self.params.no_soliciting {
                response.capabilities.push(Capability::NoSoliciting {
                    keywords: if !value.is_empty() {
                        value.to_string().into()
                    } else {
                        None
                    },
                });
            }
            let mut buf = Vec::with_capacity(64);
            response.write(&mut buf).ok();
            self.write(&buf).await
        } else {
            self.write(b"503 5.5.1 Already said hello.\r\n").await
        }
    }

    #[inline(always)]
    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), ()> {
        match self.stream.write_all(bytes).await {
            Ok(_) => {
                tracing::trace!(parent: &self.span,
                                event = "write",
                                data = std::str::from_utf8(bytes).unwrap_or_default(),
                                size = bytes.len());
                Ok(())
            }
            Err(err) => {
                tracing::debug!(parent: &self.span,
                                event = "error",
                                class = "io",
                                "Failed to write to stream: {:?}", err);
                Err(())
            }
        }
    }

    #[inline(always)]
    pub async fn read(&mut self, bytes: &mut [u8]) -> Result<usize, ()> {
        match self.stream.read(bytes).await {
            Ok(len) => {
                tracing::trace!(parent: &self.span,
                                event = "read",
                                data =  bytes
                                        .get(0..len)
                                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                                        .unwrap_or_default(),
                                size = len);
                Ok(len)
            }
            Err(err) => {
                tracing::debug!(
                    parent: &self.span,
                    event = "error",
                    class = "io",
                    "Failed to read from stream: {:?}", err
                );
                Err(())
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite> Envelope for Session<T> {
    fn local_ip(&self) -> &IpAddr {
        &self.data.local_ip
    }

    fn remote_ip(&self) -> &IpAddr {
        &self.data.remote_ip
    }

    fn sender_domain(&self) -> &str {
        self.data
            .mail_from_lcase
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or_default()
    }

    fn sender(&self) -> &str {
        self.data.mail_from_lcase.as_str()
    }

    fn rcpt_domain(&self) -> &str {
        self.data
            .rcpt_to
            .last()
            .and_then(|r| r.value_lcase.as_str().rsplit_once('@'))
            .map(|(_, d)| d)
            .unwrap_or_default()
    }

    fn rcpt(&self) -> &str {
        self.data
            .rcpt_to
            .last()
            .map(|r| r.value_lcase.as_str())
            .unwrap_or_default()
    }

    fn helo_domain(&self) -> &str {
        self.data.helo_domain.as_str()
    }

    fn authenticated_as(&self) -> &str {
        self.data.authenticated_as.as_str()
    }

    fn mx(&self) -> &str {
        ""
    }

    fn listener_id(&self) -> u16 {
        self.instance.listener_id
    }

    fn priority(&self) -> i16 {
        self.data.priority
    }
}
