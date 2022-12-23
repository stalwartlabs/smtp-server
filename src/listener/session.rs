use std::{net::IpAddr, time::SystemTime};

use smtp_proto::{
    request::receiver::{
        BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver, LineReceiver,
        MAX_LINE_LENGTH,
    },
    *,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    config::ServerProtocol,
    core::{Envelope, RcptTo, Session, State},
};

use super::sasl::SaslToken;

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn ingest(&mut self, bytes: &[u8]) -> Result<bool, ()> {
        let mut iter = bytes.iter();
        let mut state = std::mem::replace(&mut self.state, State::None);

        'outer: loop {
            match &mut state {
                State::Request(receiver) => loop {
                    match receiver.ingest(&mut iter, bytes) {
                        Ok(request) => match request {
                            Request::Rcpt { to, parameters } => {
                                if !self.data.mail_from.is_empty() {
                                    if self.data.rcpt_to.len() < self.params.rcpt_max {
                                        if self.params.rcpt_relay || do_auth() {
                                            self.data.rcpt_to.push(RcptTo {
                                                value_lcase: to.to_lowercase(),
                                                value: to,
                                            });
                                            if self
                                                .is_allowed(&self.core.clone().config.rcpt.throttle)
                                                .await
                                            {
                                                self.eval_data_params();
                                                self.write(b"250 2.1.5 OK\r\n").await?;
                                            } else {
                                                self.data.rcpt_to.pop();
                                                self.write(b"451 4.4.5 Rate limit exceeded, try again later.\r\n").await?;
                                            }
                                        } else {
                                            tokio::time::sleep(self.params.rcpt_errors_wait).await;
                                            self.data.rcpt_errors += 1;
                                            if self.data.rcpt_errors < self.params.rcpt_errors_max {
                                                self.write(
                                                    b"550 5.1.2 Mailbox does not exist.\r\n",
                                                )
                                                .await?;
                                            } else {
                                                self.write(b"550 5.1.2 Too many RCPT errors, disconnecting.\r\n")
                                                    .await?;
                                                tracing::debug!(
                                                    parent: &self.span,
                                                    event = "disconnect",
                                                    reason = "rcpt-errors",
                                                    "Too many invalid RCPT commands."
                                                );
                                                return Err(());
                                            }
                                        }
                                    } else {
                                        self.write(b"451 4.5.3 Too many recipients.\r\n").await?;
                                    }
                                } else {
                                    self.write(b"503 5.5.1 MAIL is required first.\r\n").await?;
                                }
                            }
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
                                                self.data.mail_from = "<>".to_string();
                                            }
                                            if self
                                                .is_allowed(&self.core.clone().config.mail.throttle)
                                                .await
                                            {
                                                self.eval_rcpt_params();
                                                self.write(b"250 2.1.0 OK\r\n").await?;
                                            } else {
                                                self.data.mail_from.clear();
                                                self.data.mail_from_lcase.clear();
                                                self.write(b"451 4.4.5 Rate limit exceeded, try again later.\r\n").await?;
                                            }
                                        } else {
                                            self.write(b"530 5.7.0 Authentication required.\r\n")
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
                                if self.can_send_data().await? {
                                    self.write(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                                        .await?;
                                    self.data.message = Vec::with_capacity(1024);
                                    state = State::Data(DataReceiver::new());
                                    continue 'outer;
                                }
                            }
                            Request::Bdat {
                                chunk_size,
                                is_last,
                            } => {
                                if chunk_size + self.data.message.len()
                                    < self.params.data_max_message_size
                                {
                                    if self.data.message.is_empty() {
                                        self.data.message = Vec::with_capacity(chunk_size);
                                    } else {
                                        self.data.message.reserve(chunk_size);
                                    }
                                    state = State::Bdat(BdatReceiver::new(chunk_size, is_last));
                                } else {
                                    // Chunk is too large, ignore.
                                    state = State::DataTooLarge(DummyDataReceiver::new_bdat(
                                        chunk_size,
                                    ));
                                }
                                continue 'outer;
                            }
                            Request::Auth {
                                mechanism,
                                initial_response,
                            } => {
                                if let Some(mut token) = SaslToken::from_mechanism(
                                    mechanism & self.params.auth_mechanisms,
                                ) {
                                    if self.data.authenticated_as.is_empty() {
                                        if self
                                            .handle_sasl_response(
                                                &mut token,
                                                initial_response.as_bytes(),
                                            )
                                            .await?
                                        {
                                            state = State::Sasl(LineReceiver::new(token));
                                            continue 'outer;
                                        }
                                    } else {
                                        self.write(b"503 5.5.1 Already authenticated.\r\n").await?;
                                    }
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
                            Request::Vrfy { value } => {
                                if self.can_vrfy().await {
                                    //TODO
                                } else {
                                    self.write(b"500 5.5.1 VRFY not allowed.\r\n").await?;
                                }
                            }
                            Request::Expn { value } => {
                                if self.can_expn().await {
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
                                self.reset();
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
                                    self.eval_mail_params();
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
                            Error::ResponseTooLong => {
                                state = State::RequestTooLarge(DummyLineReceiver::default());
                                continue 'outer;
                            }
                        },
                    }
                },
                State::Data(receiver) => {
                    if self.data.message.len() + bytes.len() < self.params.data_max_message_size {
                        if receiver.ingest(&mut iter, &mut self.data.message) {
                            // TODO finish
                            self.data.messages_sent += 1;
                            self.reset();
                            self.write(b"250 2.6.0 Message accepted.\r\n").await?;
                            state = State::default();
                        } else {
                            break 'outer;
                        }
                    } else {
                        state = State::DataTooLarge(DummyDataReceiver::new_data(receiver));
                    }
                }
                State::Bdat(receiver) => {
                    if receiver.ingest(&mut iter, &mut self.data.message) {
                        if self.can_send_data().await? {
                            if receiver.is_last {
                                // TODO
                                self.data.messages_sent += 1;
                                self.reset();
                                self.write(b"250 2.6.0 Message accepted.\r\n").await?;
                            } else {
                                self.write(b"250 2.6.0 Chunk accepted.\r\n").await?;
                            }
                        } else {
                            self.data.message = Vec::with_capacity(0);
                        }
                        state = State::default();
                    } else {
                        break 'outer;
                    }
                }
                State::Sasl(receiver) => {
                    if receiver.ingest(&mut iter) {
                        if receiver.buf.len() < MAX_LINE_LENGTH {
                            if self
                                .handle_sasl_response(&mut receiver.state, &receiver.buf)
                                .await?
                            {
                                receiver.buf.clear();
                                continue 'outer;
                            }
                        } else {
                            tokio::time::sleep(self.params.auth_errors_wait).await;
                            self.write(b"500 5.5.6 Authentication Exchange line is too long.\r\n")
                                .await?;
                            if self.data.auth_errors < self.params.auth_errors_max {
                                self.data.auth_errors += 1;
                            } else {
                                return Err(());
                            }
                        }
                        state = State::default();
                    } else {
                        break 'outer;
                    }
                }
                State::DataTooLarge(receiver) => {
                    if receiver.ingest(&mut iter) {
                        self.data.message = Vec::with_capacity(0);
                        self.write(b"552 5.3.4 Message too big for system.\r\n")
                            .await?;
                        state = State::default();
                    } else {
                        break 'outer;
                    }
                }
                State::RequestTooLarge(receiver) => {
                    if receiver.ingest(&mut iter) {
                        self.write(b"554 5.3.4 Line is too long.\r\n").await?;
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
            // Set EHLO domain
            self.data.helo_domain = domain;

            // Eval mail parameters
            self.eval_mail_params();

            let mut response = EhloResponse::new(self.instance.hostname.as_str());
            response.capabilities =
                EXT_ENHANCED_STATUS_CODES | EXT_8BIT_MIME | EXT_BINARY_MIME | EXT_SMTP_UTF8;
            if self.params.starttls {
                response.capabilities |= EXT_START_TLS;
            }
            if self.params.pipelining {
                response.capabilities |= EXT_PIPELINING;
            }
            if self.params.chunking {
                response.capabilities |= EXT_CHUNKING;
            }
            if self.can_expn().await {
                response.capabilities |= EXT_EXPN;
            }
            if self.params.requiretls {
                response.capabilities |= EXT_REQUIRE_TLS;
            }
            if self.params.auth_mechanisms != 0 {
                response.capabilities |= EXT_AUTH;
                response.auth_mechanisms = self.params.auth_mechanisms;
            }
            if let Some(value) = &self.params.future_release {
                response.capabilities |= EXT_FUTURE_RELEASE;
                response.future_release_interval = value.as_secs();
                response.future_release_datetime = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    + value.as_secs();
            }
            if let Some(value) = &self.params.deliver_by {
                response.capabilities |= EXT_DELIVER_BY;
                response.deliver_by = value.as_secs();
            }
            if let Some(value) = &self.params.mt_priority {
                response.capabilities |= EXT_MT_PRIORITY;
                response.mt_priority = *value;
            }
            if let Some(value) = &self.params.size {
                response.capabilities |= EXT_SIZE;
                response.size = *value;
            }
            if let Some(value) = &self.params.no_soliciting {
                response.capabilities |= EXT_NO_SOLICITING;
                response.no_soliciting = if !value.is_empty() {
                    value.to_string().into()
                } else {
                    None
                };
            }

            // Generate response
            let mut buf = Vec::with_capacity(64);
            response.write(&mut buf).ok();
            self.write(&buf).await
        } else {
            self.write(b"503 5.5.1 Already said hello.\r\n").await
        }
    }

    fn reset(&mut self) {
        self.data.mail_from.clear();
        self.data.mail_from_lcase.clear();
        self.data.rcpt_to.clear();
        self.data.message = Vec::with_capacity(0);
        self.data.priority = 0;
    }

    async fn can_send_data(&mut self) -> Result<bool, ()> {
        if !self.data.rcpt_to.is_empty() {
            if self.data.messages_sent < self.params.data_max_messages {
                Ok(true)
            } else {
                self.write(b"451 4.4.5 Maximum number of messages per session exceeded.\r\n")
                    .await?;
                Ok(false)
            }
        } else {
            self.write(b"503 5.5.1 RCPT is required first.\r\n").await?;
            Ok(false)
        }
    }

    #[inline(always)]
    async fn can_expn(&self) -> bool {
        *self.core.config.expn.enable.eval(self).await
    }

    #[inline(always)]
    async fn can_vrfy(&self) -> bool {
        *self.core.config.vrfy.enable.eval(self).await
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

fn do_auth() -> bool {
    let coco = "fdf";
    false
}

impl<T: AsyncRead + AsyncWrite> Envelope for Session<T> {
    #[inline(always)]
    fn local_ip(&self) -> &IpAddr {
        &self.data.local_ip
    }

    #[inline(always)]
    fn remote_ip(&self) -> &IpAddr {
        &self.data.remote_ip
    }

    #[inline(always)]
    fn sender_domain(&self) -> &str {
        self.data
            .mail_from_lcase
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or_default()
    }

    #[inline(always)]
    fn sender(&self) -> &str {
        self.data.mail_from_lcase.as_str()
    }

    #[inline(always)]
    fn rcpt_domain(&self) -> &str {
        self.data
            .rcpt_to
            .last()
            .and_then(|r| r.value_lcase.as_str().rsplit_once('@'))
            .map(|(_, d)| d)
            .unwrap_or_default()
    }

    #[inline(always)]
    fn rcpt(&self) -> &str {
        self.data
            .rcpt_to
            .last()
            .map(|r| r.value_lcase.as_str())
            .unwrap_or_default()
    }

    #[inline(always)]
    fn helo_domain(&self) -> &str {
        self.data.helo_domain.as_str()
    }

    #[inline(always)]
    fn authenticated_as(&self) -> &str {
        self.data.authenticated_as.as_str()
    }

    #[inline(always)]
    fn mx(&self) -> &str {
        ""
    }

    #[inline(always)]
    fn listener_id(&self) -> u16 {
        self.instance.listener_id
    }

    #[inline(always)]
    fn priority(&self) -> i16 {
        self.data.priority
    }
}
