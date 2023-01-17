use mail_builder::headers::content_type::ContentType;
use mail_builder::headers::HeaderType;
use mail_builder::mime::{make_boundary, BodyPart, MimePart};
use mail_builder::MessageBuilder;
use mail_parser::DateTime;
use smtp_proto::{
    Response, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS,
};
use std::fmt::Write;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::AsyncReadExt;

use crate::config::QueueConfig;
use crate::core::QueueCore;

use super::{
    instant_to_timestamp, DeliveryAttempt, Domain, Error, ErrorDetails, HostResponse, Message,
    Recipient, SimpleEnvelope, Status, RCPT_DSN_SENT, RCPT_STATUS_CHANGED,
};

impl QueueCore {
    pub async fn send_dsn(&self, attempt: &mut DeliveryAttempt) {
        if !attempt.message.return_path.is_empty() {
            if let Some(dsn) = attempt.build_dsn(&self.config).await {
                let mut dsn_message = Message::new_boxed("", "", "");
                dsn_message
                    .add_recipient(
                        &attempt.message.return_path,
                        &attempt.message.return_path_lcase,
                        &attempt.message.return_path_domain,
                        &self.config,
                    )
                    .await;

                // Sign message
                let signature = attempt
                    .message
                    .sign(&self.config.dsn.sign, &dsn, &attempt.span)
                    .await;
                self.queue_message(dsn_message, signature.as_deref(), &dsn, &attempt.span)
                    .await;
            }
        } else {
            attempt.handle_double_bounce();
        }
    }
}

impl DeliveryAttempt {
    async fn build_dsn(&mut self, config: &QueueConfig) -> Option<Vec<u8>> {
        let now = Instant::now();

        let mut txt_success = String::new();
        let mut txt_delay = String::new();
        let mut txt_failed = String::new();
        let mut dsn = String::new();

        for rcpt in &mut self.message.recipients {
            if rcpt.has_flag(RCPT_DSN_SENT | RCPT_NOTIFY_NEVER) {
                continue;
            }
            let domain = &self.message.domains[rcpt.domain_idx];
            match &rcpt.status {
                Status::Completed(response) => {
                    rcpt.flags |= RCPT_DSN_SENT | RCPT_STATUS_CHANGED;
                    if !rcpt.has_flag(RCPT_NOTIFY_SUCCESS) {
                        continue;
                    }
                    rcpt.write_dsn(&mut dsn);
                    rcpt.status.write_dsn(&mut dsn);
                    response.write_dsn_text(&rcpt.address, &mut txt_success);
                }
                Status::TemporaryFailure(response)
                    if domain.notify.due <= now && rcpt.has_flag(RCPT_NOTIFY_DELAY) =>
                {
                    rcpt.write_dsn(&mut dsn);
                    rcpt.status.write_dsn(&mut dsn);
                    domain.write_dsn_will_retry_until(&mut dsn);
                    response.write_dsn_text(&rcpt.address, &mut txt_delay);
                }
                Status::PermanentFailure(response) => {
                    rcpt.flags |= RCPT_DSN_SENT | RCPT_STATUS_CHANGED;
                    if !rcpt.has_flag(RCPT_NOTIFY_FAILURE) {
                        continue;
                    }
                    rcpt.write_dsn(&mut dsn);
                    rcpt.status.write_dsn(&mut dsn);
                    response.write_dsn_text(&rcpt.address, &mut txt_failed);
                }
                Status::Scheduled => {
                    // There is no status for this address, use the domain's status.
                    match &domain.status {
                        Status::PermanentFailure(err) => {
                            rcpt.flags |= RCPT_DSN_SENT | RCPT_STATUS_CHANGED;
                            if !rcpt.has_flag(RCPT_NOTIFY_FAILURE) {
                                continue;
                            }
                            rcpt.write_dsn(&mut dsn);
                            domain.status.write_dsn(&mut dsn);
                            err.write_dsn_text(&rcpt.address, &domain.domain, &mut txt_failed);
                        }
                        Status::TemporaryFailure(err)
                            if domain.notify.due <= now && rcpt.has_flag(RCPT_NOTIFY_DELAY) =>
                        {
                            rcpt.write_dsn(&mut dsn);
                            domain.status.write_dsn(&mut dsn);
                            domain.write_dsn_will_retry_until(&mut dsn);
                            err.write_dsn_text(&rcpt.address, &domain.domain, &mut txt_delay);
                        }
                        Status::Scheduled
                            if domain.notify.due <= now && rcpt.has_flag(RCPT_NOTIFY_DELAY) =>
                        {
                            // This case should not happen under normal circumstances
                            rcpt.write_dsn(&mut dsn);
                            domain.status.write_dsn(&mut dsn);
                            domain.write_dsn_will_retry_until(&mut dsn);
                            Error::ConcurrencyLimited.write_dsn_text(
                                &rcpt.address,
                                &domain.domain,
                                &mut txt_delay,
                            );
                        }
                        Status::Completed(_) => {
                            #[cfg(test)]
                            panic!("This should not have happened.");
                        }
                        _ => continue,
                    }
                }
                _ => continue,
            }

            dsn.push_str("\r\n");
        }

        // Build text response
        let txt_len = txt_success.len() + txt_delay.len() + txt_failed.len();
        if txt_len == 0 {
            return None;
        }

        let has_success = !txt_success.is_empty();
        let has_delay = !txt_delay.is_empty();
        let has_failure = !txt_failed.is_empty();

        let mut txt = String::with_capacity(txt_len + 128);
        let (subject, is_mixed) = if has_success && !has_delay && !has_failure {
            txt.push_str(
                "Your message has been successfully delivered to the following recipients:\r\n\r\n",
            );
            ("Successfully delivered message", false)
        } else if has_delay && !has_success && !has_failure {
            txt.push_str("There was a temporary problem delivering your message to the following recipients:\r\n\r\n");
            ("Warning: Delay in message delivery", false)
        } else if has_failure && !has_success && !has_delay {
            txt.push_str(
                "Your message could not be delivered to the following recipients:\r\n\r\n",
            );
            ("Failed to deliver message", false)
        } else if has_success {
            txt.push_str("Your message has been partially delivered:\r\n\r\n");
            ("Partially delivered message", true)
        } else {
            txt.push_str("Your message could not be delivered to some recipients:\r\n\r\n");
            (
                "Warning: Temporary and permanent failures during message delivery",
                true,
            )
        };

        if has_success {
            if is_mixed {
                txt.push_str(
                    "    ----- Delivery to the following addresses was succesful -----\r\n",
                );
            }

            txt.push_str(&txt_success);
            txt.push_str("\r\n");
        }

        if has_delay {
            if is_mixed {
                txt.push_str(
                    "    ----- There was a temporary problem delivering to these addresses -----\r\n",
                );
            }
            txt.push_str(&txt_delay);
            txt.push_str("\r\n");
        }

        if has_failure {
            if is_mixed {
                txt.push_str("    ----- Delivery to the following addresses failed -----\r\n");
            }
            txt.push_str(&txt_failed);
            txt.push_str("\r\n");
        }

        // Update next delay notification time
        if has_delay {
            let mut domains = std::mem::take(&mut self.message.domains);
            for domain in &mut domains {
                if domain.notify.due <= now {
                    let envelope = SimpleEnvelope::new(&self.message, &domain.domain);

                    if let Some(next_notify) = config
                        .notify
                        .eval(&envelope)
                        .await
                        .get((domain.notify.inner + 1) as usize)
                    {
                        domain.notify.inner += 1;
                        domain.notify.due = Instant::now() + *next_notify;
                    } else {
                        domain.notify.due = domain.expires + Duration::from_secs(10);
                    }
                    domain.changed = true;
                }
            }
            self.message.domains = domains;
        }

        // Obtain hostname and sender addresses
        let from_name = config.dsn.name.eval(self.message.as_ref()).await;
        let from_addr = config.dsn.address.eval(self.message.as_ref()).await;
        let reporting_mta = config.hostname.eval(self.message.as_ref()).await;

        // Prepare DSN
        let mut dsn_header = String::with_capacity(dsn.len() + 128);
        self.message
            .write_dsn_headers(&mut dsn_header, reporting_mta);
        let dsn = dsn_header + &dsn;

        // Fetch message headers
        let headers = match File::open(&self.message.path).await {
            Ok(mut file) => {
                let mut buf = vec![0u8; self.message.size_headers];
                if let Err(err) = file.read_exact(&mut buf).await {
                    tracing::error!(
                        parent: &self.span,
                        context = "queue",
                        event = "error",
                        "Failed to read {} bytes from {}: {}",
                        self.message.size_headers,
                        self.message.path.display(),
                        err
                    );
                    String::new()
                } else {
                    String::from_utf8(buf).unwrap_or_default()
                }
            }
            Err(err) => {
                tracing::error!(
                    parent: &self.span,
                    context = "queue",
                    event = "error",
                    "Failed to open file {}: {}",
                    self.message.path.display(),
                    err
                );
                String::new()
            }
        };

        // Build message
        MessageBuilder::new()
            .from((from_name.as_str(), from_addr.as_str()))
            .header(
                "To",
                HeaderType::Text(self.message.return_path.as_str().into()),
            )
            .header("Auto-Submitted", HeaderType::Text("auto-generated".into()))
            .message_id(format!("<{}@{}>", make_boundary("."), reporting_mta))
            .subject(subject)
            .body(MimePart::new(
                ContentType::new("multipart/report").attribute("report-type", "delivery-status"),
                BodyPart::Multipart(vec![
                    MimePart::new(ContentType::new("text/plain"), BodyPart::Text(txt.into())),
                    MimePart::new(
                        ContentType::new("message/delivery-status"),
                        BodyPart::Text(dsn.into()),
                    ),
                    MimePart::new(
                        ContentType::new("message/rfc822"),
                        BodyPart::Text(headers.into()),
                    ),
                ]),
            ))
            .write_to_vec()
            .unwrap_or_default()
            .into()
    }

    fn handle_double_bounce(&mut self) {
        let mut is_double_bounce = Vec::with_capacity(0);
        let message = &mut self.message;

        for rcpt in &mut message.recipients {
            if !rcpt.has_flag(RCPT_DSN_SENT | RCPT_NOTIFY_NEVER) {
                match &rcpt.status {
                    Status::PermanentFailure(err) => {
                        rcpt.flags |= RCPT_DSN_SENT;
                        let mut dsn = String::new();
                        err.write_dsn_text(&rcpt.address, &mut dsn);
                        is_double_bounce.push(dsn);
                    }
                    Status::Scheduled => {
                        let domain = &message.domains[rcpt.domain_idx];
                        if let Status::PermanentFailure(err) = &domain.status {
                            rcpt.flags |= RCPT_DSN_SENT;
                            let mut dsn = String::new();
                            err.write_dsn_text(&rcpt.address, &domain.domain, &mut dsn);
                            is_double_bounce.push(dsn);
                        }
                    }
                    _ => (),
                }
            }
        }

        let now = Instant::now();
        for domain in &mut message.domains {
            if domain.notify.due <= now {
                domain.notify.due = domain.expires + Duration::from_secs(10);
            }
        }

        if !is_double_bounce.is_empty() {
            tracing::info!(
                parent: &self.span,
                context = "queue",
                event = "double-bounce",
                id = self.message.id,
                failures = ?is_double_bounce,
                "Failed delivery of message with null return path.",
            );
        }
    }
}

impl HostResponse<String> {
    fn write_dsn_text(&self, addr: &str, dsn: &mut String) {
        let _ = write!(
            dsn,
            "<{}> (delivered to '{}' with code {} ({}.{}.{}) '",
            addr,
            self.hostname,
            self.response.code,
            self.response.esc[0],
            self.response.esc[1],
            self.response.esc[2]
        );
        self.response.write_response(dsn);
        dsn.push_str("')\r\n");
    }
}

impl HostResponse<ErrorDetails> {
    fn write_dsn_text(&self, addr: &str, dsn: &mut String) {
        let _ = write!(dsn, "<{}> (host '{}' rejected ", addr, self.hostname.entity);

        if !self.hostname.details.is_empty() {
            let _ = write!(dsn, "command '{}'", self.hostname.details,);
        } else {
            dsn.push_str("transaction");
        }

        let _ = write!(
            dsn,
            " with code {} ({}.{}.{}) '",
            self.response.code, self.response.esc[0], self.response.esc[1], self.response.esc[2]
        );
        self.response.write_response(dsn);
        dsn.push_str("')\r\n");
    }
}

impl Error {
    fn write_dsn_text(&self, addr: &str, domain: &str, dsn: &mut String) {
        match self {
            Error::UnexpectedResponse(response) => {
                response.write_dsn_text(addr, dsn);
            }
            Error::DnsError(err) => {
                let _ = write!(
                    dsn,
                    "<{}> (failed to lookup '{}': {})\r\n",
                    addr, domain, err
                );
            }
            Error::ConnectionError(details) => {
                let _ = write!(
                    dsn,
                    "<{}> (connection to '{}' failed: {})\r\n",
                    addr, details.entity, details.details
                );
            }
            Error::TlsError(details) => {
                let _ = write!(
                    dsn,
                    "<{}> (TLS error from '{}': {})\r\n",
                    addr, details.entity, details.details
                );
            }
            Error::DaneError(details) => {
                let _ = write!(
                    dsn,
                    "<{}> (DANE failed to authenticate '{}': {})\r\n",
                    addr, details.entity, details.details
                );
            }
            Error::MtaStsError(details) => {
                let _ = write!(
                    dsn,
                    "<{}> (MTA-STS failed to authenticate '{}': {})\r\n",
                    addr, domain, details
                );
            }
            Error::RateLimited => {
                let _ = write!(dsn, "<{}> (rate limited)\r\n", addr);
            }
            Error::ConcurrencyLimited => {
                let _ = write!(
                    dsn,
                    "<{}> (too many concurrent connections to remote server)\r\n",
                    addr
                );
            }
            Error::Io(err) => {
                let _ = write!(dsn, "<{}> (queue error: {})\r\n", addr, err);
            }
        }
    }
}

impl Message {
    fn write_dsn_headers(&self, dsn: &mut String, reporting_mta: &str) {
        let _ = write!(dsn, "Reporting-MTA: dns;{}\r\n", reporting_mta);
        dsn.push_str("Arrival-Date: ");
        dsn.push_str(&DateTime::from_timestamp(self.created as i64).to_rfc822());
        dsn.push_str("\r\n");
        if let Some(env_id) = &self.env_id {
            let _ = write!(dsn, "Original-Envelope-Id: {}\r\n", env_id);
        }
        dsn.push_str("\r\n");
    }
}

impl Recipient {
    fn write_dsn(&self, dsn: &mut String) {
        if let Some(orcpt) = &self.orcpt {
            let _ = write!(dsn, "Original-Recipient: rfc822;{}\r\n", orcpt);
        }
        let _ = write!(dsn, "Final-Recipient: rfc822;{}\r\n", self.address);
    }
}

impl Domain {
    fn write_dsn_will_retry_until(&self, dsn: &mut String) {
        let now = Instant::now();
        if self.expires > now {
            dsn.push_str("Will-Retry-Until: ");
            dsn.push_str(
                &DateTime::from_timestamp(instant_to_timestamp(now, self.expires) as i64)
                    .to_rfc822(),
            );
            dsn.push_str("\r\n");
        }
    }
}

impl<T, E> Status<T, E> {
    fn write_dsn_action(&self, dsn: &mut String) {
        dsn.push_str("Action: ");
        dsn.push_str(match self {
            Status::Completed(_) => "delivered",
            Status::PermanentFailure(_) => "failed",
            Status::TemporaryFailure(_) | Status::Scheduled => "delayed",
        });
        dsn.push_str("\r\n");
    }
}

impl Status<HostResponse<String>, HostResponse<ErrorDetails>> {
    fn write_dsn(&self, dsn: &mut String) {
        self.write_dsn_action(dsn);
        self.write_dsn_status(dsn);
        self.write_dsn_diagnostic(dsn);
        self.write_dsn_remote_mta(dsn);
    }

    fn write_dsn_status(&self, dsn: &mut String) {
        dsn.push_str("Status: ");
        if let Status::Completed(HostResponse { response, .. })
        | Status::PermanentFailure(HostResponse { response, .. })
        | Status::TemporaryFailure(HostResponse { response, .. }) = self
        {
            response.write_dsn_status(dsn);
        }
        dsn.push_str("\r\n");
    }

    fn write_dsn_remote_mta(&self, dsn: &mut String) {
        dsn.push_str("Remote-MTA: dns;");
        if let Status::Completed(HostResponse { hostname, .. })
        | Status::PermanentFailure(HostResponse {
            hostname: ErrorDetails {
                entity: hostname, ..
            },
            ..
        })
        | Status::TemporaryFailure(HostResponse {
            hostname: ErrorDetails {
                entity: hostname, ..
            },
            ..
        }) = self
        {
            dsn.push_str(hostname);
        }
        dsn.push_str("\r\n");
    }

    fn write_dsn_diagnostic(&self, dsn: &mut String) {
        if let Status::PermanentFailure(details) | Status::TemporaryFailure(details) = self {
            details.response.write_dsn_diagnostic(dsn);
        }
    }
}

impl Status<(), Error> {
    fn write_dsn(&self, dsn: &mut String) {
        self.write_dsn_action(dsn);
        self.write_dsn_status(dsn);
        self.write_dsn_diagnostic(dsn);
        self.write_dsn_remote_mta(dsn);
    }

    fn write_dsn_status(&self, dsn: &mut String) {
        if let Status::PermanentFailure(err) | Status::TemporaryFailure(err) = self {
            dsn.push_str("Status: ");
            if let Error::UnexpectedResponse(response) = err {
                response.response.write_dsn_status(dsn);
            } else {
                dsn.push_str(if matches!(self, Status::PermanentFailure(_)) {
                    "5.0.0"
                } else {
                    "4.0.0"
                });
            }
            dsn.push_str("\r\n");
        }
    }

    fn write_dsn_remote_mta(&self, dsn: &mut String) {
        if let Status::PermanentFailure(err) | Status::TemporaryFailure(err) = self {
            match err {
                Error::UnexpectedResponse(HostResponse {
                    hostname: details, ..
                })
                | Error::ConnectionError(details)
                | Error::TlsError(details)
                | Error::DaneError(details) => {
                    dsn.push_str("Remote-MTA: dns;");
                    dsn.push_str(&details.entity);
                    dsn.push_str("\r\n");
                }
                _ => (),
            }
        }
    }

    fn write_dsn_diagnostic(&self, dsn: &mut String) {
        if let Status::PermanentFailure(Error::UnexpectedResponse(response))
        | Status::TemporaryFailure(Error::UnexpectedResponse(response)) = self
        {
            response.response.write_dsn_diagnostic(dsn);
        }
    }
}

impl WriteDsn for Response<String> {
    fn write_dsn_status(&self, dsn: &mut String) {
        if self.esc[0] > 0 {
            let _ = write!(dsn, "{}.{}.{}", self.esc[0], self.esc[1], self.esc[2]);
        } else {
            let _ = write!(
                dsn,
                "{}.{}.{}",
                self.code / 100,
                (self.code / 10) % 10,
                self.code % 10
            );
        }
    }

    fn write_dsn_diagnostic(&self, dsn: &mut String) {
        let _ = write!(dsn, "Diagnostic-Code: smtp;{} ", self.code);
        self.write_response(dsn);
        dsn.push_str("\r\n");
    }

    fn write_response(&self, dsn: &mut String) {
        for ch in self.message.chars() {
            if ch != '\n' && ch != '\r' {
                dsn.push(ch);
            }
        }
    }
}

trait WriteDsn {
    fn write_dsn_status(&self, dsn: &mut String);
    fn write_dsn_diagnostic(&self, dsn: &mut String);
    fn write_response(&self, dsn: &mut String);
}

#[cfg(test)]
mod test {
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, Instant, SystemTime},
    };

    use smtp_proto::{Response, RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_SUCCESS};

    use crate::{
        config::QueueConfig,
        queue::{
            DeliveryAttempt, Domain, Error, ErrorDetails, HostResponse, Message, Recipient,
            Schedule, Status,
        },
    };

    #[tokio::test]
    async fn generate_dsn() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("resources");
        path.push("tests");
        path.push("dsn");
        path.push("original.txt");
        let size = fs::metadata(&path).unwrap().len() as usize;

        let flags = RCPT_NOTIFY_FAILURE | RCPT_NOTIFY_DELAY | RCPT_NOTIFY_SUCCESS;
        let message = Box::new(Message {
            size_headers: size,
            size,
            id: 0,
            path,
            created: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            return_path: "sender@foobar.org".to_string(),
            return_path_lcase: "".to_string(),
            return_path_domain: "foobar.org".to_string(),
            recipients: vec![Recipient {
                domain_idx: 0,
                address: "foobar@example.org".to_string(),
                address_lcase: "foobar@example.org".to_string(),
                status: Status::PermanentFailure(HostResponse {
                    hostname: ErrorDetails {
                        entity: "mx.example.org".to_string(),
                        details: "RCPT TO:<foobar@example.org>".to_string(),
                    },
                    response: Response {
                        code: 550,
                        esc: [5, 1, 2],
                        message: "User does not exist".to_string(),
                    },
                }),
                flags: 0,
                orcpt: None,
            }],
            domains: vec![Domain {
                domain: "example.org".to_string(),
                retry: Schedule::now(),
                notify: Schedule::now(),
                expires: Instant::now() + Duration::from_secs(10),
                status: Status::TemporaryFailure(Error::ConnectionError(ErrorDetails {
                    entity: "mx.domain.org".to_string(),
                    details: "Connection timeout".to_string(),
                })),
                changed: false,
            }],
            flags: 0,
            env_id: None,
            priority: 0,

            queue_refs: vec![],
        });
        let mut attempt = DeliveryAttempt {
            span: tracing::span!(tracing::Level::INFO, "hi"),
            message,
            in_flight: vec![],
        };
        let config = QueueConfig::test();

        // Disabled DSN
        assert!(attempt.build_dsn(&config).await.is_none());

        // Failure DSN
        attempt.message.recipients[0].flags = flags;
        compare_dsn(&mut attempt, &config, "failure.eml").await;

        // Success DSN
        attempt.message.recipients.push(Recipient {
            domain_idx: 0,
            address: "jane@example.org".to_string(),
            address_lcase: "jane@example.org".to_string(),
            status: Status::Completed(HostResponse {
                hostname: "mx2.example.org".to_string(),
                response: Response {
                    code: 250,
                    esc: [2, 1, 5],
                    message: "Message accepted for delivery".to_string(),
                },
            }),
            flags,
            orcpt: None,
        });
        compare_dsn(&mut attempt, &config, "success.eml").await;

        // Delay DSN
        attempt.message.recipients.push(Recipient {
            domain_idx: 0,
            address: "john.doe@example.org".to_string(),
            address_lcase: "john.doe@example.org".to_string(),
            status: Status::Scheduled,
            flags,
            orcpt: "jdoe@example.org".to_string().into(),
        });
        compare_dsn(&mut attempt, &config, "delay.eml").await;

        // Mixed DSN
        for rcpt in &mut attempt.message.recipients {
            rcpt.flags = flags;
        }
        attempt.message.domains[0].notify.due = Instant::now();
        compare_dsn(&mut attempt, &config, "mixed.eml").await;
    }

    async fn compare_dsn(attempt: &mut DeliveryAttempt, config: &QueueConfig, test: &str) {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("resources");
        path.push("tests");
        path.push("dsn");
        path.push(test);

        let dsn = remove_ids(attempt.build_dsn(config).await.unwrap());
        let dsn_expected = fs::read_to_string(&path).unwrap();

        //fs::write(&path, dsn.as_bytes()).unwrap();
        assert_eq!(dsn, dsn_expected, "Failed for {}", path.display());
    }

    fn remove_ids(message: Vec<u8>) -> String {
        let old_message = String::from_utf8(message).unwrap();
        let mut message = String::with_capacity(old_message.len());

        let mut boundary = "";
        for line in old_message.split("\r\n") {
            if line.starts_with("Date:") || line.starts_with("Message-ID:") {
                continue;
            } else if line.starts_with("--") {
                message.push_str(&line.replace(boundary, "mime_boundary"));
            } else if let Some((_, boundary_)) = line.split_once("boundary=\"") {
                boundary = boundary_.split_once('"').unwrap().0;
                message.push_str(&line.replace(boundary, "mime_boundary"));
            } else if line.starts_with("Arrival-Date:") {
                message.push_str("Arrival-Date: <date goes here>");
            } else if line.starts_with("Will-Retry-Until:") {
                message.push_str("Will-Retry-Until: <date goes here>");
            } else {
                message.push_str(line);
            }
            message.push_str("\r\n");
        }
        message
    }
}
