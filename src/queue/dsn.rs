use mail_parser::DateTime;
use smtp_proto::{Response, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS};
use std::fmt::Write;
use std::time::{Duration, Instant, SystemTime};

use crate::core::QueueCore;

use super::{
    Domain, Error, ErrorDetails, HostResponse, Message, Recipient, SimpleEnvelope, Status,
    RCPT_DSN_SENT,
};

impl QueueCore {
    pub async fn send_dsn(&self, message: &mut Message) {
        let now = Instant::now();

        let mut txt_success = String::new();
        let mut txt_delay = String::new();
        let mut txt_failed = String::new();
        let mut dsn = String::new();

        for rcpt in &mut message.recipients {
            if rcpt.has_flag(RCPT_DSN_SENT | RCPT_NOTIFY_NEVER) {
                continue;
            }
            let domain = &mut message.domains[rcpt.domain_idx];
            match &rcpt.status {
                Status::Completed(response) => {
                    rcpt.flags |= RCPT_DSN_SENT;
                    if !rcpt.has_flag(RCPT_NOTIFY_SUCCESS) {
                        continue;
                    }
                    rcpt.write_dsn(&mut dsn);
                    rcpt.status.write_dsn(&mut dsn);
                    response.write_dsn_text(&rcpt.address, &mut txt_success);
                }
                Status::TemporaryFailure(response) if domain.notify.due <= now => {
                    rcpt.write_dsn(&mut dsn);
                    rcpt.status.write_dsn(&mut dsn);
                    domain.write_dsn_will_retry_until(&mut dsn);
                    response.write_dsn_text(&rcpt.address, &mut txt_delay);
                }
                Status::PermanentFailure(response) => {
                    rcpt.flags |= RCPT_DSN_SENT;
                    rcpt.write_dsn(&mut dsn);
                    rcpt.status.write_dsn(&mut dsn);
                    response.write_dsn_text(&rcpt.address, &mut txt_failed);
                }
                Status::Scheduled => {
                    // There is no status for this address, use the domain's status.
                    match &domain.status {
                        Status::PermanentFailure(err) => {
                            rcpt.write_dsn(&mut dsn);
                            domain.status.write_dsn(&mut dsn);
                            err.write_dsn_text(&rcpt.address, &domain.domain, &mut txt_failed);
                            rcpt.flags |= RCPT_DSN_SENT;
                        }
                        Status::TemporaryFailure(err) if domain.notify.due <= now => {
                            rcpt.write_dsn(&mut dsn);
                            domain.status.write_dsn(&mut dsn);
                            domain.write_dsn_will_retry_until(&mut dsn);
                            err.write_dsn_text(&rcpt.address, &domain.domain, &mut txt_delay);
                        }
                        Status::Scheduled if domain.notify.due <= now => {
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
            return;
        }
        let has_success = !txt_success.is_empty();
        let has_delay = !txt_delay.is_empty();
        let has_failure = !txt_failed.is_empty();

        let mut txt = String::with_capacity(txt_len + 128);
        let is_mixed = if has_success && !has_delay && !has_failure {
            txt.push_str(
                "Your message has been successfully delivered to the following recipients:\r\n\r\n",
            );
            false
        } else if has_delay && !has_success && !has_failure {
            txt.push_str("There has been a delay delivering your message to the following recipients:\r\n\r\n");
            false
        } else if has_failure && !has_success && !has_delay {
            txt.push_str(
                "Your message could not be delivered to the following recipients:\r\n\r\n",
            );
            false
        } else if has_success {
            txt.push_str("Your message has been partially delivered:\r\n\r\n");
            true
        } else {
            txt.push_str("Your message could not be delivered to some recipients:\r\n\r\n");
            true
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
                    "    ----- There has been a delay delivering to these addresses -----\r\n",
                );
            }
            txt.push_str(&txt_delay);
            txt.push_str("\r\n");
        }

        if has_delay {
            if is_mixed {
                txt.push_str("    ----- Delivery to the following addresses failed -----\r\n");
            }
            txt.push_str(&txt_failed);
            txt.push_str("\r\n");
        }

        // Update next delay notification time
        if has_delay {
            let mut domains = std::mem::take(&mut message.domains);
            for domain in &mut domains {
                if domain.notify.due <= now {
                    let envelope = SimpleEnvelope::new(message, &domain.domain);

                    if let Some(next_notify) = self
                        .config
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
                }
            }
            message.domains = domains;
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
                &DateTime::from_timestamp(
                    (SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                        + self.expires.duration_since(now).as_secs()) as i64,
                )
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
