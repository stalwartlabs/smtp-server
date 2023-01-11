use std::{
    path::PathBuf,
    time::{Duration, Instant, SystemTime},
};

use mail_auth::{
    common::headers::HeaderWriter, dmarc, AuthenticatedMessage, AuthenticationResults, DkimResult,
    DmarcResult, ReceivedSpf, SpfResult,
};
use mail_builder::headers::{date::Date, message_id::generate_message_id_header};
use smtp_proto::{RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    core::{Session, SessionAddress},
    queue::{self, Message, SimpleEnvelope},
};

use super::IsTls;

impl<T: AsyncWrite + AsyncRead + IsTls + Unpin> Session<T> {
    pub async fn queue_message(&mut self) -> Result<(), ()> {
        // Authenticate message
        let dc = &self.core.session.config.data;
        let ac = &self.core.mail_auth;
        let rc = &self.core.report.config;

        let auth_message =
            if let Some(auth_message) = AuthenticatedMessage::parse(&self.data.message) {
                auth_message
            } else {
                self.reset();
                return self.write(b"550 5.7.7 Failed to parse message.\r\n").await;
            };

        // Loop detection
        if auth_message.received_headers_count() > *dc.max_received_headers.eval(self).await {
            self.reset();
            return self
                .write(b"450 4.4.6 Too many Received headers. Possible loop detected.\r\n")
                .await;
        }

        // Verify DKIM
        let dkim = *ac.dkim.verify.eval(self).await;
        let dmarc = *ac.dmarc.verify.eval(self).await;
        let dkim_output = if dkim.verify() || dmarc.verify() {
            let dkim_output = self.core.resolvers.dns.verify_dkim(&auth_message).await;
            let rejected = dkim.is_strict()
                && !dkim_output
                    .iter()
                    .any(|d| matches!(d.result(), DkimResult::Pass));

            // Send reports for failed signatures
            if let Some(rate) = rc.dkim.send.eval(self).await {
                for output in &dkim_output {
                    if let Some(rcpt) = output.failure_report_addr() {
                        self.send_dkim_report(rcpt, &auth_message, rate, rejected, output)
                            .await;
                    }
                }
            }

            if rejected {
                // This violates the advice of Section 6.1 of RFC6376
                let message = if dkim_output
                    .iter()
                    .any(|d| matches!(d.result(), DkimResult::TempError(_)))
                {
                    &b"451 4.7.20 No passing DKIM signature found.\r\n"[..]
                } else {
                    &b"550 5.7.20 No passing DKIM signature found.\r\n"[..]
                };
                self.reset();
                return self.write(message).await;
            }
            dkim_output
        } else {
            vec![]
        };

        // Verify ARC
        let arc = *ac.arc.verify.eval(self).await;
        let arc_sealer = ac.arc.seal.eval(self).await;
        let arc_output = if arc.verify() || arc_sealer.is_some() {
            let arc_output = self.core.resolvers.dns.verify_arc(&auth_message).await;
            if arc.is_strict()
                && !matches!(arc_output.result(), DkimResult::Pass | DkimResult::None)
            {
                let message = if matches!(arc_output.result(), DkimResult::TempError(_)) {
                    &b"451 4.7.29 ARC validation failed.\r\n"[..]
                } else {
                    &b"550 5.7.29 ARC validation failed.\r\n"[..]
                };
                self.reset();
                return self.write(message).await;
            }
            arc_output.into()
        } else {
            None
        };

        // Build authentication results header
        let mail_from = self.data.mail_from.take().unwrap();
        let mut auth_results = AuthenticationResults::new(&self.instance.hostname);
        if !dkim_output.is_empty() {
            auth_results = auth_results.with_dkim_results(&dkim_output, auth_message.from())
        }
        if let Some(spf_ehlo) = &self.data.spf_ehlo {
            auth_results = auth_results.with_spf_ehlo_result(
                spf_ehlo,
                self.data.remote_ip,
                &self.data.helo_domain,
            );
        }
        if let Some(spf_mail_from) = &self.data.spf_mail_from {
            auth_results = auth_results.with_spf_mailfrom_result(
                spf_mail_from,
                self.data.remote_ip,
                &mail_from.address,
                &self.data.helo_domain,
            );
        }
        if let Some(iprev) = &self.data.iprev {
            auth_results = auth_results.with_iprev_result(iprev, self.data.remote_ip);
        }

        // Verify DMARC
        if dmarc.verify() && self.data.spf_mail_from.is_some() {
            let spf_output = if let Some(spf_helo) = &self.data.spf_ehlo {
                if matches!(spf_helo.result(), SpfResult::Pass) {
                    self.data.spf_mail_from.as_ref().unwrap()
                } else {
                    spf_helo
                }
            } else {
                self.data.spf_mail_from.as_ref().unwrap()
            };

            let dmarc_output = self
                .core
                .resolvers
                .dns
                .verify_dmarc(
                    &auth_message,
                    &dkim_output,
                    if !mail_from.domain.is_empty() {
                        &mail_from.domain
                    } else {
                        &self.data.helo_domain
                    },
                    spf_output,
                )
                .await;
            let rejected = dmarc.is_strict()
                && dmarc_output.policy() == dmarc::Policy::Reject
                && !matches!(
                    (dmarc_output.spf_result(), dmarc_output.dkim_result()),
                    (DmarcResult::Pass, DmarcResult::Pass)
                );
            let is_temp_fail = rejected
                && matches!(dmarc_output.spf_result(), DmarcResult::TempError(_))
                || matches!(dmarc_output.dkim_result(), DmarcResult::TempError(_));

            // Add to DMARC output to the Authentication-Results header
            auth_results = auth_results.with_dmarc_result(&dmarc_output);

            // Send DMARC report
            if dmarc_output.requested_reports() {
                self.send_dmarc_report(
                    &auth_message,
                    &auth_results,
                    rejected,
                    dmarc_output,
                    &dkim_output,
                    &arc_output,
                )
                .await;
            }

            if rejected {
                self.reset();
                return self
                    .write(if is_temp_fail {
                        &b"451 4.7.1 Email temporarily rejected per DMARC policy.\r\n"[..]
                    } else {
                        &b"550 5.7.1 Email rejected per DMARC policy.\r\n"[..]
                    })
                    .await;
            }
        }

        // Build message
        let rcpt_to = std::mem::take(&mut self.data.rcpt_to);
        let mut message = self.build_message(mail_from, rcpt_to).await;

        // Add Received header
        let mut headers = Vec::with_capacity(64);
        if *dc.add_received.eval(self).await {
            self.write_received(&mut headers, message.id)
        }

        // Add authentication results header
        if *dc.add_auth_results.eval(self).await {
            auth_results.write_header(&mut headers);
        }

        // Add Received-SPF header
        if let Some(spf_mailfrom) = &self.data.spf_mail_from {
            if *dc.add_received_spf.eval(self).await {
                let spf_output = if let Some(spf_helo) = &self.data.spf_ehlo {
                    if matches!(spf_helo.result(), SpfResult::Pass) {
                        spf_mailfrom
                    } else {
                        spf_helo
                    }
                } else {
                    spf_mailfrom
                };
                ReceivedSpf::new(
                    spf_output,
                    self.data.remote_ip,
                    &self.data.helo_domain,
                    &message.return_path,
                    &self.instance.hostname,
                )
                .write_header(&mut headers);
            }
        }

        // ARC Seal
        if let (Some(arc_sealer), Some(arc_output)) = (arc_sealer, &arc_output) {
            if !dkim_output.is_empty() && arc_output.can_be_sealed() {
                match arc_sealer.seal(&auth_message, &auth_results, arc_output) {
                    Ok(set) => {
                        set.write_header(&mut headers);
                    }
                    Err(err) => {
                        //TODO log
                    }
                }
            }
        }

        // Add any missing headers
        if !auth_message.has_date_header() && *dc.add_date.eval(self).await {
            headers.extend_from_slice(b"Date: ");
            headers.extend_from_slice(Date::now().to_rfc822().as_bytes());
            headers.extend_from_slice(b"\r\n");
        }
        if !auth_message.has_message_id_header() && *dc.add_message_id.eval(self).await {
            headers.extend_from_slice(b"Message-ID: ");
            let _ = generate_message_id_header(&mut headers, &self.instance.hostname);
            headers.extend_from_slice(b"\r\n");
        }

        // Add Return-Path
        if *dc.add_return_path.eval(self).await {
            headers.extend_from_slice(b"Return-Path: <");
            headers.extend_from_slice(message.return_path.as_bytes());
            headers.extend_from_slice(b">\r\n");
        }

        // DKIM sign
        for signer in ac.dkim.sign.eval(self).await.iter() {
            match signer.sign_chained(&[headers.as_ref(), &self.data.message]) {
                Ok(signature) => {
                    signature.write_header(&mut headers);
                }
                Err(err) => {
                    // TODO log
                }
            }
        }

        // Update size
        message.size = self.data.message.len() + headers.len();
        message.size_headers = auth_message.body_offset() + headers.len();

        // Verify queue quota
        if self.core.queue.has_quota(&mut message).await {
            let id = message.id;
            if self
                .core
                .queue
                .queue_message(
                    message,
                    vec![headers, std::mem::take(&mut self.data.message)],
                )
                .await
            {
                self.data.messages_sent += 1;
                self.write(
                    format!(
                        "250 2.0.0 Message queued for delivery with ID {:X}.\r\n",
                        id
                    )
                    .as_bytes(),
                )
                .await?;
            } else {
                self.write(b"451 4.3.5 Unable to accept message at this time.\r\n")
                    .await?;
            }
        } else {
            tracing::warn!(
                parent: &self.span,
                module = "queue",
                event = "quota-exceeded",
                "Queue quota exceeded, rejecting message."
            );
            self.write(b"452 4.3.1 Mail system full, try again later.\r\n")
                .await?;
        }

        self.reset();
        Ok(())
    }

    async fn build_message(
        &self,
        mail_from: SessionAddress,
        mut rcpt_to: Vec<SessionAddress>,
    ) -> Box<Message> {
        // Build message
        let mut message = Box::new(Message {
            id: self.core.queue.queue_id(),
            path: PathBuf::new(),
            created: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            return_path: mail_from.address,
            return_path_lcase: mail_from.address_lcase,
            return_path_domain: mail_from.domain,
            recipients: Vec::with_capacity(rcpt_to.len()),
            domains: Vec::with_capacity(3),
            flags: mail_from.flags,
            priority: self.data.priority,
            size: 0,
            size_headers: 0,
            env_id: mail_from.dsn_info,
            queue_refs: Vec::with_capacity(0),
        });

        // Add recipients
        let future_release = Duration::from_secs(self.data.future_release);
        rcpt_to.sort_unstable();
        for rcpt in rcpt_to {
            if message
                .domains
                .last()
                .map_or(true, |d| d.domain != rcpt.domain)
            {
                let envelope = SimpleEnvelope::new(message.as_ref(), &rcpt.domain);

                // Set next retry time
                let retry = if self.data.future_release == 0 {
                    queue::Schedule::now()
                } else {
                    queue::Schedule::later(future_release)
                };

                // Set expiration time
                let expires = Instant::now()
                    + if self.data.delivery_by == 0 {
                        *self.core.queue.config.expire.eval(&envelope).await
                    } else {
                        Duration::from_secs(self.data.delivery_by)
                    };

                // Set delayed notification time
                let notify = queue::Schedule::later(
                    future_release
                        + *self
                            .core
                            .queue
                            .config
                            .notify
                            .eval(&envelope)
                            .await
                            .first()
                            .unwrap(),
                );

                message.domains.push(queue::Domain {
                    retry,
                    notify,
                    expires,
                    status: queue::Status::Scheduled,
                    domain: rcpt.domain,
                    changed: false,
                });
            }

            message.recipients.push(queue::Recipient {
                address: rcpt.address,
                address_lcase: rcpt.address_lcase,
                status: queue::Status::Scheduled,
                flags: if rcpt.flags
                    & (RCPT_NOTIFY_DELAY
                        | RCPT_NOTIFY_FAILURE
                        | RCPT_NOTIFY_SUCCESS
                        | RCPT_NOTIFY_NEVER)
                    != 0
                {
                    rcpt.flags
                } else {
                    rcpt.flags | RCPT_NOTIFY_DELAY | RCPT_NOTIFY_FAILURE
                },
                domain_idx: message.domains.len() - 1,
                orcpt: rcpt.dsn_info,
            });
        }
        message
    }

    pub async fn can_send_data(&mut self) -> Result<bool, ()> {
        if !self.data.rcpt_to.is_empty() {
            if self.data.messages_sent
                < *self.core.session.config.data.max_messages.eval(self).await
            {
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

    fn write_received(&self, headers: &mut Vec<u8>, id: u64) {
        headers.extend_from_slice(b"Received: from ");
        headers.extend_from_slice(self.data.helo_domain.as_bytes());
        headers.extend_from_slice(b" (");
        headers.extend_from_slice(
            self.data
                .iprev
                .as_ref()
                .and_then(|ir| ir.ptr.as_ref())
                .and_then(|ptr| ptr.first().map(|s| s.as_str()))
                .unwrap_or("unknown")
                .as_bytes(),
        );
        headers.extend_from_slice(b" [");
        headers.extend_from_slice(self.data.remote_ip.to_string().as_bytes());
        headers.extend_from_slice(b"])\r\n\t");
        self.stream.write_tls_header(headers);
        headers.extend_from_slice(b"by ");
        headers.extend_from_slice(self.instance.hostname.as_bytes());
        headers.extend_from_slice(b" (Stalwart SMTP) with ");
        headers.extend_from_slice(
            if self.stream.is_tls() {
                "ESMTPS"
            } else {
                "ESMTP"
            }
            .as_bytes(),
        );
        headers.extend_from_slice(b" id ");
        headers.extend_from_slice(format!("{:X}", id).as_bytes());
        headers.extend_from_slice(b";\r\n\t");
        headers.extend_from_slice(Date::now().to_rfc822().as_bytes());
        headers.extend_from_slice(b"\r\n");
    }
}
