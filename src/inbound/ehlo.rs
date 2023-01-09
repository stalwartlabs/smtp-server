use std::time::SystemTime;

use mail_auth::SpfResult;
use smtp_proto::*;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::Session;

use super::IsTls;

impl<T: AsyncWrite + AsyncRead + IsTls + Unpin> Session<T> {
    pub async fn handle_ehlo(&mut self, domain: String) -> Result<(), ()> {
        // Set EHLO domain
        if domain != self.data.helo_domain {
            // SPF check
            if self.params.spf_ehlo.verify() {
                let spf_result = self
                    .core
                    .resolvers
                    .dns
                    .verify_spf_helo(self.data.remote_ip, &domain, &self.instance.hostname)
                    .await;

                // Reject EHLO when SPF fails in strict mode
                match spf_result.result() {
                    SpfResult::Pass => (),
                    SpfResult::TempError if self.params.spf_ehlo.is_strict() => {
                        return self
                            .write(b"451 4.7.24 Temporary SPF validation error.\r\n")
                            .await;
                    }
                    result => {
                        if self.params.spf_ehlo.is_strict() {
                            return self
                                .write(
                                    format!(
                                        "550 5.7.23 SPF validation failed, status: {}.\r\n",
                                        result
                                    )
                                    .as_bytes(),
                                )
                                .await;
                        }
                    }
                }

                self.data.spf_ehlo = spf_result.into();
            }
            self.data.helo_domain = domain;
        }

        // Reset
        if self.data.mail_from.is_some() {
            self.reset();
        }

        let mut response = EhloResponse::new(self.instance.hostname.as_str());
        response.capabilities =
            EXT_ENHANCED_STATUS_CODES | EXT_8BIT_MIME | EXT_BINARY_MIME | EXT_SMTP_UTF8;
        if !self.stream.is_tls() {
            response.capabilities |= EXT_START_TLS;
        }
        let ec = &self.core.session.config.ehlo;
        let rc = &self.core.session.config.rcpt;
        let ac = &self.core.session.config.auth;
        let dc = &self.core.session.config.data;

        // Pipelining
        if *ec.pipelining.eval(self).await {
            response.capabilities |= EXT_PIPELINING;
        }

        // Chunking
        if *ec.chunking.eval(self).await {
            response.capabilities |= EXT_CHUNKING;
        }

        // Address Expansion
        if rc.lookup_expn.eval(self).await.is_some() {
            response.capabilities |= EXT_EXPN;
        }

        // Recipient Verification
        if rc.lookup_vrfy.eval(self).await.is_some() {
            response.capabilities |= EXT_VRFY;
        }

        // Require TLS
        if *ec.requiretls.eval(self).await {
            response.capabilities |= EXT_REQUIRE_TLS;
        }

        // Authentication
        response.auth_mechanisms = *ac.mechanisms.eval(self).await;
        if response.auth_mechanisms != 0 {
            if !self.stream.is_tls() {
                response.auth_mechanisms &= !(AUTH_PLAIN | AUTH_LOGIN);
            }
            if response.auth_mechanisms != 0 {
                response.capabilities |= EXT_AUTH;
            }
        }

        // Future release
        if let Some(value) = ec.future_release.eval(self).await {
            response.capabilities |= EXT_FUTURE_RELEASE;
            response.future_release_interval = value.as_secs();
            response.future_release_datetime = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
                + value.as_secs();
        }

        // Deliver By
        if let Some(value) = ec.deliver_by.eval(self).await {
            response.capabilities |= EXT_DELIVER_BY;
            response.deliver_by = value.as_secs();
        }

        // Priority
        if let Some(value) = ec.mt_priority.eval(self).await {
            response.capabilities |= EXT_MT_PRIORITY;
            response.mt_priority = *value;
        }

        // Size
        response.size = *dc.max_message_size.eval(self).await;
        if response.size > 0 {
            response.capabilities |= EXT_SIZE;
        }

        // No soliciting
        if let Some(value) = ec.no_soliciting.eval(self).await {
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
    }
}
