use std::time::SystemTime;

use smtp_proto::*;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::Session;

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn handle_ehlo(&mut self, domain: String) -> Result<(), ()> {
        // Set EHLO domain
        if domain != self.data.helo_domain {
            self.data.helo_domain = domain;

            // Eval mail parameters
            self.eval_mail_params().await;
        }

        // Reset
        if self.data.mail_from.is_some() {
            self.reset();
        }

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
        if self.params.expn {
            response.capabilities |= EXT_EXPN;
        }
        if self.params.vrfy {
            response.capabilities |= EXT_VRFY;
        }
        if self.params.requiretls {
            response.capabilities |= EXT_REQUIRE_TLS;
        }
        if self.params.auth != 0 {
            response.capabilities |= EXT_AUTH;
            response.auth_mechanisms = self.params.auth;
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
    }
}
