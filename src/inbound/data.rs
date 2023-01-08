use std::{
    path::PathBuf,
    time::{Duration, Instant, SystemTime},
};

use smtp_proto::{RCPT_NOTIFY_DELAY, RCPT_NOTIFY_FAILURE, RCPT_NOTIFY_NEVER, RCPT_NOTIFY_SUCCESS};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    core::Session,
    queue::{self, Message, SimpleEnvelope},
};

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn queue_message(&mut self) -> Result<(), ()> {
        // Build message
        let mail_from = self.data.mail_from.take().unwrap();
        let mut message = Box::new(Message {
            id: 0,
            path: PathBuf::new(),
            created: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            return_path: mail_from.address,
            return_path_lcase: mail_from.address_lcase,
            return_path_domain: mail_from.domain,
            recipients: Vec::with_capacity(self.data.rcpt_to.len()),
            domains: Vec::with_capacity(3),
            flags: mail_from.flags,
            priority: self.data.priority,
            size: self.data.message.len(),
            size_headers: self.data.message.len(),
            env_id: mail_from.dsn_info,
            queue_refs: Vec::with_capacity(0),
        });

        // Parse message
        let coco = "parse";
        //message.size_headers = ...;

        let future_release = Duration::from_secs(self.data.future_release);

        // Add recipients
        self.data.rcpt_to.sort_unstable();
        for rcpt in self.data.rcpt_to.drain(..) {
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

        // Verify queue quota
        if self.core.queue.has_quota(&mut message).await {
            if self
                .core
                .queue
                .queue_message(message, std::mem::take(&mut self.data.message))
                .await
            {
                self.data.messages_sent += 1;
                self.write(b"250 2.0.0 Message queued for delivery.\r\n")
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

    pub async fn can_send_data(&mut self) -> Result<bool, ()> {
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
}

/*

Received: from open.nlnet.nl (open.nlnet.nl [IPv6:2a04:b900::1:0:0:12])
    (using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
     key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
    (No client certificate requested)
    by mail.stalw.art (Postfix) with ESMTPS id 1BC637CF44
    for <mauro@stalw.art>; Wed,  4 Jan 2023 20:33:01 +0000 (UTC)

*/
