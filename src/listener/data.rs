use std::time::SystemTime;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    core::Session,
    queue::{self, Message},
};

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn queue_message(&mut self) -> Result<(), ()> {
        // Build message
        let mail_from = self.data.mail_from.take().unwrap();
        let mut message = Box::new(Message {
            id: 0,
            created: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            return_path: mail_from.address,
            return_path_lcase: mail_from.address_lcase,
            return_path_domain: mail_from.domain,
            recipients: Vec::with_capacity(self.data.rcpt_to.len()),
            domains: Vec::with_capacity(3),
            notify: queue::Schedule::now(),
            flags: 0,
            priority: self.data.priority,
            size: self.data.message.len(),
            queue_refs: Vec::with_capacity(0),
        });

        // Add recipients
        self.data.rcpt_to.sort_unstable();
        for rcpt in self.data.rcpt_to.drain(..) {
            if message
                .domains
                .last()
                .map_or(true, |d| d.domain != rcpt.domain)
            {
                message.domains.push(queue::Domain {
                    domain: rcpt.domain,
                    retry: queue::Schedule::now(),
                    status: queue::Status::Scheduled,
                    queue_refs: Vec::new(),
                });
            }
            message.recipients.push(queue::Recipient {
                address: rcpt.address,
                address_lcase: rcpt.address_lcase,
                status: queue::Status::Scheduled,
                flags: 0,
                queue_refs: Vec::new(),
                domain_idx: message.domains.len() - 1,
            });
        }

        // Verify queue capacity
        if self.core.queue.queue_has_capacity(&mut message).await {
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
                event = "queue",
                class = "capacity-exceeded",
                "Queue capacity exceeded, rejecting message."
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
