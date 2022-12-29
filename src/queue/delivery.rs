use std::{sync::Arc, time::Instant};

use crate::core::Core;

use super::{manager::Queue, throttle, DeliveryAttempt, Message, OnHold, Schedule, Status};

impl DeliveryAttempt {
    pub async fn try_deliver(mut self, core: Arc<Core>, queue: &mut Queue) {
        // Throttle sender
        if !core.queue.config.throttle.sender.is_empty() {
            if let Err(err) = core.queue.throttle_sender(&mut self).await {
                match err {
                    throttle::Error::Concurrency { limiter } => {
                        queue.on_hold.push(OnHold {
                            max_concurrent: limiter.max_concurrent,
                            concurrent: limiter.concurrent,
                            message: self.message,
                        });
                    }
                    throttle::Error::Rate { retry_at } => {
                        queue.rate_limit.push(Schedule {
                            due: retry_at,
                            inner: self.message,
                        });
                    }
                }
                return;
            }
        }

        tokio::spawn(async move {
            let mut done = 0;
            for domain in &self.message.domains {
                match &domain.status {
                    Status::Scheduled | Status::TemporaryFailure(_)
                        if domain.retry.due <= Instant::now() => {}
                    Status::Delivered | Status::PermanentFailure(_) => {
                        done += 1;
                        continue;
                    }
                    _ => continue,
                }
            }

            if done == self.message.domains.len() {}
        });
    }
}

impl From<Box<Message>> for DeliveryAttempt {
    fn from(message: Box<Message>) -> Self {
        DeliveryAttempt {
            span: tracing::info_span!(
                "delivery",
                "queue-id" = message.id,
                "sender" = message.return_path_lcase,
                "size" = message.size,
            ),
            in_flight: Vec::new(),
            message,
        }
    }
}
