use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::core::{throttle::ConcurrencyLimiter, Core};

use super::{
    manager::Queue, throttle, DeliveryAttempt, Domain, Error, Event, Message, OnHold, Schedule,
    SimpleEnvelope, Status, WorkerResult,
};

impl DeliveryAttempt {
    pub async fn try_deliver(mut self, core: Arc<Core>, queue: &mut Queue) {
        // Throttle sender
        for throttle in &core.queue.config.throttle.sender {
            if let Err(err) = core
                .queue
                .is_allowed(
                    throttle,
                    self.message.as_ref(),
                    &mut self.in_flight,
                    &self.span,
                )
                .await
            {
                match err {
                    throttle::Error::Concurrency { limiter } => {
                        queue.on_hold.push(OnHold {
                            next_due: self.message.next_event_after(Instant::now()),
                            max_concurrent: limiter.max_concurrent,
                            concurrent: limiter.concurrent,
                            message: self.message,
                        });
                    }
                    throttle::Error::Rate { retry_at } => {
                        queue.main.push(Schedule {
                            due: retry_at,
                            inner: self.message,
                        });
                    }
                }
                return;
            }
        }

        tokio::spawn(async move {
            let queue_config = &core.queue.config;
            let mut on_hold: Option<ConcurrencyLimiter> = None;

            let mut domains = std::mem::take(&mut self.message.domains);
            'outer: for domain in &mut domains {
                // Only process domains due for delivery
                if !matches!(&domain.status, Status::Scheduled | Status::TemporaryFailure(_)
                if domain.retry.due <= Instant::now())
                {
                    continue;
                }

                // Throttle recipient domain
                let mut in_flight = Vec::new();
                let envelope = SimpleEnvelope::new(self.message.as_ref(), &domain.domain);
                for throttle in &queue_config.throttle.rcpt {
                    if let Err(err) = core
                        .queue
                        .is_allowed(throttle, &envelope, &mut in_flight, &self.span)
                        .await
                    {
                        match err {
                            throttle::Error::Concurrency { limiter } => {
                                on_hold = limiter.into();
                            }
                            throttle::Error::Rate { retry_at } => {
                                domain.retry.due = retry_at;
                            }
                        }
                        continue;
                    }
                }

                // Obtain next hop
                if let Some(next_hop) = queue_config.next_hop.eval(&envelope).await {
                } else {
                    let mx_list = match core.resolver.mx_lookup(&domain.domain).await {
                        Ok(mx) => mx,
                        Err(err) => {
                            domain.set_dns_error(err, queue_config.retry.eval(&envelope).await);
                            continue;
                        }
                    };
                    for mx in mx_list.iter() {
                        let ips = match core.resolver.ip_lookup(&mx.exchange).await {
                            Ok(ips) => ips,
                            Err(err) => {
                                domain.set_dns_error(err, queue_config.retry.eval(&envelope).await);
                                continue 'outer;
                            }
                        };
                    }
                }
            }
            self.message.domains = domains;

            // Notify queue manager
            let span = self.span;
            let result = if let Some(on_hold) = on_hold {
                WorkerResult::OnHold(OnHold {
                    next_due: self.message.next_event_after(Instant::now()),
                    max_concurrent: on_hold.max_concurrent,
                    concurrent: on_hold.concurrent,
                    message: self.message,
                })
            } else if let Some(due) = self.message.next_event() {
                WorkerResult::Retry(Schedule {
                    due,
                    inner: self.message,
                })
            } else {
                WorkerResult::Delivered
            };
            if core.queue.tx.send(Event::Done(result)).await.is_err() {
                tracing::warn!(
                    parent: &span,
                    "Channel closed while trying to notify queue manager."
                );
            }
        });
    }
}

impl Domain {
    pub fn set_dns_error(&mut self, err: mail_auth::Error, schedule: &[Duration]) {
        match &err {
            mail_auth::Error::DNSRecordNotFound(code) => {
                self.status = Status::PermanentFailure(Error::DNSError(format!(
                    "Domain not found: {}",
                    code
                )));
            }
            _ => {
                self.status = Status::TemporaryFailure(Error::DNSError(err.to_string()));
                self.retry(schedule);
            }
        }
    }

    pub fn retry(&mut self, schedule: &[Duration]) {
        self.retry.due =
            Instant::now() + schedule[std::cmp::min(self.retry.inner as usize, schedule.len() - 1)];
        self.retry.inner += 1;
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
