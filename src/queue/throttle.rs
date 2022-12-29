use std::{net::IpAddr, time::Instant};

use dashmap::mapref::entry::Entry;

use crate::{
    config::Throttle,
    core::{
        throttle::{ConcurrencyLimiter, InFlight, Limiter, RateLimiter},
        Envelope, QueueCore,
    },
};

use super::{DeliveryAttempt, QueueEnvelope, SimpleEnvelope};

pub enum Error {
    Concurrency { limiter: ConcurrencyLimiter },
    Rate { retry_at: Instant },
}

impl QueueCore {
    pub async fn throttle_sender(&self, attempt: &mut DeliveryAttempt) -> Result<(), Error> {
        if !self.config.throttle.sender.is_empty() {
            let envelope = SimpleEnvelope::new(
                &attempt.message.return_path_lcase,
                &attempt.message.return_path_domain,
                "",
                "",
                attempt.message.priority,
            );

            for throttle in &self.config.throttle.sender {
                self.is_allowed(throttle, &envelope, &mut attempt.in_flight, &attempt.span)
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn throttle_recipient(
        &self,
        attempt: &DeliveryAttempt,
        rcpt_domain: &str,
        mx: &str,
        local_ip: IpAddr,
        remote_ip: IpAddr,
    ) -> Result<Vec<InFlight>, Error> {
        let mut in_flight = Vec::new();
        let envelope = QueueEnvelope {
            sender: &attempt.message.return_path_lcase,
            sender_domain: &attempt.message.return_path_domain,
            rcpt_domain,
            mx,
            remote_ip,
            local_ip,
            priority: attempt.message.priority,
        };

        for throttle in &self.config.throttle.recipient {
            self.is_allowed(throttle, &envelope, &mut in_flight, &attempt.span)
                .await?;
        }

        Ok(in_flight)
    }

    async fn is_allowed(
        &self,
        throttle: &Throttle,
        envelope: &impl Envelope,
        in_flight: &mut Vec<InFlight>,
        span: &tracing::Span,
    ) -> Result<(), Error> {
        if throttle.conditions.conditions.is_empty() || throttle.conditions.eval(envelope).await {
            match self.throttle.entry(throttle.new_key(envelope)) {
                Entry::Occupied(mut e) => {
                    let limiter = e.get_mut();
                    if let Some(limiter) = &limiter.concurrency {
                        if let Some(inflight) = limiter.is_allowed() {
                            in_flight.push(inflight);
                        } else {
                            tracing::info!(
                                parent: span,
                                event = "throttle",
                                class = "concurrency",
                                max_concurrent = limiter.max_concurrent,
                                "Queue concurrency limit exceeded."
                            );
                            return Err(Error::Concurrency {
                                limiter: limiter.clone(),
                            });
                        }
                    }
                    if let Some(limiter) = &mut limiter.rate {
                        if !limiter.is_allowed() {
                            tracing::info!(
                                parent: span,
                                event = "throttle",
                                class = "rate",
                                max_requests = limiter.max_requests as u64,
                                max_interval = limiter.max_interval as u64,
                                "Queue rate limit exceeded."
                            );
                            return Err(Error::Rate {
                                retry_at: limiter.retry_at(),
                            });
                        }
                    }
                }
                Entry::Vacant(e) => {
                    let concurrency = throttle.concurrency.map(|concurrency| {
                        let limiter = ConcurrencyLimiter::new(concurrency);
                        if let Some(inflight) = limiter.is_allowed() {
                            in_flight.push(inflight);
                        }
                        limiter
                    });
                    let rate = throttle
                        .rate
                        .as_ref()
                        .map(|rate| RateLimiter::new(rate.requests, rate.period.as_secs()));

                    e.insert(Limiter { rate, concurrency });
                }
            }
        }

        Ok(())
    }
}
