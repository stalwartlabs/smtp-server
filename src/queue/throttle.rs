use std::time::Instant;

use dashmap::mapref::entry::Entry;

use crate::{
    config::Throttle,
    core::{
        throttle::{ConcurrencyLimiter, InFlight, Limiter, RateLimiter},
        Envelope, QueueCore,
    },
};

use super::{Domain, Status};

pub enum Error {
    Concurrency { limiter: ConcurrencyLimiter },
    Rate { retry_at: Instant },
}

impl QueueCore {
    pub async fn is_allowed(
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
                                module = "concurrency",
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
                                module = "rate",
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

impl Domain {
    pub fn set_throttle_error(&mut self, err: Error, on_hold: &mut Vec<ConcurrencyLimiter>) {
        match err {
            Error::Concurrency { limiter } => {
                on_hold.push(limiter);
                self.status = Status::TemporaryFailure(super::Error::ConcurrencyLimited);
            }
            Error::Rate { retry_at } => {
                self.retry.due = retry_at;
                self.status = Status::TemporaryFailure(super::Error::RateLimited);
            }
        }
    }
}
