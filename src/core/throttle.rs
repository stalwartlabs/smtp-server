use dashmap::mapref::entry::Entry;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite};

use std::{
    hash::{BuildHasher, Hash, Hasher},
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use crate::config::*;

use super::{if_block::ConditionEval, Envelope, Session};

#[derive(Debug)]
pub struct Limiter {
    rate: Option<RateLimiter>,
    concurrency: Option<ConcurrencyLimiter>,
}

#[derive(Debug)]
pub struct RateLimiter {
    max_requests: f64,
    max_interval: f64,
    limiter: Arc<Mutex<(Instant, f64)>>,
}

#[derive(Debug)]
pub struct ConcurrencyLimiter {
    pub max_concurrent: u64,
    concurrent: Arc<AtomicU64>,
}

pub struct InFlightRequest {
    concurrent_requests: Arc<AtomicU64>,
}

impl Drop for InFlightRequest {
    fn drop(&mut self) {
        self.concurrent_requests.fetch_sub(1, Ordering::Relaxed);
    }
}

impl RateLimiter {
    pub fn new(max_requests: u64, max_interval: u64) -> Self {
        RateLimiter {
            max_requests: max_requests as f64,
            max_interval: max_interval as f64,
            limiter: Arc::new(Mutex::new((Instant::now(), max_requests as f64))),
        }
    }

    pub fn is_allowed(&self) -> bool {
        // Check rate limit
        let mut limiter = self.limiter.lock();
        let elapsed = limiter.0.elapsed().as_secs_f64();
        limiter.0 = Instant::now();
        limiter.1 += elapsed * (self.max_requests / self.max_interval);
        if limiter.1 > self.max_requests {
            limiter.1 = self.max_requests;
        }
        if limiter.1 >= 1.0 {
            limiter.1 -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn reset(&self) {
        *self.limiter.lock() = (Instant::now(), self.max_requests);
    }
}

impl ConcurrencyLimiter {
    pub fn new(max_concurrent: u64) -> Self {
        ConcurrencyLimiter {
            max_concurrent,
            concurrent: Arc::new(0.into()),
        }
    }

    pub fn is_allowed(&self) -> Option<InFlightRequest> {
        if self.concurrent.load(Ordering::Relaxed) < self.max_concurrent {
            // Return in-flight request
            self.concurrent.fetch_add(1, Ordering::Relaxed);
            Some(InFlightRequest {
                concurrent_requests: self.concurrent.clone(),
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Eq)]
pub struct ThrottleKey {
    hash: [u8; 32],
}

impl PartialEq for ThrottleKey {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash
    }
}

impl Hash for ThrottleKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

#[derive(Default)]
pub struct ThrottleKeyHasher {
    hash: u64,
}

impl Hasher for ThrottleKeyHasher {
    fn finish(&self) -> u64 {
        self.hash
    }

    fn write(&mut self, bytes: &[u8]) {
        self.hash = u64::from_ne_bytes((&bytes[..std::mem::size_of::<u64>()]).try_into().unwrap());
    }
}

#[derive(Clone, Default)]
pub struct ThrottleKeyHasherBuilder {}

impl BuildHasher for ThrottleKeyHasherBuilder {
    type Hasher = ThrottleKeyHasher;

    fn build_hasher(&self) -> Self::Hasher {
        ThrottleKeyHasher::default()
    }
}

impl ThrottleKey {
    pub fn new(e: &impl Envelope, t: &Throttle) -> Self {
        let mut hasher = blake3::Hasher::new();

        if (t.keys & THROTTLE_RCPT) != 0 {
            hasher.update(e.rcpt().as_bytes());
        }
        if (t.keys & THROTTLE_RCPT_DOMAIN) != 0 {
            hasher.update(e.rcpt_domain().as_bytes());
        }
        if (t.keys & THROTTLE_SENDER) != 0 {
            hasher.update(e.sender().as_bytes());
        }
        if (t.keys & THROTTLE_SENDER_DOMAIN) != 0 {
            hasher.update(e.sender_domain().as_bytes());
        }
        if (t.keys & THROTTLE_HELO_DOMAIN) != 0 {
            hasher.update(e.helo_domain().as_bytes());
        }
        if (t.keys & THROTTLE_AUTH_AS) != 0 {
            hasher.update(e.authenticated_as().as_bytes());
        }
        if (t.keys & THROTTLE_LISTENER) != 0 {
            hasher.update(&e.listener_id().to_ne_bytes()[..]);
        }
        if (t.keys & THROTTLE_MX) != 0 {
            hasher.update(e.mx().as_bytes());
        }
        if (t.keys & THROTTLE_REMOTE_IP) != 0 {
            match &e.local_ip() {
                IpAddr::V4(ip) => {
                    hasher.update(&ip.octets()[..]);
                }
                IpAddr::V6(ip) => {
                    hasher.update(&ip.octets()[..]);
                }
            }
        }
        if (t.keys & THROTTLE_LOCAL_IP) != 0 {
            match &e.remote_ip() {
                IpAddr::V4(ip) => {
                    hasher.update(&ip.octets()[..]);
                }
                IpAddr::V6(ip) => {
                    hasher.update(&ip.octets()[..]);
                }
            }
        }
        if let Some(rate_limit) = &t.rate {
            hasher.update(&rate_limit.period.as_secs().to_ne_bytes()[..]);
            hasher.update(&rate_limit.requests.to_ne_bytes()[..]);
        }
        if let Some(concurrency) = &t.concurrency {
            hasher.update(&concurrency.to_ne_bytes()[..]);
        }

        ThrottleKey {
            hash: hasher.finalize().into(),
        }
    }
}

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub fn is_allowed(&mut self, throttle: &[Throttle]) -> bool {
        for t in throttle {
            if t.condition.is_empty() || t.condition.eval(self) {
                // Build throttle key
                match self.core.throttle.entry(ThrottleKey::new(self, t)) {
                    Entry::Occupied(e) => {
                        let limiter = e.get();
                        if let Some(limiter) = &limiter.concurrency {
                            if let Some(inflight) = limiter.is_allowed() {
                                self.in_flight.push(inflight);
                            } else {
                                tracing::info!(
                                    parent: &self.span,
                                    event = "throttle",
                                    class = "concurrency",
                                    max_concurrent = limiter.max_concurrent,
                                    "Too many concurrent requests."
                                );
                                return false;
                            }
                        }
                        if let Some(limiter) = &limiter.rate {
                            if !limiter.is_allowed() {
                                tracing::info!(
                                    parent: &self.span,
                                    event = "throttle",
                                    class = "rate",
                                    max_requests = limiter.max_requests as u64,
                                    max_interval = limiter.max_interval as u64,
                                    "Rate limit exceeded."
                                );
                                return false;
                            }
                        }
                    }
                    Entry::Vacant(e) => {
                        let concurrency = t.concurrency.map(|concurrency| {
                            let limiter = ConcurrencyLimiter::new(concurrency);
                            if let Some(inflight) = limiter.is_allowed() {
                                self.in_flight.push(inflight);
                            }
                            limiter
                        });
                        let rate = t
                            .rate
                            .as_ref()
                            .map(|rate| RateLimiter::new(rate.requests, rate.period.as_secs()));

                        e.insert(Limiter { rate, concurrency });
                    }
                }
            }
        }

        true
    }
}
