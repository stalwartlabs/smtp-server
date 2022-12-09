use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use parking_lot::Mutex;

#[derive(Debug)]
pub struct RateLimiter {
    max_requests: f64,
    max_interval: f64,
    max_concurrent: u64,
    limiter: Arc<Mutex<(Instant, f64)>>,
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
    pub fn new(max_concurrent: u64, max_requests: u64, max_interval: u64) -> Self {
        RateLimiter {
            max_concurrent,
            max_requests: max_requests as f64,
            max_interval: max_interval as f64,
            limiter: Arc::new(Mutex::new((Instant::now(), max_requests as f64))),
            concurrent: Arc::new(0.into()),
        }
    }

    pub fn is_allowed(&self) -> Option<InFlightRequest> {
        if self.max_concurrent == 0 || self.concurrent.load(Ordering::Relaxed) < self.max_concurrent
        {
            // Check rate limit
            if self.max_requests > 0.0 {
                let mut limiter = self.limiter.lock();
                let elapsed = limiter.0.elapsed().as_secs_f64();
                limiter.0 = Instant::now();
                limiter.1 += elapsed * (self.max_requests / self.max_interval);
                if limiter.1 > self.max_requests {
                    limiter.1 = self.max_requests;
                }
                if limiter.1 >= 1.0 {
                    limiter.1 -= 1.0;
                } else {
                    return None;
                }
            }

            // Return in-flight request
            self.concurrent.fetch_add(1, Ordering::Relaxed);
            Some(InFlightRequest {
                concurrent_requests: self.concurrent.clone(),
            })
        } else {
            None
        }
    }

    pub fn reset(&self) {
        *self.limiter.lock() = (Instant::now(), self.max_requests);
    }
}
