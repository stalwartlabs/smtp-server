use std::sync::{atomic::Ordering, Arc};

use dashmap::mapref::entry::Entry;

use crate::{config::QueueCapacity, core::QueueCore};

use super::{Message, QueueLimiter, QueueLimiterRef, SimpleEnvelope};

impl QueueCore {
    pub async fn queue_has_capacity(&self, message: &mut Message) -> bool {
        if !self.config.capacity.sender.is_empty() {
            let envelope = SimpleEnvelope::new(
                &message.return_path_lcase,
                &message.return_path_domain,
                "",
                "",
                message.priority,
            );
            for capacity in &self.config.capacity.sender {
                if !self
                    .reserve_capacity(capacity, &envelope, message.size, &mut message.queue_refs)
                    .await
                {
                    return false;
                }
            }
        }

        for capacity in &self.config.capacity.rcpt_domain {
            for domain in &mut message.domains {
                if !self
                    .reserve_capacity(
                        capacity,
                        &SimpleEnvelope::new(
                            &message.return_path_lcase,
                            &message.return_path_domain,
                            "",
                            &domain.domain,
                            message.priority,
                        ),
                        message.size,
                        &mut domain.queue_refs,
                    )
                    .await
                {
                    return false;
                }
            }
        }

        for capacity in &self.config.capacity.rcpt {
            for rcpt in &mut message.recipients {
                if !self
                    .reserve_capacity(
                        capacity,
                        &SimpleEnvelope::new(
                            &message.return_path_lcase,
                            &message.return_path_domain,
                            &rcpt.address_lcase,
                            &message.domains[rcpt.domain_idx].domain,
                            message.priority,
                        ),
                        message.size,
                        &mut rcpt.queue_refs,
                    )
                    .await
                {
                    return false;
                }
            }
        }

        true
    }

    async fn reserve_capacity(
        &self,
        capacity: &QueueCapacity,
        envelope: &SimpleEnvelope<'_>,
        size: usize,
        refs: &mut Vec<QueueLimiterRef>,
    ) -> bool {
        if capacity.conditions.conditions.is_empty() || capacity.conditions.eval(envelope).await {
            match self.capacity.entry(capacity.new_key(envelope)) {
                Entry::Occupied(e) => {
                    if let Some(qref) = e.get().is_allowed(size) {
                        refs.push(qref);
                    } else {
                        return false;
                    }
                }
                Entry::Vacant(e) => {
                    let limiter = Arc::new(QueueLimiter {
                        max_size: capacity.size.unwrap_or(0),
                        max_messages: capacity.messages.unwrap_or(0),
                        size: 0.into(),
                        messages: 0.into(),
                    });

                    if let Some(qref) = limiter.is_allowed(size) {
                        refs.push(qref);
                        e.insert(limiter);
                    } else {
                        return false;
                    }
                }
            }
        }
        true
    }
}

trait QueueLimiterAllowed {
    fn is_allowed(&self, size: usize) -> Option<QueueLimiterRef>;
}

impl QueueLimiterAllowed for Arc<QueueLimiter> {
    fn is_allowed(&self, size: usize) -> Option<QueueLimiterRef> {
        if self.max_messages > 0 {
            if self.messages.load(Ordering::Relaxed) < self.max_messages {
                self.messages.fetch_add(1, Ordering::Relaxed);
            } else {
                return None;
            }
        }

        if self.max_size > 0 {
            if self.size.load(Ordering::Relaxed) + size < self.max_size {
                self.size.fetch_add(size, Ordering::Relaxed);
            } else {
                return None;
            }
        }

        Some(QueueLimiterRef {
            size,
            limiter: self.clone(),
        })
    }
}

impl Drop for QueueLimiterRef {
    fn drop(&mut self) {
        if self.limiter.max_messages > 0 {
            self.limiter.messages.fetch_sub(1, Ordering::Relaxed);
        }
        if self.limiter.max_size > 0 {
            self.limiter.size.fetch_sub(self.size, Ordering::Relaxed);
        }
    }
}
