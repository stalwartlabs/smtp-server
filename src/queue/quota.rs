use std::sync::{atomic::Ordering, Arc};

use dashmap::mapref::entry::Entry;

use crate::{
    config::QueueQuota,
    core::{Envelope, QueueCore},
};

use super::{Message, QuotaLimiter, SimpleEnvelope, Status, UsedQuota};

impl QueueCore {
    pub async fn has_quota(&self, message: &mut Message) -> bool {
        let mut queue_refs = Vec::new();

        if !self.config.quota.sender.is_empty() {
            for quota in &self.config.quota.sender {
                if !self
                    .reserve_quota(quota, message, message.size, 0, &mut queue_refs)
                    .await
                {
                    return false;
                }
            }
        }

        for quota in &self.config.quota.rcpt_domain {
            for (pos, domain) in message.domains.iter().enumerate() {
                if !self
                    .reserve_quota(
                        quota,
                        &SimpleEnvelope::new(message, &domain.domain),
                        message.size,
                        ((pos + 1) << 32) as u64,
                        &mut queue_refs,
                    )
                    .await
                {
                    return false;
                }
            }
        }

        for quota in &self.config.quota.rcpt {
            for (pos, rcpt) in message.recipients.iter().enumerate() {
                if !self
                    .reserve_quota(
                        quota,
                        &SimpleEnvelope::new_rcpt(
                            message,
                            &message.domains[rcpt.domain_idx].domain,
                            &rcpt.address_lcase,
                        ),
                        message.size,
                        (pos + 1) as u64,
                        &mut queue_refs,
                    )
                    .await
                {
                    return false;
                }
            }
        }

        message.queue_refs = queue_refs;

        true
    }

    async fn reserve_quota(
        &self,
        quota: &QueueQuota,
        envelope: &impl Envelope,
        size: usize,
        id: u64,
        refs: &mut Vec<UsedQuota>,
    ) -> bool {
        if quota.conditions.conditions.is_empty() || quota.conditions.eval(envelope).await {
            match self.quota.entry(quota.new_key(envelope)) {
                Entry::Occupied(e) => {
                    if let Some(qref) = e.get().is_allowed(id, size) {
                        refs.push(qref);
                    } else {
                        return false;
                    }
                }
                Entry::Vacant(e) => {
                    let limiter = Arc::new(QuotaLimiter {
                        max_size: quota.size.unwrap_or(0),
                        max_messages: quota.messages.unwrap_or(0),
                        size: 0.into(),
                        messages: 0.into(),
                    });

                    if let Some(qref) = limiter.is_allowed(id, size) {
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

impl Message {
    pub fn release_quota(&mut self) {
        let mut quota_ids = Vec::with_capacity(self.domains.len() + self.recipients.len());
        for (pos, domain) in self.domains.iter().enumerate() {
            if matches!(
                &domain.status,
                Status::Completed(_) | Status::PermanentFailure(_)
            ) {
                quota_ids.push(((pos + 1) << 32) as u64);
            }
        }
        for (pos, rcpt) in self.recipients.iter().enumerate() {
            if matches!(
                &rcpt.status,
                Status::Completed(_) | Status::PermanentFailure(_)
            ) {
                quota_ids.push((pos + 1) as u64);
            }
        }
        if !quota_ids.is_empty() {
            self.queue_refs.retain(|q| !quota_ids.contains(&q.id));
        }
    }
}

trait QuotaLimiterAllowed {
    fn is_allowed(&self, id: u64, size: usize) -> Option<UsedQuota>;
}

impl QuotaLimiterAllowed for Arc<QuotaLimiter> {
    fn is_allowed(&self, id: u64, size: usize) -> Option<UsedQuota> {
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

        Some(UsedQuota {
            id,
            size,
            limiter: self.clone(),
        })
    }
}

impl Drop for UsedQuota {
    fn drop(&mut self) {
        if self.limiter.max_messages > 0 {
            self.limiter.messages.fetch_sub(1, Ordering::Relaxed);
        }
        if self.limiter.max_size > 0 {
            self.limiter.size.fetch_sub(self.size, Ordering::Relaxed);
        }
    }
}
