use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use super::lookup::{Item, LookupResult};

#[allow(clippy::type_complexity)]
pub struct LookupCache {
    cache_pos: lru_cache::LruCache<Item, (Option<Arc<Vec<String>>>, Instant), ahash::RandomState>,
    cache_neg: lru_cache::LruCache<Item, Instant, ahash::RandomState>,
    ttl_pos: Duration,
    ttl_neg: Duration,
}

impl LookupCache {
    pub fn new(capacity: usize, ttl_pos: Duration, ttl_neg: Duration) -> Self {
        Self {
            cache_pos: lru_cache::LruCache::with_hasher(capacity, ahash::RandomState::new()),
            cache_neg: lru_cache::LruCache::with_hasher(capacity, ahash::RandomState::new()),
            ttl_pos,
            ttl_neg,
        }
    }

    pub fn get(&mut self, name: &Item) -> Option<LookupResult> {
        // Check positive cache
        if let Some((value, valid_until)) = self.cache_pos.get_mut(name) {
            if *valid_until >= Instant::now() {
                return Some(
                    value
                        .as_ref()
                        .map(|v| LookupResult::Values(v.clone()))
                        .unwrap_or(LookupResult::True),
                );
            } else {
                self.cache_pos.remove(name);
            }
        }

        // Check negative cache
        let valid_until = self.cache_neg.get_mut(name)?;
        if *valid_until >= Instant::now() {
            Some(LookupResult::False)
        } else {
            self.cache_pos.remove(name);
            None
        }
    }

    pub fn insert(&mut self, item: Item, value: LookupResult) {
        match value {
            LookupResult::True => {
                self.cache_pos
                    .insert(item, (None, Instant::now() + self.ttl_pos));
            }
            LookupResult::False => {
                self.cache_neg.insert(item, Instant::now() + self.ttl_neg);
            }
            LookupResult::Values(values) => {
                self.cache_pos
                    .insert(item, (values.into(), Instant::now() + self.ttl_pos));
            }
        }
    }

    pub fn clear(&mut self) {
        self.cache_pos.clear();
        self.cache_neg.clear();
    }
}
