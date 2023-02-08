use std::{
    borrow::Borrow,
    hash::Hash,
    time::{Duration, Instant},
};

#[allow(clippy::type_complexity)]
#[derive(Debug)]
pub struct LookupCache<T: Hash + Eq> {
    cache_pos: lru_cache::LruCache<T, Instant, ahash::RandomState>,
    cache_neg: lru_cache::LruCache<T, Instant, ahash::RandomState>,
    ttl_pos: Duration,
    ttl_neg: Duration,
}

impl<T: Hash + Eq> LookupCache<T> {
    pub fn new(capacity: usize, ttl_pos: Duration, ttl_neg: Duration) -> Self {
        Self {
            cache_pos: lru_cache::LruCache::with_hasher(capacity, ahash::RandomState::new()),
            cache_neg: lru_cache::LruCache::with_hasher(capacity, ahash::RandomState::new()),
            ttl_pos,
            ttl_neg,
        }
    }

    pub fn get<Q: ?Sized>(&mut self, name: &Q) -> Option<bool>
    where
        T: Borrow<Q>,
        Q: Hash + Eq,
    {
        // Check positive cache
        if let Some(valid_until) = self.cache_pos.get_mut(name) {
            if *valid_until >= Instant::now() {
                return Some(true);
            } else {
                self.cache_pos.remove(name);
            }
        }

        // Check negative cache
        let valid_until = self.cache_neg.get_mut(name)?;
        if *valid_until >= Instant::now() {
            Some(false)
        } else {
            self.cache_pos.remove(name);
            None
        }
    }

    pub fn insert_pos(&mut self, item: T) {
        self.cache_pos.insert(item, Instant::now() + self.ttl_pos);
    }

    pub fn insert_neg(&mut self, item: T) {
        self.cache_neg.insert(item, Instant::now() + self.ttl_neg);
    }

    pub fn clear(&mut self) {
        self.cache_pos.clear();
        self.cache_neg.clear();
    }
}
