use std::{
    borrow::Borrow,
    hash::Hash,
    time::{Duration, Instant},
};

pub struct LookupCache<K: Hash + Eq> {
    cache: lru_cache::LruCache<K, Instant, ahash::RandomState>,
    ttl: Duration,
}

impl<K: Hash + Eq> LookupCache<K> {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            cache: lru_cache::LruCache::with_hasher(capacity, ahash::RandomState::new()),
            ttl,
        }
    }

    pub fn get<Q: ?Sized>(&mut self, name: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq,
    {
        match self.cache.get_mut(name) {
            Some(valid_until) => {
                if *valid_until >= Instant::now() {
                    true
                } else {
                    self.cache.remove(name);
                    false
                }
            }
            None => false,
        }
    }

    pub fn insert(&mut self, key: K) {
        self.cache.insert(key, Instant::now() + self.ttl);
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }
}
