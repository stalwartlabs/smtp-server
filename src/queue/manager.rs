use std::{
    collections::{BinaryHeap, VecDeque},
    sync::Arc,
};

use ahash::{AHashMap, HashMap};
use dashmap::DashMap;
use tokio::sync::{mpsc, watch};

use crate::{
    config::Queue,
    core::{
        throttle::{RateLimiter, ThrottleKey, ThrottleKeyHasherBuilder},
        Core,
    },
};

use super::{Event, Message, QueueItem};

struct ThrottleQueue {
    pub limiter: RateLimiter,
    pub concurrent: usize,
    pub queue: VecDeque<Box<Message>>,
}

impl Queue {
    pub fn spawn(self, queue_rx: mpsc::Receiver<Event>) -> Result<(), String> {
        let mut queue: BinaryHeap<QueueItem> = BinaryHeap::new();
        let mut throttle: DashMap<ThrottleKey, ThrottleQueue, ThrottleKeyHasherBuilder> =
            DashMap::with_capacity_and_hasher(100, ThrottleKeyHasherBuilder::default());

        todo!()
    }
}
