use std::{
    collections::BinaryHeap,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use tokio::sync::mpsc;

use crate::core::Core;

use super::{DeliveryAttempt, Event, Message, OnHold, Schedule, WorkerResult};

pub struct Queue {
    short_wait: Duration,
    long_wait: Duration,
    pub main: BinaryHeap<Schedule<Box<Message>>>,
    pub rate_limit: BinaryHeap<Schedule<Box<Message>>>,
    pub on_hold: Vec<OnHold>,
}

impl SpawnQueue for mpsc::Receiver<Event> {
    fn spawn(mut self, core: Arc<Core>) -> Result<(), String> {
        tokio::spawn(async move {
            let mut queue = Queue {
                short_wait: Duration::from_millis(1),
                long_wait: Duration::from_secs(86400 * 365),
                main: BinaryHeap::with_capacity(128),
                rate_limit: BinaryHeap::with_capacity(128),
                on_hold: Vec::with_capacity(128),
            };

            loop {
                match tokio::time::timeout(queue.wake_up_time(), self.recv()).await {
                    Ok(Some(event)) => match event {
                        Event::Queue(item) => {
                            // Deliver any concurrency limited messages
                            while let Some(message) = queue.next_on_hold() {
                                DeliveryAttempt::from(message)
                                    .try_deliver(core.clone(), &mut queue)
                                    .await;
                            }

                            if item.due <= Instant::now() {
                                DeliveryAttempt::from(item.inner)
                                    .try_deliver(core.clone(), &mut queue)
                                    .await;
                            } else {
                                queue.main.push(item);
                            }
                        }
                        Event::Done(result) => {
                            // Deliver concurrency limited messages
                            while let Some(message) = queue.next_on_hold() {
                                DeliveryAttempt::from(message)
                                    .try_deliver(core.clone(), &mut queue)
                                    .await;
                            }
                            match result {
                                WorkerResult::Success => (),
                                WorkerResult::RateLimited(schedule) => {
                                    queue.rate_limit.push(schedule);
                                }
                                WorkerResult::ConcurrencyExceeded(on_hold) => {
                                    queue.on_hold.push(on_hold);
                                }
                            }
                        }
                        Event::Stop => break,
                    },
                    Ok(None) => break,
                    Err(_) => (),
                }

                // Deliver scheduled messages
                while let Some(message) = queue.next_due() {
                    DeliveryAttempt::from(message)
                        .try_deliver(core.clone(), &mut queue)
                        .await;
                }
            }
        });

        Ok(())
    }
}

impl Queue {
    pub fn next_due(&mut self) -> Option<Box<Message>> {
        let now = Instant::now();
        if matches!(self.rate_limit.peek(), Some(item) if item.due <= now ) {
            self.rate_limit.pop().map(|i| i.inner)
        } else if matches!(self.main.peek(), Some(item) if item.due <= now ) {
            self.main.pop().map(|i| i.inner)
        } else {
            None
        }
    }

    pub fn next_on_hold(&mut self) -> Option<Box<Message>> {
        self.on_hold
            .iter()
            .position(|o| o.concurrent.load(Ordering::Relaxed) < o.max_concurrent)
            .map(|pos| self.on_hold.remove(pos).message)
    }

    pub fn wake_up_time(&self) -> Duration {
        match (self.main.peek(), self.rate_limit.peek()) {
            (Some(main), Some(rate_limit)) => {
                if main.due < rate_limit.due {
                    &main.due
                } else {
                    &rate_limit.due
                }
            }
            (Some(main), None) => &main.due,
            (None, Some(rate_limit)) => &rate_limit.due,
            (None, None) => return self.long_wait,
        }
        .checked_duration_since(Instant::now())
        .unwrap_or(self.short_wait)
    }
}

pub trait SpawnQueue {
    fn spawn(self, core: Arc<Core>) -> Result<(), String>;
}
