use std::{
    collections::BinaryHeap,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use tokio::sync::mpsc;

use crate::core::Core;

use super::{DeliveryAttempt, Event, Message, OnHold, Schedule, Status, WorkerResult};

pub struct Queue {
    short_wait: Duration,
    long_wait: Duration,
    pub main: BinaryHeap<Schedule<Box<Message>>>,
    pub on_hold: Vec<OnHold>,
}

impl SpawnQueue for mpsc::Receiver<Event> {
    fn spawn(mut self, core: Arc<Core>) -> Result<(), String> {
        tokio::spawn(async move {
            let mut queue = Queue {
                short_wait: Duration::from_millis(1),
                long_wait: Duration::from_secs(86400 * 365),
                main: BinaryHeap::with_capacity(128),
                on_hold: Vec::with_capacity(128),
            };

            loop {
                let result = tokio::time::timeout(queue.wake_up_time(), self.recv()).await;

                // Deliver scheduled messages
                while let Some(message) = queue.next_due() {
                    DeliveryAttempt::from(message)
                        .try_deliver(core.clone(), &mut queue)
                        .await;
                }

                match result {
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
                            // A worker is done, try delivering concurrency limited messages
                            while let Some(message) = queue.next_on_hold() {
                                DeliveryAttempt::from(message)
                                    .try_deliver(core.clone(), &mut queue)
                                    .await;
                            }
                            match result {
                                WorkerResult::Done => (),
                                WorkerResult::Retry(schedule) => {
                                    queue.main.push(schedule);
                                }
                                WorkerResult::OnHold(on_hold) => {
                                    queue.on_hold.push(on_hold);
                                }
                            }
                        }
                        Event::Stop => break,
                    },
                    Ok(None) => break,
                    Err(_) => (),
                }
            }
        });

        Ok(())
    }
}

impl Queue {
    pub fn next_due(&mut self) -> Option<Box<Message>> {
        let item = self.main.peek()?;
        if item.due <= Instant::now() {
            self.main.pop().map(|i| i.inner)
        } else {
            None
        }
    }

    pub fn next_on_hold(&mut self) -> Option<Box<Message>> {
        let now = Instant::now();
        self.on_hold
            .iter()
            .position(|o| {
                o.limiters
                    .iter()
                    .any(|l| l.concurrent.load(Ordering::Relaxed) < l.max_concurrent)
                    || o.next_due.map_or(false, |due| due <= now)
            })
            .map(|pos| self.on_hold.remove(pos).message)
    }

    pub fn wake_up_time(&self) -> Duration {
        self.main
            .peek()
            .map(|item| {
                item.due
                    .checked_duration_since(Instant::now())
                    .unwrap_or(self.short_wait)
            })
            .unwrap_or(self.long_wait)
    }
}

impl Message {
    pub fn next_event(&self) -> Option<Instant> {
        let mut next_event = Instant::now();
        let mut has_events = false;

        for domain in &self.domains {
            if matches!(
                domain.status,
                Status::Scheduled | Status::TemporaryFailure(_)
            ) {
                if !has_events || domain.retry.due < next_event {
                    next_event = domain.retry.due;
                    has_events = true;
                }
                if domain.notify.due < next_event {
                    next_event = domain.notify.due;
                }
                if domain.expires < next_event {
                    next_event = domain.expires;
                }
            }
        }

        if has_events {
            next_event.into()
        } else {
            None
        }
    }

    pub fn next_event_after(&self, instant: Instant) -> Option<Instant> {
        let mut next_event = instant;
        let mut has_events = false;

        for domain in &self.domains {
            if matches!(
                domain.status,
                Status::Scheduled | Status::TemporaryFailure(_)
            ) {
                if domain.retry.due > instant && (!has_events || domain.retry.due < next_event) {
                    next_event = domain.retry.due;
                    has_events = true;
                }
                if domain.notify.due > instant && (!has_events || domain.notify.due < next_event) {
                    next_event = domain.notify.due;
                    has_events = true;
                }
                if domain.expires > instant && (!has_events || domain.expires < next_event) {
                    next_event = domain.expires;
                    has_events = true;
                }
            }
        }

        if has_events {
            next_event.into()
        } else {
            None
        }
    }
}

pub trait SpawnQueue {
    fn spawn(self, core: Arc<Core>) -> Result<(), String>;
}
