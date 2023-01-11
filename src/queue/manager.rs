use std::{
    collections::BinaryHeap,
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use tokio::sync::mpsc;

use crate::core::{Core, QueueCore};

use super::{DeliveryAttempt, Event, Message, OnHold, Schedule, Status, WorkerResult};

pub struct Queue {
    short_wait: Duration,
    long_wait: Duration,
    pub main: BinaryHeap<Schedule<Box<Message>>>,
    pub on_hold: Vec<OnHold>,
}

impl SpawnQueue for mpsc::Receiver<Event> {
    fn spawn(mut self, core: Arc<Core>, mut queue: Queue) {
        tokio::spawn(async move {
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

    pub fn next_delivery_event(&self) -> Instant {
        let mut next_delivery = Instant::now();

        for (pos, domain) in self
            .domains
            .iter()
            .filter(|d| matches!(d.status, Status::Scheduled | Status::TemporaryFailure(_)))
            .enumerate()
        {
            if pos == 0 || domain.retry.due < next_delivery {
                next_delivery = domain.retry.due;
            }
        }

        next_delivery
    }

    pub fn next_event_after(&self, instant: Instant) -> Option<Instant> {
        let mut next_event = instant;

        for (pos, domain) in self
            .domains
            .iter()
            .filter(|d| matches!(d.status, Status::Scheduled | Status::TemporaryFailure(_)))
            .enumerate()
        {
            if domain.retry.due > instant && (pos == 0 || domain.retry.due < next_event) {
                next_event = domain.retry.due;
            }
            if domain.notify.due > instant && (pos == 0 || domain.notify.due < next_event) {
                next_event = domain.notify.due;
            }
            if domain.expires > instant && (pos == 0 || domain.expires < next_event) {
                next_event = domain.expires;
            }
        }

        if next_event != instant {
            next_event.into()
        } else {
            None
        }
    }
}

impl QueueCore {
    pub async fn read_queue(&self) -> Queue {
        let mut queue = Queue::default();
        let mut messages = Vec::new();

        for path in self
            .config
            .path
            .if_then
            .iter()
            .map(|t| &t.then)
            .chain([&self.config.path.default])
        {
            let mut dir = match tokio::fs::read_dir(path).await {
                Ok(dir) => dir,
                Err(_) => continue,
            };
            loop {
                match dir.next_entry().await {
                    Ok(Some(file)) => {
                        let file = file.path();
                        if file.is_dir() {
                            match tokio::fs::read_dir(path).await {
                                Ok(mut dir) => {
                                    let file_ = file;
                                    loop {
                                        match dir.next_entry().await {
                                            Ok(Some(file)) => {
                                                let file = file.path();
                                                if file.extension().map_or(false, |e| e == "msg") {
                                                    messages.push(tokio::spawn(
                                                        Message::from_path(file),
                                                    ));
                                                }
                                            }
                                            Ok(None) => break,
                                            Err(err) => {
                                                tracing::warn!(
                                                    "Failed to read queue directory {}: {}",
                                                    file_.display(),
                                                    err
                                                );
                                                break;
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    tracing::warn!(
                                        "Failed to read queue directory {}: {}",
                                        file.display(),
                                        err
                                    )
                                }
                            };
                        } else if file.extension().map_or(false, |e| e == "msg") {
                            messages.push(tokio::spawn(Message::from_path(file)));
                        }
                    }
                    Ok(None) => {
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(
                            "Failed to read queue directory {}: {}",
                            path.display(),
                            err
                        );
                        break;
                    }
                }
            }
        }

        // Join all futures
        for message in messages {
            match message.await {
                Ok(Ok(mut message)) => {
                    // Reserve quota
                    self.has_quota(&mut message).await;

                    // Schedule message
                    queue.main.push(Schedule {
                        due: message.next_event().unwrap_or_else(|| {
                            tracing::warn!(
                                module = "queue",
                                event = "warn",
                                "No due events found for message {}",
                                message.path.display()
                            );
                            Instant::now()
                        }),
                        inner: Box::new(message),
                    });
                }
                Ok(Err(err)) => {
                    tracing::warn!(
                        module = "queue",
                        event = "error",
                        "Queue startup error: {}",
                        err
                    );
                }
                Err(err) => {
                    tracing::error!("Join error while starting queue: {}", err);
                }
            }
        }

        queue
    }
}

impl Default for Queue {
    fn default() -> Self {
        Queue {
            short_wait: Duration::from_millis(1),
            long_wait: Duration::from_secs(86400 * 365),
            main: BinaryHeap::with_capacity(128),
            on_hold: Vec::with_capacity(128),
        }
    }
}

pub trait SpawnQueue {
    fn spawn(self, core: Arc<Core>, queue: Queue);
}
