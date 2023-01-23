use std::time::Duration;

use tokio::sync::mpsc::error::TryRecvError;

use crate::{
    queue::{self, Message, OnHold, Schedule, WorkerResult},
    reporting::{self, DmarcEvent, TlsEvent},
};

use super::{QueueReceiver, ReportReceiver};

pub mod auth;
pub mod basic;
pub mod data;
pub mod dmarc;
pub mod ehlo;
pub mod limits;
pub mod mail;
pub mod rcpt;
pub mod sign;
pub mod throttle;
pub mod vrfy;

impl QueueReceiver {
    pub async fn read_event(&mut self) -> queue::Event {
        match tokio::time::timeout(Duration::from_millis(100), self.queue_rx.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => panic!("Channel closed."),
            Err(_) => panic!("No queue event received."),
        }
    }

    pub async fn try_read_event(&mut self) -> Option<queue::Event> {
        match tokio::time::timeout(Duration::from_millis(100), self.queue_rx.recv()).await {
            Ok(Some(event)) => Some(event),
            Ok(None) => panic!("Channel closed."),
            Err(_) => None,
        }
    }
    pub fn assert_empty_queue(&mut self) {
        match self.queue_rx.try_recv() {
            Err(TryRecvError::Empty) => (),
            Ok(event) => panic!("Expected empty queue but got {:?}", event),
            Err(err) => panic!("Queue error: {:?}", err),
        }
    }
}

impl ReportReceiver {
    pub async fn read_report(&mut self) -> reporting::Event {
        match tokio::time::timeout(Duration::from_millis(100), self.report_rx.recv()).await {
            Ok(Some(event)) => event,
            Ok(None) => panic!("Channel closed."),
            Err(_) => panic!("No report event received."),
        }
    }

    pub async fn try_read_report(&mut self) -> Option<reporting::Event> {
        match tokio::time::timeout(Duration::from_millis(100), self.report_rx.recv()).await {
            Ok(Some(event)) => Some(event),
            Ok(None) => panic!("Channel closed."),
            Err(_) => None,
        }
    }
    pub fn assert_no_reports(&mut self) {
        match self.report_rx.try_recv() {
            Err(TryRecvError::Empty) => (),
            Ok(event) => panic!("Expected no reports but got {:?}", event),
            Err(err) => panic!("Report error: {:?}", err),
        }
    }
}

impl queue::Event {
    pub fn unwrap_message(self) -> Box<Message> {
        match self {
            queue::Event::Queue(message) => message.inner,
            e => panic!("Unexpected event: {:?}", e),
        }
    }

    pub fn unwrap_schedule(self) -> Schedule<Box<Message>> {
        match self {
            queue::Event::Queue(message) => message,
            e => panic!("Unexpected event: {:?}", e),
        }
    }

    pub fn unwrap_result(self) -> WorkerResult {
        match self {
            queue::Event::Done(result) => result,
            queue::Event::Queue(message) => {
                panic!("Unexpected message: {}", message.inner.read_message());
            }
            e => panic!("Unexpected event: {:?}", e),
        }
    }

    pub fn unwrap_done(self) {
        match self {
            queue::Event::Done(WorkerResult::Done) => (),
            queue::Event::Queue(message) => {
                panic!("Unexpected message: {}", message.inner.read_message());
            }
            e => panic!("Unexpected event: {:?}", e),
        }
    }

    pub fn unwrap_on_hold(self) -> OnHold {
        match self {
            queue::Event::Done(WorkerResult::OnHold(value)) => value,
            queue::Event::Queue(message) => {
                panic!("Unexpected message: {}", message.inner.read_message());
            }
            e => panic!("Unexpected event: {:?}", e),
        }
    }

    pub fn unwrap_retry(self) -> Schedule<Box<Message>> {
        match self {
            queue::Event::Done(WorkerResult::Retry(value)) => value,
            queue::Event::Queue(message) => {
                panic!("Unexpected message: {}", message.inner.read_message());
            }
            e => panic!("Unexpected event: {:?}", e),
        }
    }
}

impl reporting::Event {
    pub fn unwrap_dmarc(self) -> Box<DmarcEvent> {
        match self {
            reporting::Event::Dmarc(event) => event,
            e => panic!("Unexpected event: {:?}", e),
        }
    }

    pub fn unwrap_tls(self) -> Box<TlsEvent> {
        match self {
            reporting::Event::Tls(event) => event,
            e => panic!("Unexpected event: {:?}", e),
        }
    }
}

impl Message {
    pub fn read_message(&self) -> String {
        let mut buf = vec![0u8; self.size];
        let mut file = std::fs::File::open(&self.path).unwrap();
        std::io::Read::read_exact(&mut file, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    pub fn read_lines(&self) -> Vec<String> {
        self.read_message()
            .split('\n')
            .map(|l| l.to_string())
            .collect()
    }
}
