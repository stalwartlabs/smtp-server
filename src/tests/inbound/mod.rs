use std::time::Duration;

use tokio::sync::mpsc::{self, error::TryRecvError};

use crate::{
    queue::{self, Message, Schedule},
    reporting::{self, DmarcEvent, TlsEvent},
};

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

pub async fn read_queue(rx: &mut mpsc::Receiver<queue::Event>) -> Schedule<Box<Message>> {
    match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
        Ok(Some(event)) => match event {
            queue::Event::Queue(message) => message,
            _ => panic!("Unexpected event."),
        },
        Ok(None) => panic!("Channel closed."),
        Err(_) => panic!("No queue event received."),
    }
}

pub fn assert_empty_queue(rx: &mut mpsc::Receiver<queue::Event>) {
    match rx.try_recv() {
        Err(TryRecvError::Empty) => (),
        Ok(event) => panic!("Expected empty queue but got {:?}", event),
        Err(err) => panic!("Queue error: {:?}", err),
    }
}

pub async fn read_dmarc_report(rx: &mut mpsc::Receiver<reporting::Event>) -> Box<DmarcEvent> {
    match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
        Ok(Some(event)) => match event {
            reporting::Event::Dmarc(event) => event,
            _ => panic!("Unexpected event."),
        },
        Ok(None) => panic!("Channel closed."),
        Err(_) => panic!("No queue event received."),
    }
}

pub async fn read_tls_report(rx: &mut mpsc::Receiver<reporting::Event>) -> Box<TlsEvent> {
    match tokio::time::timeout(Duration::from_millis(100), rx.recv()).await {
        Ok(Some(event)) => match event {
            reporting::Event::Tls(event) => event,
            _ => panic!("Unexpected event."),
        },
        Ok(None) => panic!("Channel closed."),
        Err(_) => panic!("No queue event received."),
    }
}

impl Message {
    fn read_message(&self) -> String {
        let mut buf = vec![0u8; self.size];
        let mut file = std::fs::File::open(&self.path).unwrap();
        std::io::Read::read_exact(&mut file, &mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn read_lines(&self) -> Vec<String> {
        self.read_message()
            .split('\n')
            .map(|l| l.to_string())
            .collect()
    }
}
