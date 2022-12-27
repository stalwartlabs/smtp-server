use std::time::Instant;

pub mod manager;
pub mod message;

pub enum Event {
    Start,
    Stop,
}

pub struct QueueItem {
    pub due: u64,
    pub message: Box<Message>,
}

pub struct Message {
    pub id: u64,
    pub created: u64,

    pub return_path: String,
    pub recipients: Vec<Recipient>,

    pub flags: u64,
    pub priority: i64,
    pub size: usize,

    pub notify: Action,
}

pub struct Recipient {
    pub address: String,
    pub domain: String,
    pub status: Status,
    pub flags: u64,
    pub retry: Action,
}

pub struct Action {
    pub due_at: Instant,
    pub count: u32,
}

pub enum Status {
    None,
    Delivered,
    TemporaryFailure,
    PermanentFailure,
}
