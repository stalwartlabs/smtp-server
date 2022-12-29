use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, AtomicUsize},
        Arc,
    },
    time::Instant,
};

use smtp_proto::Response;

use crate::core::{throttle::InFlight, Envelope};

pub mod delivery;
pub mod limiter;
pub mod manager;
pub mod spool;
pub mod throttle;

pub enum Event {
    Queue(Schedule<Box<Message>>),
    Done(WorkerResult),
    Stop,
}

pub enum WorkerResult {
    Success,
    RateLimited(Schedule<Box<Message>>),
    ConcurrencyExceeded(OnHold),
}

pub struct OnHold {
    max_concurrent: u64,
    concurrent: Arc<AtomicU64>,
    message: Box<Message>,
}

pub struct Schedule<T> {
    pub due: Instant,
    pub inner: T,
}

pub struct Message {
    pub id: u64,
    pub created: u64,

    pub return_path: String,
    pub return_path_lcase: String,
    pub return_path_domain: String,
    pub recipients: Vec<Recipient>,
    pub domains: Vec<Domain>,
    pub notify: Schedule<u32>,

    pub flags: u64,
    pub priority: i16,
    pub size: usize,

    pub queue_refs: Vec<QueueLimiterRef>,
}

pub struct Domain {
    pub domain: String,
    pub retry: Schedule<u32>,
    pub status: Status,
    pub queue_refs: Vec<QueueLimiterRef>,
}
pub struct Recipient {
    pub domain_idx: usize,
    pub address: String,
    pub address_lcase: String,
    pub status: Status,
    pub flags: u64,
    pub queue_refs: Vec<QueueLimiterRef>,
}

pub enum Status {
    Scheduled,
    Delivered,
    TemporaryFailure(Error),
    PermanentFailure(Error),
}

pub enum Error {
    UnexpectedResponse(Response<String>),
    Timeout,
}

pub struct DeliveryAttempt {
    pub span: tracing::Span,
    pub in_flight: Vec<InFlight>,
    pub message: Box<Message>,
}

pub struct QueueLimiter {
    pub max_size: usize,
    pub max_messages: usize,
    pub size: AtomicUsize,
    pub messages: AtomicUsize,
}

pub struct QueueLimiterRef {
    size: usize,
    limiter: Arc<QueueLimiter>,
}

impl<T> Ord for Schedule<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.due.cmp(&self.due)
    }
}

impl<T> PartialOrd for Schedule<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        other.due.partial_cmp(&self.due)
    }
}

impl<T> PartialEq for Schedule<T> {
    fn eq(&self, other: &Self) -> bool {
        self.due == other.due
    }
}

impl<T> Eq for Schedule<T> {}

impl<T: Default> Schedule<T> {
    pub fn now() -> Self {
        Schedule {
            due: Instant::now(),
            inner: T::default(),
        }
    }
}

pub struct SimpleEnvelope<'x> {
    pub sender: &'x str,
    pub sender_domain: &'x str,
    pub rcpt: &'x str,
    pub rcpt_domain: &'x str,
    pub priority: i16,
}

impl<'x> SimpleEnvelope<'x> {
    pub fn new(
        sender: &'x str,
        sender_domain: &'x str,
        rcpt: &'x str,
        rcpt_domain: &'x str,
        priority: i16,
    ) -> Self {
        Self {
            sender,
            sender_domain,
            rcpt,
            rcpt_domain,
            priority,
        }
    }
}

impl<'x> Envelope for SimpleEnvelope<'x> {
    fn local_ip(&self) -> &std::net::IpAddr {
        unreachable!()
    }

    fn remote_ip(&self) -> &std::net::IpAddr {
        unreachable!()
    }

    fn sender_domain(&self) -> &str {
        self.sender_domain
    }

    fn sender(&self) -> &str {
        self.sender
    }

    fn rcpt_domain(&self) -> &str {
        self.rcpt_domain
    }

    fn rcpt(&self) -> &str {
        self.rcpt
    }

    fn helo_domain(&self) -> &str {
        ""
    }

    fn authenticated_as(&self) -> &str {
        ""
    }

    fn mx(&self) -> &str {
        ""
    }

    fn listener_id(&self) -> u16 {
        0
    }

    fn priority(&self) -> i16 {
        self.priority
    }
}

pub struct QueueEnvelope<'x> {
    pub sender: &'x str,
    pub sender_domain: &'x str,
    pub rcpt_domain: &'x str,
    pub mx: &'x str,
    pub remote_ip: IpAddr,
    pub local_ip: IpAddr,
    pub priority: i16,
}

impl<'x> Envelope for QueueEnvelope<'x> {
    fn local_ip(&self) -> &std::net::IpAddr {
        &self.local_ip
    }

    fn remote_ip(&self) -> &std::net::IpAddr {
        &self.remote_ip
    }

    fn sender_domain(&self) -> &str {
        self.sender_domain
    }

    fn sender(&self) -> &str {
        self.sender
    }

    fn rcpt_domain(&self) -> &str {
        self.rcpt_domain
    }

    fn rcpt(&self) -> &str {
        ""
    }

    fn helo_domain(&self) -> &str {
        ""
    }

    fn authenticated_as(&self) -> &str {
        ""
    }

    fn mx(&self) -> &str {
        self.mx
    }

    fn listener_id(&self) -> u16 {
        0
    }

    fn priority(&self) -> i16 {
        self.priority
    }
}
