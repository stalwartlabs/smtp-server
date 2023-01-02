use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{atomic::AtomicUsize, Arc},
    time::{Duration, Instant},
};

use smtp_proto::Response;

use crate::core::{
    throttle::{ConcurrencyLimiter, InFlight},
    Envelope,
};

pub mod dane;
pub mod delivery;
pub mod dsn;
pub mod manager;
pub mod quota;
pub mod session;
pub mod spool;
pub mod throttle;

pub enum Event {
    Queue(Schedule<Box<Message>>),
    Done(WorkerResult),
    Stop,
}

pub enum WorkerResult {
    Done,
    Retry(Schedule<Box<Message>>),
    OnHold(OnHold),
}

pub struct OnHold {
    next_due: Option<Instant>,
    limiters: Vec<ConcurrencyLimiter>,
    message: Box<Message>,
}

pub struct Schedule<T> {
    pub due: Instant,
    pub inner: T,
}

pub struct Message {
    pub id: u64,
    pub created: u64,
    pub path: PathBuf,

    pub return_path: String,
    pub return_path_lcase: String,
    pub return_path_domain: String,
    pub recipients: Vec<Recipient>,
    pub domains: Vec<Domain>,

    pub flags: u64,
    pub priority: i16,
    pub size: usize,

    pub queue_refs: Vec<UsedQuota>,
}

pub struct Domain {
    pub domain: String,
    pub retry: Schedule<u32>,
    pub notify: Schedule<u32>,
    pub expires: Instant,
    pub status: Status,
}
pub struct Recipient {
    pub domain_idx: usize,
    pub address: String,
    pub address_lcase: String,
    pub status: Status,
    pub flags: u64,
}

pub enum Status {
    Scheduled,
    Delivered,
    TemporaryFailure(Error),
    PermanentFailure(Error),
}

pub enum Error {
    DnsError(String),
    UnexpectedResponse {
        message: String,
        response: Response<String>,
    },
    ConnectionError(String),
    DaneError(String),
    RateLimited,
    ConcurrencyLimited,
}

pub struct DeliveryAttempt {
    pub span: tracing::Span,
    pub in_flight: Vec<InFlight>,
    pub message: Box<Message>,
}

pub struct QuotaLimiter {
    pub max_size: usize,
    pub max_messages: usize,
    pub size: AtomicUsize,
    pub messages: AtomicUsize,
}

pub struct UsedQuota {
    id: u64,
    size: usize,
    limiter: Arc<QuotaLimiter>,
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

    pub fn later(duration: Duration) -> Self {
        Schedule {
            due: Instant::now() + duration,
            inner: T::default(),
        }
    }
}

pub struct SimpleEnvelope<'x> {
    pub message: &'x Message,
    pub domain: &'x str,
    pub recipient: &'x str,
}

impl<'x> SimpleEnvelope<'x> {
    pub fn new(message: &'x Message, domain: &'x str) -> Self {
        Self {
            message,
            domain,
            recipient: "",
        }
    }

    pub fn new_rcpt(message: &'x Message, domain: &'x str, recipient: &'x str) -> Self {
        Self {
            message,
            domain,
            recipient,
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
        &self.message.return_path_domain
    }

    fn sender(&self) -> &str {
        &self.message.return_path_lcase
    }

    fn rcpt_domain(&self) -> &str {
        self.domain
    }

    fn rcpt(&self) -> &str {
        self.recipient
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
        self.message.priority
    }
}

pub struct QueueEnvelope<'x> {
    pub message: &'x Message,
    pub domain: &'x str,
    pub mx: &'x str,
    pub remote_ip: IpAddr,
    pub local_ip: IpAddr,
}

impl<'x> Envelope for QueueEnvelope<'x> {
    fn local_ip(&self) -> &std::net::IpAddr {
        &self.local_ip
    }

    fn remote_ip(&self) -> &std::net::IpAddr {
        &self.remote_ip
    }

    fn sender_domain(&self) -> &str {
        &self.message.return_path_domain
    }

    fn sender(&self) -> &str {
        &self.message.return_path_lcase
    }

    fn rcpt_domain(&self) -> &str {
        self.domain
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
        self.message.priority
    }
}

impl Envelope for Message {
    fn local_ip(&self) -> &IpAddr {
        unreachable!()
    }

    fn remote_ip(&self) -> &IpAddr {
        unreachable!()
    }

    fn sender_domain(&self) -> &str {
        &self.return_path_domain
    }

    fn sender(&self) -> &str {
        &self.return_path_lcase
    }

    fn rcpt_domain(&self) -> &str {
        ""
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
        ""
    }

    fn listener_id(&self) -> u16 {
        0
    }

    fn priority(&self) -> i16 {
        self.priority
    }
}
