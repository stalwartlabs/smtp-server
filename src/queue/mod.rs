use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{atomic::AtomicUsize, Arc},
    time::{Duration, Instant, SystemTime},
};

use smtp_proto::Response;

use crate::core::{
    throttle::{ConcurrencyLimiter, InFlight},
    Envelope,
};

pub mod dsn;
pub mod manager;
pub mod quota;
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
    pub next_due: Option<Instant>,
    pub limiters: Vec<ConcurrencyLimiter>,
    pub message: Box<Message>,
}

#[derive(Debug)]
pub struct Schedule<T> {
    pub due: Instant,
    pub inner: T,
}

#[derive(Debug)]
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
    pub env_id: Option<String>,
    pub priority: i16,

    pub size: usize,
    pub size_headers: usize,

    pub queue_refs: Vec<UsedQuota>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Domain {
    pub domain: String,
    pub retry: Schedule<u32>,
    pub notify: Schedule<u32>,
    pub expires: Instant,
    pub status: Status<(), Error>,
    pub changed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Recipient {
    pub domain_idx: usize,
    pub address: String,
    pub address_lcase: String,
    pub status: Status<HostResponse<String>, HostResponse<ErrorDetails>>,
    pub flags: u64,
    pub orcpt: Option<String>,
}

pub const RCPT_DSN_SENT: u64 = 1 << 32;
pub const RCPT_STATUS_CHANGED: u64 = 2 << 32;

#[derive(Debug, PartialEq, Eq)]
pub enum Status<T, E> {
    Scheduled,
    Completed(T),
    TemporaryFailure(E),
    PermanentFailure(E),
}

#[derive(Debug, PartialEq, Eq)]
pub struct HostResponse<T> {
    pub hostname: T,
    pub response: Response<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    DnsError(String),
    UnexpectedResponse(HostResponse<ErrorDetails>),
    ConnectionError(ErrorDetails),
    TlsError(ErrorDetails),
    DaneError(ErrorDetails),
    MtaStsError(String),
    RateLimited,
    ConcurrencyLimited,
    Io(String),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ErrorDetails {
    pub entity: String,
    pub details: String,
}

pub struct DeliveryAttempt {
    pub span: tracing::Span,
    pub in_flight: Vec<InFlight>,
    pub message: Box<Message>,
}

#[derive(Debug)]
pub struct QuotaLimiter {
    pub max_size: usize,
    pub max_messages: usize,
    pub size: AtomicUsize,
    pub messages: AtomicUsize,
}

#[derive(Debug)]
pub struct UsedQuota {
    id: u64,
    size: usize,
    limiter: Arc<QuotaLimiter>,
}

impl PartialEq for UsedQuota {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.size == other.size
    }
}

impl Eq for UsedQuota {}

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

impl Envelope for &str {
    fn local_ip(&self) -> &IpAddr {
        unreachable!()
    }

    fn remote_ip(&self) -> &IpAddr {
        unreachable!()
    }

    fn sender_domain(&self) -> &str {
        ""
    }

    fn sender(&self) -> &str {
        ""
    }

    fn rcpt_domain(&self) -> &str {
        self
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
        0
    }
}

#[inline(always)]
pub fn instant_to_timestamp(now: Instant, time: Instant) -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
        + time.checked_duration_since(now).map_or(0, |d| d.as_secs())
}

pub trait DomainPart {
    fn domain_part(&self) -> &str;
}

impl DomainPart for &str {
    #[inline(always)]
    fn domain_part(&self) -> &str {
        self.rsplit_once('@').map(|(_, d)| d).unwrap_or_default()
    }
}

impl DomainPart for String {
    #[inline(always)]
    fn domain_part(&self) -> &str {
        self.rsplit_once('@').map(|(_, d)| d).unwrap_or_default()
    }
}

#[cfg(test)]
impl Default for crate::config::QueueConfig {
    fn default() -> Self {
        use crate::config::{
            Dsn, IfBlock, QueueOutboundSourceIp, QueueOutboundTimeout, QueueOutboundTls,
            QueueQuotas, QueueThrottle,
        };

        Self {
            path: Default::default(),
            hash: Default::default(),
            retry: IfBlock::new(vec![Duration::from_secs(10)]),
            notify: IfBlock::new(vec![Duration::from_secs(20)]),
            expire: IfBlock::new(Duration::from_secs(10)),
            hostname: IfBlock::new("mx.example.org".to_string()),
            next_hop: Default::default(),
            max_mx: IfBlock::new(5),
            max_multihomed: IfBlock::new(5),
            source_ip: QueueOutboundSourceIp {
                ipv4: IfBlock::new(vec![]),
                ipv6: IfBlock::new(vec![]),
            },
            tls: QueueOutboundTls {
                dane: IfBlock::new(crate::config::RequireOptional::Optional),
                mta_sts: IfBlock::new(crate::config::RequireOptional::Optional),
                start: IfBlock::new(crate::config::RequireOptional::Optional),
            },
            dsn: Dsn {
                name: IfBlock::new("Mail Delivery Subsystem".to_string()),
                address: IfBlock::new("MAILER-DAEMON@example.org".to_string()),
                sign: IfBlock::default(),
            },
            timeout: QueueOutboundTimeout {
                connect: IfBlock::new(Duration::from_secs(1)),
                greeting: IfBlock::new(Duration::from_secs(1)),
                tls: IfBlock::new(Duration::from_secs(1)),
                ehlo: IfBlock::new(Duration::from_secs(1)),
                mail: IfBlock::new(Duration::from_secs(1)),
                rcpt: IfBlock::new(Duration::from_secs(1)),
                data: IfBlock::new(Duration::from_secs(1)),
                mta_sts: IfBlock::new(Duration::from_secs(1)),
            },
            throttle: QueueThrottle {
                sender: vec![],
                rcpt: vec![],
                host: vec![],
            },
            quota: QueueQuotas {
                sender: vec![],
                rcpt: vec![],
                rcpt_domain: vec![],
            },
        }
    }
}
