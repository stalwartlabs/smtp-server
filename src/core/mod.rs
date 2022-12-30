use std::{
    borrow::Cow,
    hash::Hash,
    net::IpAddr,
    sync::{atomic::AtomicU32, Arc},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use mail_auth::Resolver;
use smtp_proto::{
    request::receiver::{
        BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver, LineReceiver,
        RequestReceiver,
    },
    MtPriority,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};
use tracing::Span;

use crate::{
    config::{EnvelopeKey, List, QueueConfig, Script, ServerProtocol, SessionConfig},
    listener::auth::SaslToken,
    queue::{self, QuotaLimiter},
};

use self::throttle::{
    ConcurrencyLimiter, InFlight, Limiter, ThrottleKey, ThrottleKeyHasherBuilder,
};

pub mod if_block;
pub mod params;
pub mod throttle;

pub struct Core {
    pub session: SessionCore,
    pub queue: QueueCore,
    pub resolver: Resolver,
}

pub struct SessionCore {
    pub config: SessionConfig,
    pub concurrency: ConcurrencyLimiter,
    pub throttle: DashMap<ThrottleKey, Limiter, ThrottleKeyHasherBuilder>,
}

pub struct QueueCore {
    pub config: QueueConfig,
    pub throttle: DashMap<ThrottleKey, Limiter, ThrottleKeyHasherBuilder>,
    pub quota: DashMap<ThrottleKey, Arc<QuotaLimiter>, ThrottleKeyHasherBuilder>,
    pub tx: mpsc::Sender<queue::Event>,
    pub id_seq: AtomicU32,
}

pub enum State {
    Request(RequestReceiver),
    Bdat(BdatReceiver),
    Data(DataReceiver),
    Sasl(LineReceiver<SaslToken>),
    DataTooLarge(DummyDataReceiver),
    RequestTooLarge(DummyLineReceiver),
    None,
}

pub struct ServerInstance {
    pub id: String,
    pub listener_id: u16,
    pub protocol: ServerProtocol,
    pub hostname: String,
    pub greeting: Vec<u8>,
}

pub struct Session<T: AsyncWrite + AsyncRead> {
    pub state: State,
    pub instance: Arc<ServerInstance>,
    pub core: Arc<Core>,
    pub span: Span,
    pub stream: T,
    pub data: SessionData,
    pub params: SessionParameters,
    pub in_flight: Vec<InFlight>,
}

pub struct SessionData {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub helo_domain: String,

    pub mail_from: Option<SessionAddress>,
    pub rcpt_to: Vec<SessionAddress>,
    pub rcpt_errors: usize,
    pub message: Vec<u8>,

    pub authenticated_as: String,
    pub auth_errors: usize,

    pub priority: i16,
    pub delivery_by: u64,
    pub future_release: u64,

    pub valid_until: Instant,
    pub bytes_left: usize,
    pub messages_sent: usize,
}

pub struct SessionAddress {
    pub address: String,
    pub address_lcase: String,
    pub domain: String,
    pub flags: u64,
}

#[derive(Debug, Default)]
pub struct SessionParameters {
    // Global parameters
    pub timeout: Duration,

    // Ehlo parameters
    pub ehlo_script: Option<Arc<Script>>,
    pub ehlo_require: bool,

    // Supported capabilities
    pub pipelining: bool,
    pub chunking: bool,
    pub requiretls: bool,
    pub starttls: bool,
    pub expn: bool,
    pub vrfy: bool,
    pub no_soliciting: Option<String>,
    pub future_release: Option<Duration>,
    pub deliver_by: Option<Duration>,
    pub mt_priority: Option<MtPriority>,
    pub size: Option<usize>,
    pub auth: u64,

    // Auth parameters
    pub auth_script: Option<Arc<Script>>,
    pub auth_lookup: Option<Arc<List>>,
    pub auth_errors_max: usize,
    pub auth_errors_wait: Duration,

    // Mail parameters
    pub mail_script: Option<Arc<Script>>,

    // Rcpt parameters
    pub rcpt_script: Option<Arc<Script>>,
    pub rcpt_relay: bool,
    pub rcpt_errors_max: usize,
    pub rcpt_errors_wait: Duration,
    pub rcpt_max: usize,
    pub rcpt_lookup_domain: Option<Arc<List>>,
    pub rcpt_lookup_addresses: Option<Arc<List>>,
    pub rcpt_lookup_expn: Option<Arc<List>>,
    pub rcpt_lookup_vrfy: Option<Arc<List>>,

    // Data parameters
    pub data_script: Option<Arc<Script>>,
    pub data_max_messages: usize,
    pub data_max_message_size: usize,
    pub data_max_received_headers: usize,
    pub data_max_mime_parts: usize,
    pub data_max_nested_messages: usize,
    pub data_add_received: bool,
    pub data_add_received_spf: bool,
    pub data_add_return_path: bool,
    pub data_add_auth_results: bool,
    pub data_add_message_id: bool,
    pub data_add_date: bool,
}

impl SessionData {
    pub fn new(local_ip: IpAddr, remote_ip: IpAddr) -> Self {
        SessionData {
            local_ip,
            remote_ip,
            helo_domain: String::new(),
            mail_from: None,
            rcpt_to: Vec::new(),
            authenticated_as: String::new(),
            priority: 0,
            valid_until: Instant::now(),
            rcpt_errors: 0,
            message: Vec::with_capacity(0),
            auth_errors: 0,
            messages_sent: 0,
            bytes_left: 0,
            delivery_by: 0,
            future_release: 0,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        State::Request(RequestReceiver::default())
    }
}

pub trait Envelope {
    fn local_ip(&self) -> &IpAddr;
    fn remote_ip(&self) -> &IpAddr;
    fn sender_domain(&self) -> &str;
    fn sender(&self) -> &str;
    fn rcpt_domain(&self) -> &str;
    fn rcpt(&self) -> &str;
    fn helo_domain(&self) -> &str;
    fn authenticated_as(&self) -> &str;
    fn mx(&self) -> &str;
    fn listener_id(&self) -> u16;
    fn priority(&self) -> i16;

    #[inline(always)]
    fn key_to_string(&self, key: &EnvelopeKey) -> Cow<'_, str> {
        match key {
            EnvelopeKey::Recipient => self.rcpt().into(),
            EnvelopeKey::RecipientDomain => self.rcpt_domain().into(),
            EnvelopeKey::Sender => self.sender().into(),
            EnvelopeKey::SenderDomain => self.sender_domain().into(),
            EnvelopeKey::Mx => self.mx().into(),
            EnvelopeKey::AuthenticatedAs => self.authenticated_as().into(),
            EnvelopeKey::HeloDomain => self.helo_domain().into(),
            EnvelopeKey::Listener => self.listener_id().to_string().into(),
            EnvelopeKey::RemoteIp => self.remote_ip().to_string().into(),
            EnvelopeKey::LocalIp => self.local_ip().to_string().into(),
            EnvelopeKey::Priority => self.priority().to_string().into(),
        }
    }
}

impl PartialEq for SessionAddress {
    fn eq(&self, other: &Self) -> bool {
        self.address_lcase == other.address_lcase
    }
}

impl Eq for SessionAddress {}

impl Hash for SessionAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.address_lcase.hash(state);
    }
}

impl Ord for SessionAddress {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.domain.cmp(&other.domain) {
            std::cmp::Ordering::Equal => self.address_lcase.cmp(&other.address_lcase),
            order => order,
        }
    }
}

impl PartialOrd for SessionAddress {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.domain.partial_cmp(&other.domain) {
            Some(std::cmp::Ordering::Equal) => self.address_lcase.partial_cmp(&other.address_lcase),
            order => order,
        }
    }
}
