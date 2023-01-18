use std::{
    borrow::Cow,
    hash::Hash,
    net::IpAddr,
    sync::{atomic::AtomicU32, Arc},
    time::{Duration, Instant},
};

use dashmap::DashMap;
use mail_auth::{common::lru::LruCache, IprevOutput, Resolver, SpfOutput};
use smtp_proto::request::receiver::{
    BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver, LineReceiver, RequestReceiver,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};
use tokio_rustls::TlsConnector;
use tracing::Span;

use crate::{
    config::{
        EnvelopeKey, List, MailAuthConfig, QueueConfig, ReportConfig, Script, ServerProtocol,
        SessionConfig, VerifyStrategy,
    },
    inbound::auth::SaslToken,
    outbound::{
        dane::{DnssecResolver, Tlsa},
        mta_sts,
    },
    queue::{self, QuotaLimiter},
    reporting,
};

use self::throttle::{
    ConcurrencyLimiter, InFlight, Limiter, ThrottleKey, ThrottleKeyHasherBuilder,
};

pub mod if_block;
pub mod params;
pub mod throttle;
pub mod worker;

pub struct Core {
    pub worker_pool: rayon::ThreadPool,
    pub session: SessionCore,
    pub queue: QueueCore,
    pub resolvers: Resolvers,
    pub mail_auth: MailAuthConfig,
    pub report: ReportCore,
}

pub struct Resolvers {
    pub dns: Resolver,
    pub dnssec: DnssecResolver,
    pub cache: DnsCache,
}

pub struct DnsCache {
    pub tlsa: LruCache<String, Arc<Tlsa>>,
    pub mta_sts: LruCache<String, Arc<mta_sts::Policy>>,
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
    pub connectors: TlsConnectors,
}

pub struct ReportCore {
    pub config: ReportConfig,
    pub tx: mpsc::Sender<reporting::Event>,
}

pub struct TlsConnectors {
    pub pki_verify: TlsConnector,
    pub dummy_verify: TlsConnector,
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
    pub delivery_by: i64,
    pub future_release: u64,

    pub valid_until: Instant,
    pub bytes_left: usize,
    pub messages_sent: usize,

    pub iprev: Option<IprevOutput>,
    pub spf_ehlo: Option<SpfOutput>,
    pub spf_mail_from: Option<SpfOutput>,
}

pub struct SessionAddress {
    pub address: String,
    pub address_lcase: String,
    pub domain: String,
    pub flags: u64,
    pub dsn_info: Option<String>,
}

#[derive(Debug, Default)]
pub struct SessionParameters {
    // Global parameters
    pub timeout: Duration,

    // Ehlo parameters
    pub ehlo_script: Option<Arc<Script>>,
    pub ehlo_require: bool,

    // Auth parameters
    pub auth_script: Option<Arc<Script>>,
    pub auth_lookup: Option<Arc<List>>,
    pub auth_errors_max: usize,
    pub auth_errors_wait: Duration,

    // Rcpt parameters
    pub rcpt_script: Option<Arc<Script>>,
    pub rcpt_relay: bool,
    pub rcpt_errors_max: usize,
    pub rcpt_errors_wait: Duration,
    pub rcpt_max: usize,
    pub rcpt_dsn: bool,
    pub rcpt_lookup_domain: Option<Arc<List>>,
    pub rcpt_lookup_addresses: Option<Arc<List>>,
    pub rcpt_lookup_expn: Option<Arc<List>>,
    pub rcpt_lookup_vrfy: Option<Arc<List>>,
    pub max_message_size: usize,

    // Mail authentication parameters
    pub iprev: VerifyStrategy,
    pub spf_ehlo: VerifyStrategy,
    pub spf_mail_from: VerifyStrategy,
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
            iprev: None,
            spf_ehlo: None,
            spf_mail_from: None,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        State::Request(RequestReceiver::default())
    }
}

pub trait Envelope {
    fn local_ip(&self) -> IpAddr;
    fn remote_ip(&self) -> IpAddr;
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

impl VerifyStrategy {
    #[inline(always)]
    pub fn verify(&self) -> bool {
        matches!(self, VerifyStrategy::Strict | VerifyStrategy::Relaxed)
    }

    #[inline(always)]
    pub fn is_strict(&self) -> bool {
        matches!(self, VerifyStrategy::Strict)
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
