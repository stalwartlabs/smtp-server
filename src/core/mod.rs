use std::{
    borrow::Cow,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use smtp_proto::{
    request::receiver::{BdatReceiver, DataReceiver, Receiver},
    MtPriority, Request,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::Span;

use crate::config::{EnvelopeKey, Host, Script, ServerProtocol, Stage};

use self::throttle::{
    ConcurrencyLimiter, InFlightRequest, Limiter, ThrottleKey, ThrottleKeyHasherBuilder,
};

pub mod if_block;
pub mod params;
pub mod throttle;

pub struct Core {
    pub stage: Stage,
    pub concurrency: ConcurrencyLimiter,
    pub throttle: DashMap<ThrottleKey, Limiter, ThrottleKeyHasherBuilder>,
}

pub enum State {
    Request(Receiver<Request<String>>),
    Bdat(BdatReceiver),
    Data(DataReceiver),
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
    pub in_flight: Vec<InFlightRequest>,
}

pub struct SessionData {
    pub local_ip: IpAddr,
    pub remote_ip: IpAddr,
    pub helo_domain: String,
    pub mail_from: String,
    pub mail_from_lcase: String,
    pub rcpt_to: Vec<RcptTo>,
    pub authenticated_as: String,
    pub priority: i16,
    pub valid_until: Instant,
}

pub struct RcptTo {
    pub value: String,
    pub value_lcase: String,
}

#[derive(Debug, Default)]
pub struct SessionParameters {
    // Ehlo parameters
    pub ehlo_script: Option<Arc<Script>>,
    pub ehlo_require: bool,
    pub ehlo_multiple: bool,

    // Supported capabilities
    pub pipelining: bool,
    pub chunking: bool,
    pub requiretls: bool,
    pub starttls: bool,
    pub no_soliciting: Option<String>,
    pub future_release: Option<Duration>,
    pub deliver_by: Option<Duration>,
    pub mt_priority: Option<MtPriority>,
    pub size: Option<usize>,
    pub expn: bool,

    // Auth parameters
    pub auth_script: Option<Arc<Script>>,
    pub auth_require: bool,
    pub auth_host: Option<Arc<Host>>,
    pub auth_mechanisms: u64,
    pub auth_errors_max: usize,
    pub auth_errors_wait: Duration,
}

impl SessionData {
    pub fn new(local_ip: IpAddr, remote_ip: IpAddr) -> Self {
        SessionData {
            local_ip,
            remote_ip,
            helo_domain: String::new(),
            mail_from: String::new(),
            mail_from_lcase: String::new(),
            rcpt_to: Vec::new(),
            authenticated_as: String::new(),
            priority: 0,
            valid_until: Instant::now(),
        }
    }
}

impl Default for State {
    fn default() -> Self {
        State::Request(Receiver::default())
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
            EnvelopeKey::AuthenticatedAs => self.authenticated_as().into(),
            EnvelopeKey::Mx => self.mx().into(),
            EnvelopeKey::HeloDomain => self.helo_domain().into(),
            EnvelopeKey::Listener => self.listener_id().to_string().into(),
            EnvelopeKey::RemoteIp => self.remote_ip().to_string().into(),
            EnvelopeKey::LocalIp => self.local_ip().to_string().into(),
            EnvelopeKey::Priority => self.priority().to_string().into(),
        }
    }
}
