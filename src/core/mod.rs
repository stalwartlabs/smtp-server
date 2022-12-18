use std::{
    borrow::Cow,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use smtp_proto::{
    request::receiver::{BdatReceiver, DataReceiver, DummyDataReceiver, Receiver},
    MtPriority, Request,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::Span;

use crate::config::{EnvelopeKey, Host, Script, ServerProtocol, SessionConfig};

use self::throttle::{
    ConcurrencyLimiter, InFlightRequest, Limiter, ThrottleKey, ThrottleKeyHasherBuilder,
};

pub mod if_block;
pub mod params;
pub mod throttle;

pub struct Core {
    pub config: SessionConfig,
    pub concurrency: ConcurrencyLimiter,
    pub throttle: DashMap<ThrottleKey, Limiter, ThrottleKeyHasherBuilder>,
}

pub enum State {
    Request(Receiver<Request<String>>),
    Bdat(BdatReceiver),
    Data(DataReceiver),
    DataTooLarge(DummyDataReceiver),
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
    pub rcpt_errors: usize,
    pub message: Vec<u8>,
    pub authenticated_as: String,
    pub auth_errors: usize,
    pub priority: i16,
    pub valid_until: Instant,
    pub messages_sent: usize,
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

    // Mail parameters
    pub mail_script: Option<Arc<Script>>,

    // Rcpt parameters
    pub rcpt_script: Option<Arc<Script>>,
    pub rcpt_relay: bool,
    pub rcpt_errors_max: usize,
    pub rcpt_errors_wait: Duration,
    pub rcpt_max: usize,

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
            mail_from: String::new(),
            mail_from_lcase: String::new(),
            rcpt_to: Vec::new(),
            authenticated_as: String::new(),
            priority: 0,
            valid_until: Instant::now(),
            rcpt_errors: 0,
            message: Vec::with_capacity(0),
            auth_errors: 0,
            messages_sent: 0,
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
