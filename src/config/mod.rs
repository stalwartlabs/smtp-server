pub mod certificate;
pub mod condition;
pub mod parser;
pub mod server;
pub mod stage;
pub mod throttle;
pub mod utils;

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

use rustls::ServerConfig;
use smtp_proto::MtPriority;
use tokio::net::TcpListener;

pub struct Server {
    pub id: String,
    pub hostname: String,
    pub greeting: String,
    pub protocol: ServerProtocol,
    pub listeners: Vec<TcpListener>,
    pub tls: Option<ServerConfig>,
    pub tls_implicit: bool,
}

pub enum ServerProtocol {
    Smtp,
    Lmtp,
}

pub enum Condition {
    Recipient(Vec<StringMatch>),
    RecipientDomain(Vec<StringMatch>),
    Sender(Vec<StringMatch>),
    SenderDomain(Vec<StringMatch>),
    Listener(Vec<String>),
    Mx(Vec<StringMatch>),
    RemoteIp(Vec<IpAddrMask>),
    LocalIp(Vec<IpAddrMask>),
    Priority(Vec<i64>),
}

pub enum StringMatch {
    EqualTo(String),
    StartsWith(String),
    EndsWith(String),
    InList(String),
    RegexMatch(String),
}

pub enum ThrottleKey {
    RecipientDomain,
    SenderDomain,
    Listener,
    Mx,
    RemoteIp,
    LocalIp,
}

pub struct Throttle {
    pub key: Vec<ThrottleKey>,
    pub concurrency: u64,
    pub rate_requests: u64,
    pub rate_period: u64,
}

pub enum IpAddrMask {
    V4 { addr: Ipv4Addr, mask: u32 },
    V6 { addr: Ipv6Addr, mask: u128 },
}

pub struct ConnectStage {
    pub script: String,
    pub concurrency: u64,
    pub pipelining: bool,
    pub throttle: Vec<Throttle>,
}

pub struct EhloStage {
    pub script: String,
    pub require: bool,
    pub spf: AuthLevel,
    pub timeout: u64,
    pub max_commands: u64,

    // Capabilities
    pub pipelining: bool,
    pub chunking: bool,
    pub requiretls: bool,
    pub no_soliciting: Option<String>,
    pub auth: u64,
    pub future_release: Option<u64>,
    pub deliver_by: Option<u64>,
    pub mt_priority: MtPriority,
    pub size: Option<usize>,
    pub expn: bool,
}

pub struct AuthStage {
    pub script: String,
    pub require: bool,
    pub auth_host: usize,
    pub timeout: u64,
    pub errors_max: usize,
    pub errors_wait: u64,
}

pub struct MailStage {
    pub script: String,
    pub spf: AuthLevel,
    pub timeout: u64,
}

pub struct RcptStage {
    pub script: String,
    pub timeout: u64,

    // Lookup
    pub local_domains: usize,
    pub local_addresses: usize,

    // Recipient cache
    pub cache_size: usize,
    pub cache_ttl_positive: u64,
    pub cache_ttl_negative: u64,

    // Errors
    pub errors_max: usize,
    pub errors_wait: usize,

    // Limits
    pub max_recipients: usize,
}

pub struct DataStage {
    pub script: String,
    pub timeout: u64,

    // Message Authentication
    pub dkim: AuthLevel,
    pub arc: AuthLevel,
    pub dmarc: AuthLevel,

    // Limits
    pub max_messages: usize,
    pub max_message_size: usize,
    pub max_received_headers: usize,
    pub max_mime_parts: usize,
    pub max_nested_messages: usize,

    // Headers
    pub add_received: bool,
    pub add_received_spf: bool,
    pub add_auth_results: bool,
    pub add_dkim_signature: bool,
    pub add_arc_seal: bool,
    pub add_message_id: bool,
    pub add_date: bool,
}

pub enum AuthLevel {
    Enable,
    Disable,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    keys: BTreeMap<String, String>,
}

pub type Result<T> = std::result::Result<T, String>;
