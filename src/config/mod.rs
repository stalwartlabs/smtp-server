pub mod certificate;
pub mod condition;
pub mod if_block;
pub mod parser;
pub mod server;
pub mod stage;
pub mod throttle;
pub mod utils;

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use ahash::AHashMap;
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

pub struct Conditions {
    pub conditions: Vec<Condition>,
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

pub struct IfThen<T: Default> {
    pub conditions: Vec<Arc<Conditions>>,
    pub then: T,
}

#[derive(Default)]
pub struct IfBlock<T: Default> {
    pub if_then: Vec<IfThen<T>>,
    pub default: T,
}

pub struct Throttle {
    pub key: Vec<ThrottleKey>,
    pub concurrency: IfBlock<u64>,
    pub rate: IfBlock<ThrottleRate>,
}

#[derive(Default)]
pub struct ThrottleRate {
    pub requests: u64,
    pub period: Duration,
}

pub enum IpAddrMask {
    V4 { addr: Ipv4Addr, mask: u32 },
    V6 { addr: Ipv6Addr, mask: u128 },
}

pub struct Connect {
    pub script: Option<IfBlock<String>>,
    pub concurrency: IfBlock<u64>,
    pub throttle: Vec<Throttle>,
}

pub struct Ehlo {
    pub script: String,
    pub require: bool,
    pub timeout: u64,
    pub max_commands: u64,

    // Capabilities
    pub pipelining: bool,
    pub chunking: bool,
    pub requiretls: bool,
    pub no_soliciting: Option<String>,
    pub future_release: Option<u64>,
    pub deliver_by: Option<u64>,
    pub mt_priority: MtPriority,
    pub size: Option<usize>,
    pub expn: bool,
}

pub struct Auth {
    pub script: String,
    pub require: bool,
    pub auth_host: usize,
    pub mechanisms: u64,
    pub timeout: u64,
    pub errors_max: usize,
    pub errors_wait: u64,
}

pub struct Mail {
    pub script: String,
    pub spf: AuthLevel,
    pub timeout: u64,
    pub throttle: Vec<Throttle>,
}

pub struct Rcpt {
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

    // Throttle
    pub throttle: Vec<Throttle>,
}

pub struct Data {
    pub script: String,
    pub timeout: u64,

    // Limits
    pub max_messages: usize,
    pub max_message_size: usize,
    pub max_received_headers: usize,
    pub max_mime_parts: usize,
    pub max_nested_messages: usize,

    // Headers
    pub add_received: bool,
    pub add_received_spf: bool,
    pub add_return_path: bool,
    pub add_auth_results: bool,
    pub add_message_id: bool,
    pub add_date: bool,
}

pub struct Queue {
    pub script: String,
    pub queue_id: usize,
}

pub struct Stage {
    pub connect: Connect,
    pub ehlo: Ehlo,
    pub auth: Auth,
    pub mail: Mail,
    pub rcpt: Rcpt,
    pub data: Data,
    pub queue: Queue,
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

pub struct ConfigContext {
    pub rules: AHashMap<String, Arc<Conditions>>,
}

pub type Result<T> = std::result::Result<T, String>;
