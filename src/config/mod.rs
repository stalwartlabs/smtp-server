pub mod certificate;
pub mod condition;
pub mod if_block;
pub mod list;
pub mod parser;
pub mod remote;
pub mod resolver;
pub mod server;
pub mod session;
pub mod throttle;
pub mod utils;

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use ahash::{AHashMap, AHashSet};
use regex::Regex;
use rustls::ServerConfig;
use smtp_proto::MtPriority;
use tokio::{net::TcpSocket, sync::mpsc};

use crate::remote::lookup::{self, LookupChannel};

#[derive(Debug, Default)]
pub struct Server {
    pub id: String,
    pub internal_id: u16,
    pub hostname: String,
    pub greeting: String,
    pub protocol: ServerProtocol,
    pub listeners: Vec<Listener>,
    pub tls: Option<ServerConfig>,
    pub tls_implicit: bool,
}

#[derive(Debug)]
pub struct Listener {
    pub socket: TcpSocket,
    pub addr: SocketAddr,
    pub ttl: Option<u32>,
    pub backlog: Option<u32>,
}

#[derive(Debug)]
pub struct Host {
    pub address: String,
    pub port: u16,
    pub protocol: ServerProtocol,
    pub concurrency: usize,
    pub timeout: Duration,
    pub tls_implicit: bool,
    pub tls_allow_invalid_certs: bool,
    pub username: Option<String>,
    pub secret: Option<String>,
    pub cache_entries: usize,
    pub cache_ttl_positive: Duration,
    pub cache_ttl_negative: Duration,
    pub channel_tx: mpsc::Sender<lookup::Event>,
    pub channel_rx: mpsc::Receiver<lookup::Event>,
    pub ref_count: usize,
}

#[derive(Debug, Default)]
pub struct Script {}

#[derive(Debug)]
pub enum List {
    Local(AHashSet<String>),
    Remote(LookupChannel),
}

impl Default for List {
    fn default() -> Self {
        List::Local(AHashSet::default())
    }
}

#[derive(Debug, Default)]
pub struct Queue {}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum ServerProtocol {
    #[default]
    Smtp,
    Lmtp,
    Imap,
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum Condition {
    Match {
        key: EnvelopeKey,
        op: ConditionOp,
        value: ConditionValue,
        not: bool,
    },
    JumpIfTrue {
        positions: usize,
    },
    JumpIfFalse {
        positions: usize,
    },
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConditionOp {
    Equal,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone)]
pub enum ConditionValue {
    String(String),
    UInt(u16),
    Int(i16),
    IpAddrMask(IpAddrMask),
    List(Arc<List>),
    Regex(Regex),
}

#[cfg(test)]
impl PartialEq for ConditionValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(l0), Self::String(r0)) => l0 == r0,
            (Self::UInt(l0), Self::UInt(r0)) => l0 == r0,
            (Self::Int(l0), Self::Int(r0)) => l0 == r0,
            (Self::IpAddrMask(l0), Self::IpAddrMask(r0)) => l0 == r0,
            (Self::List(l0), Self::List(r0)) => l0 == r0,
            (Self::Regex(_), Self::Regex(_)) => false,
            _ => false,
        }
    }
}

#[cfg(test)]
impl Eq for ConditionValue {}

#[cfg(test)]
impl PartialEq for List {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Local(l0), Self::Local(r0)) => l0 == r0,
            (Self::Remote(_), Self::Remote(_)) => true,
            _ => false,
        }
    }
}

impl Default for Condition {
    fn default() -> Self {
        Condition::JumpIfFalse { positions: 0 }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EnvelopeKey {
    Recipient,
    RecipientDomain,
    Sender,
    SenderDomain,
    HeloDomain,
    AuthenticatedAs,
    Listener,
    Mx,
    RemoteIp,
    LocalIp,
    Priority,
}

#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct IfThen<T: Default> {
    pub conditions: Conditions,
    pub then: T,
}

#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Conditions {
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct IfBlock<T: Default> {
    pub if_then: Vec<IfThen<T>>,
    pub default: T,
}

#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Throttle {
    pub conditions: Conditions,
    pub keys: u16,
    pub concurrency: Option<u64>,
    pub rate: Option<ThrottleRate>,
}

pub const THROTTLE_RCPT: u16 = 1 << 0;
pub const THROTTLE_RCPT_DOMAIN: u16 = 1 << 1;
pub const THROTTLE_SENDER: u16 = 1 << 2;
pub const THROTTLE_SENDER_DOMAIN: u16 = 1 << 3;
pub const THROTTLE_AUTH_AS: u16 = 1 << 4;
pub const THROTTLE_LISTENER: u16 = 1 << 5;
pub const THROTTLE_MX: u16 = 1 << 6;
pub const THROTTLE_REMOTE_IP: u16 = 1 << 7;
pub const THROTTLE_LOCAL_IP: u16 = 1 << 8;
pub const THROTTLE_HELO_DOMAIN: u16 = 1 << 9;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ThrottleRate {
    pub requests: u64,
    pub period: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpAddrMask {
    V4 { addr: Ipv4Addr, mask: u32 },
    V6 { addr: Ipv6Addr, mask: u128 },
}

pub struct Connect {
    pub script: IfBlock<Option<Arc<Script>>>,
    pub throttle: Vec<Throttle>,
}

pub struct Ehlo {
    pub script: IfBlock<Option<Arc<Script>>>,
    pub require: IfBlock<bool>,
    pub multiple: IfBlock<bool>,

    // Capabilities
    pub pipelining: IfBlock<bool>,
    pub chunking: IfBlock<bool>,
    pub requiretls: IfBlock<bool>,
    pub no_soliciting: IfBlock<Option<String>>,
    pub future_release: IfBlock<Option<Duration>>,
    pub deliver_by: IfBlock<Option<Duration>>,
    pub mt_priority: IfBlock<Option<MtPriority>>,
    pub size: IfBlock<Option<usize>>,
}

pub struct Auth {
    pub script: IfBlock<Option<Arc<Script>>>,
    pub require: IfBlock<bool>,
    pub lookup: IfBlock<Option<Arc<List>>>,
    pub mechanisms: IfBlock<u64>,
    pub errors_max: IfBlock<usize>,
    pub errors_wait: IfBlock<Duration>,
}

pub struct Mail {
    pub script: IfBlock<Option<Arc<Script>>>,
    pub throttle: Vec<Throttle>,
}

pub struct Rcpt {
    pub script: IfBlock<Option<Arc<Script>>>,
    pub relay: IfBlock<bool>,
    pub expn: IfBlock<bool>,
    pub vrfy: IfBlock<bool>,
    pub lookup_domains: IfBlock<Option<Arc<List>>>,
    pub lookup_addresses: IfBlock<Option<Arc<List>>>,

    // Errors
    pub errors_max: IfBlock<usize>,
    pub errors_wait: IfBlock<Duration>,

    // Limits
    pub max_recipients: IfBlock<usize>,

    // Throttle
    pub throttle: Vec<Throttle>,
}

pub struct Data {
    pub script: IfBlock<Option<Arc<Script>>>,

    // Limits
    pub max_messages: IfBlock<usize>,
    pub max_message_size: IfBlock<usize>,
    pub max_received_headers: IfBlock<usize>,
    pub max_mime_parts: IfBlock<usize>,
    pub max_nested_messages: IfBlock<usize>,

    // Headers
    pub add_received: IfBlock<bool>,
    pub add_received_spf: IfBlock<bool>,
    pub add_return_path: IfBlock<bool>,
    pub add_auth_results: IfBlock<bool>,
    pub add_message_id: IfBlock<bool>,
    pub add_date: IfBlock<bool>,
}

pub struct SessionConfig {
    pub timeout: IfBlock<Duration>,
    pub duration: IfBlock<Duration>,
    pub transfer_limit: IfBlock<usize>,

    pub connect: Connect,
    pub ehlo: Ehlo,
    pub auth: Auth,
    pub mail: Mail,
    pub rcpt: Rcpt,
    pub data: Data,
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

#[derive(Debug, Default)]
pub struct ConfigContext {
    pub servers: Vec<Server>,
    pub hosts: AHashMap<String, Host>,
    pub scripts: AHashMap<String, Arc<Script>>,
    pub lists: AHashMap<String, Arc<List>>,
    pub queues: AHashMap<String, Arc<Queue>>,
}

pub type Result<T> = std::result::Result<T, String>;
