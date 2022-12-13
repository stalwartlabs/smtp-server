pub mod certificate;
pub mod if_block;
pub mod list;
pub mod parser;
pub mod remote;
pub mod rule;
pub mod server;
pub mod stage;
pub mod throttle;
pub mod utils;

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use ahash::{AHashMap, AHashSet};
use rustls::ServerConfig;
use smtp_proto::MtPriority;
use tokio::net::TcpSocket;

#[derive(Debug, Default)]
pub struct Server {
    pub id: String,
    pub internal_id: u64,
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

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Host {}

#[derive(Debug, Default)]
pub struct Script {}

#[derive(Debug, PartialEq, Eq)]
pub enum List {
    Local(AHashSet<String>),
    Remote(Arc<Host>),
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    Condition {
        key: ContextKey,
        op: RuleOp,
        value: RuleValue,
    },
    Logical {
        op: LogicalOp,
        value: Vec<Rule>,
    },
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RuleOp {
    Equal,
    NotEqual,
    StartsWith,
    EndsWith,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LogicalOp {
    And,
    Or,
    Not,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleValue {
    String(String),
    UInt(u64),
    Int(i64),
    IpAddrMask(IpAddrMask),
    List(Arc<List>),
    Regex(String),
}

impl Default for Rule {
    fn default() -> Self {
        Rule::Logical {
            op: LogicalOp::And,
            value: vec![],
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ContextKey {
    Recipient,
    RecipientDomain,
    Sender,
    SenderDomain,
    AuthenticatedAs,
    Listener,
    Mx,
    RemoteIp,
    LocalIp,
    Priority,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct IfThen<T: Default> {
    pub rules: Vec<Rule>,
    pub then: T,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct IfBlock<T: Default> {
    pub if_then: Vec<IfThen<T>>,
    pub default: T,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Throttle {
    pub key: Vec<ContextKey>,
    pub concurrency: IfBlock<u64>,
    pub rate: IfBlock<ThrottleRate>,
}

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
    pub concurrency: IfBlock<u64>,
    pub timeout: IfBlock<Option<Duration>>,
    pub throttle: Vec<Throttle>,
}

pub struct Ehlo {
    pub script: IfBlock<Option<Arc<Script>>>,
    pub require: IfBlock<bool>,
    pub max_commands: IfBlock<Option<u64>>,

    // Capabilities
    pub pipelining: IfBlock<bool>,
    pub chunking: IfBlock<bool>,
    pub requiretls: IfBlock<bool>,
    pub no_soliciting: IfBlock<Option<String>>,
    pub future_release: IfBlock<Option<Duration>>,
    pub deliver_by: IfBlock<Option<Duration>>,
    pub mt_priority: IfBlock<Option<MtPriority>>,
    pub size: IfBlock<Option<usize>>,
    pub expn: IfBlock<bool>,
}

pub struct Auth {
    pub script: IfBlock<Option<Arc<Script>>>,
    pub require: IfBlock<bool>,
    pub auth_host: IfBlock<Option<Arc<Host>>>,
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

pub struct BeforeQueue {
    pub script: IfBlock<Option<Arc<Script>>>,
    pub queue: IfBlock<Arc<Queue>>,
}

pub struct Stage {
    pub connect: Connect,
    pub ehlo: Ehlo,
    pub auth: Auth,
    pub mail: Mail,
    pub rcpt: Rcpt,
    pub data: Data,
    pub queue: BeforeQueue,
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
    pub rules: AHashMap<String, Rule>,
    pub hosts: AHashMap<String, Arc<Host>>,
    pub scripts: AHashMap<String, Arc<Script>>,
    pub lists: AHashMap<String, Arc<List>>,
    pub queues: AHashMap<String, Arc<Queue>>,
}

pub type Result<T> = std::result::Result<T, String>;
