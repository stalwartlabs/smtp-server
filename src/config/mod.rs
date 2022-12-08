pub mod certificate;
pub mod parser;
pub mod server;
pub mod utils;

use std::collections::BTreeMap;

use rustls::ServerConfig;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    keys: BTreeMap<String, String>,
}

pub type Result<T> = std::result::Result<T, String>;
