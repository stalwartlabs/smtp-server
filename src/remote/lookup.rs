use std::{collections::VecDeque, fmt::Debug, sync::Arc, time::Duration};

use crate::config::{Config, Host, ServerProtocol};
use mail_send::{smtp::tls::build_tls_connector, Credentials, SmtpClientBuilder};
use tokio::sync::{mpsc, oneshot};

use super::{cache::LookupCache, imap::ImapAuthClientBuilder};

#[derive(Debug)]
pub enum Event {
    Lookup(Lookup),
    WorkerReady {
        item: Item,
        result: bool,
        next_lookup: Option<oneshot::Sender<Option<Lookup>>>,
    },
    WorkerFailed,
    Reload,
    Stop,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Item {
    Entry(String),
    Credentials(Credentials<String>),
}

#[derive(Debug)]
pub struct Lookup {
    pub item: Item,
    pub result: oneshot::Sender<bool>,
}

#[derive(Debug)]
pub struct LookupChannel {
    tx: mpsc::Sender<Event>,
}

#[derive(Clone)]
struct RemoteHost<T: RemoteLookup> {
    tx: mpsc::Sender<Event>,
    host: T,
}

pub trait RemoteLookup: Clone {
    fn spawn_lookup(&self, lookup: Lookup, tx: mpsc::Sender<Event>);
}

impl Host {
    pub fn spawn(self, config: &Config) -> mpsc::Sender<Event> {
        // Create channel
        let (tx, rx) = mpsc::channel(1024);
        let local_host = config
            .value("server.hostname")
            .unwrap_or("[127.0.0.1]")
            .to_string();
        let tx_ = tx.clone();

        tokio::spawn(async move {
            // Prepare builders
            match self.protocol {
                ServerProtocol::Smtp | ServerProtocol::Lmtp => {
                    RemoteHost {
                        tx,
                        host: Arc::new(SmtpClientBuilder {
                            addr: format!("{}:{}", self.address, self.port),
                            timeout: self.timeout,
                            tls_connector: build_tls_connector(self.tls_allow_invalid_certs),
                            tls_hostname: self.address,
                            tls_implicit: self.tls_implicit,
                            is_lmtp: matches!(self.protocol, ServerProtocol::Lmtp),
                            local_host,
                        }),
                    }
                    .run(
                        rx,
                        self.cache_entries,
                        self.cache_ttl_positive,
                        self.cache_ttl_negative,
                        self.concurrency,
                    )
                    .await;
                }
                ServerProtocol::Imap => {
                    RemoteHost {
                        tx,
                        host: Arc::new(
                            ImapAuthClientBuilder::new(
                                format!("{}:{}", self.address, self.port),
                                self.timeout,
                                build_tls_connector(self.tls_allow_invalid_certs),
                                self.address,
                                self.tls_implicit,
                            )
                            .init()
                            .await,
                        ),
                    }
                    .run(
                        rx,
                        self.cache_entries,
                        self.cache_ttl_positive,
                        self.cache_ttl_negative,
                        self.concurrency,
                    )
                    .await;
                }
            }
        });

        tx_
    }
}

impl<T: RemoteLookup> RemoteHost<T> {
    pub async fn run(
        &self,
        mut rx: mpsc::Receiver<Event>,
        entries: usize,
        ttl_pos: Duration,
        ttl_neg: Duration,
        max_concurrent: usize,
    ) {
        // Create caches and queue
        let mut cache_pos = LookupCache::<Item>::new(entries, ttl_pos);
        let mut cache_neg = LookupCache::<Item>::new(entries, ttl_neg);
        let mut queue = VecDeque::new();
        let mut active_lookups = 0;

        while let Some(event) = rx.recv().await {
            match event {
                Event::Lookup(lookup) => {
                    if cache_pos.get(&lookup.item) {
                        lookup.result.send(true).logged_unwrap();
                    } else if cache_neg.get(&lookup.item) {
                        lookup.result.send(false).logged_unwrap();
                    } else if active_lookups < max_concurrent {
                        active_lookups += 1;
                        self.host.spawn_lookup(lookup, self.tx.clone());
                    } else {
                        queue.push_back(lookup);
                    }
                }
                Event::WorkerReady {
                    item,
                    result,
                    next_lookup,
                } => {
                    if result {
                        cache_pos.insert(item);
                    } else {
                        cache_neg.insert(item);
                    }

                    let mut lookup = None;
                    while let Some(queued_lookup) = queue.pop_front() {
                        if cache_pos.get(&queued_lookup.item) {
                            queued_lookup.result.send(true).logged_unwrap();
                        } else if cache_neg.get(&queued_lookup.item) {
                            queued_lookup.result.send(false).logged_unwrap();
                        } else {
                            lookup = queued_lookup.into();
                            break;
                        }
                    }
                    if let Some(next_lookup) = next_lookup {
                        if lookup.is_none() {
                            active_lookups -= 1;
                        }
                        next_lookup.send(lookup).logged_unwrap();
                    } else if let Some(lookup) = lookup {
                        self.host.spawn_lookup(lookup, self.tx.clone());
                    } else {
                        active_lookups -= 1;
                    }
                }
                Event::WorkerFailed => {
                    if let Some(queued_lookup) = queue.pop_front() {
                        self.host.spawn_lookup(queued_lookup, self.tx.clone());
                    } else {
                        active_lookups -= 1;
                    }
                }
                Event::Stop => {
                    queue.clear();
                    break;
                }
                Event::Reload => {
                    cache_pos.clear();
                    cache_neg.clear();
                }
            }
        }
    }
}

impl LookupChannel {
    pub async fn lookup(&self, item: Item) -> Option<bool> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx
            .send(Event::Lookup(Lookup { item, result: tx }))
            .await
            .is_ok()
        {
            rx.await.ok()
        } else {
            None
        }
    }
}

impl From<mpsc::Sender<Event>> for LookupChannel {
    fn from(tx: mpsc::Sender<Event>) -> Self {
        LookupChannel { tx }
    }
}

pub trait LoggedUnwrap {
    fn logged_unwrap(self) -> bool;
}

impl<T, E: std::fmt::Debug> LoggedUnwrap for Result<T, E> {
    fn logged_unwrap(self) -> bool {
        match self {
            Ok(_) => true,
            Err(err) => {
                tracing::debug!("Failed to send message over channel: {:?}", err);
                false
            }
        }
    }
}

impl Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Entry(arg0) => f.debug_tuple("Entry").field(arg0).finish(),
            Self::Credentials(_) => f.debug_tuple("Credentials").finish(),
        }
    }
}
