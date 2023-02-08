use ahash::AHashSet;
use mail_send::Credentials;
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

use self::cache::LookupCache;

pub mod cache;
pub mod dispatch;
pub mod imap;
pub mod smtp;
pub mod spawn;
pub mod sql;

#[derive(Debug)]
pub enum Lookup {
    Local(AHashSet<String>),
    Remote(LookupChannel),
    Sql(SqlQuery),
}

#[derive(Debug, Clone)]
pub enum SqlDatabase {
    Postgres(sqlx::Pool<sqlx::Postgres>),
    MySql(sqlx::Pool<sqlx::MySql>),
    MsSql(sqlx::Pool<sqlx::Mssql>),
    SqlLite(sqlx::Pool<sqlx::Sqlite>),
}

#[derive(Debug)]
pub struct SqlQuery {
    pub query: String,
    pub db: SqlDatabase,
    pub cache: Option<Mutex<LookupCache<String>>>,
}

impl Default for Lookup {
    fn default() -> Self {
        Lookup::Local(AHashSet::default())
    }
}

#[derive(Debug)]
pub enum Event {
    Lookup(LookupItem),
    WorkerReady {
        item: Item,
        result: Option<bool>,
        next_lookup: Option<oneshot::Sender<Option<LookupItem>>>,
    },
    WorkerFailed,
    Reload,
    Stop,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Item {
    IsAccount(String),
    Authenticate(Credentials<String>),
    Verify(String),
    Expand(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupResult {
    True,
    False,
    Values(Vec<String>),
}

#[derive(Debug)]
pub struct LookupItem {
    pub item: Item,
    pub result: oneshot::Sender<LookupResult>,
}

#[derive(Debug, Clone)]
pub struct LookupChannel {
    pub tx: mpsc::Sender<Event>,
}

#[derive(Clone)]
struct RemoteHost<T: RemoteLookup> {
    tx: mpsc::Sender<Event>,
    host: T,
}

pub trait RemoteLookup: Clone {
    fn spawn_lookup(&self, lookup: LookupItem, tx: mpsc::Sender<Event>);
}
