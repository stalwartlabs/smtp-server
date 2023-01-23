pub mod lookup;
pub mod parse;
pub mod verify;

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    Enforce,
    Testing,
    None,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum MxPattern {
    Equals(String),
    StartsWith(String),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Policy {
    pub id: String,
    pub mode: Mode,
    pub mx: Vec<MxPattern>,
    pub max_age: u64,
}

#[derive(Debug)]
pub enum Error {
    Dns(mail_auth::Error),
    Http(reqwest::Error),
    InvalidPolicy(String),
}
