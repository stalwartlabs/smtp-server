pub mod parser;
pub mod utils;

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    keys: BTreeMap<String, String>,
}

pub type Result<T> = std::result::Result<T, String>;
