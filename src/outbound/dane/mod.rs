use std::sync::Arc;

use mail_auth::{common::lru::LruCache, trust_dns_resolver::TokioAsyncResolver};

pub mod dnssec;
pub mod verify;

pub struct DnssecResolver {
    pub resolver: TokioAsyncResolver,
}

#[derive(Debug)]
pub struct Tlsa {
    is_end_entity: bool,
    is_sha256: bool,
    is_spki: bool,
    data: Vec<u8>,
}
