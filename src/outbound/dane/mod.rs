use mail_auth::trust_dns_resolver::TokioAsyncResolver;

pub mod dnssec;
pub mod verify;

pub struct DnssecResolver {
    pub resolver: TokioAsyncResolver,
}

#[derive(Debug, Hash)]
pub struct TlsaEntry {
    pub is_end_entity: bool,
    pub is_sha256: bool,
    pub is_spki: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Hash)]
pub struct Tlsa {
    pub entries: Vec<TlsaEntry>,
    pub has_end_entities: bool,
    pub has_intermediates: bool,
}
