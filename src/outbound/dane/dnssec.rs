use mail_auth::{
    common::{
        lru::{DnsCache, LruCache},
        resolver::IntoFqdn,
    },
    trust_dns_resolver::{
        config::{ResolverConfig, ResolverOpts},
        error::{ResolveError, ResolveErrorKind},
        proto::{
            error::ProtoErrorKind,
            rr::rdata::tlsa::{CertUsage, Matching, Selector},
        },
        AsyncResolver,
    },
};
use std::sync::Arc;

use super::{DnssecResolver, Tlsa};

impl DnssecResolver {
    pub fn with_capacity(
        config: ResolverConfig,
        options: ResolverOpts,
        capacity: usize,
    ) -> Result<Self, ResolveError> {
        Ok(Self {
            resolver: AsyncResolver::tokio(config, options)?,
            cache_tlsa: LruCache::with_capacity(capacity),
        })
    }

    pub async fn tlsa_lookup<'x>(
        &self,
        key: impl IntoFqdn<'x>,
    ) -> mail_auth::Result<Option<Arc<Vec<Tlsa>>>> {
        let key = key.into_fqdn();
        if let Some(value) = self.cache_tlsa.get(key.as_ref()) {
            return Ok(Some(value));
        }

        let mut tlsa_list = Vec::new();
        let tlsa_lookup = match self.resolver.tlsa_lookup(key.as_ref()).await {
            Ok(tlsa_lookup) => tlsa_lookup,
            Err(err) => {
                return match &err.kind() {
                    ResolveErrorKind::Proto(proto_err)
                        if matches!(proto_err.kind(), ProtoErrorKind::RrsigsNotPresent { .. }) =>
                    {
                        Ok(None)
                    }
                    _ => Err(err.into()),
                };
            }
        };
        for record in tlsa_lookup.as_lookup().record_iter() {
            if let Some(tlsa) = record.data().and_then(|r| r.as_tlsa()) {
                tlsa_list.push(Tlsa {
                    is_end_entity: match tlsa.cert_usage() {
                        CertUsage::DomainIssued => true,
                        CertUsage::TrustAnchor => false,
                        _ => continue,
                    },
                    is_sha256: match tlsa.matching() {
                        Matching::Sha256 => true,
                        Matching::Sha512 => false,
                        _ => continue,
                    },
                    is_spki: match tlsa.selector() {
                        Selector::Spki => true,
                        Selector::Full => false,
                        _ => continue,
                    },
                    data: tlsa.cert_data().to_vec(),
                });
            }
        }

        Ok(Some(self.cache_tlsa.insert(
            key.into_owned(),
            Arc::new(tlsa_list),
            tlsa_lookup.valid_until(),
        )))
    }

    #[cfg(test)]
    pub(crate) fn tlsa_add<'x>(
        &self,
        key: impl IntoFqdn<'x>,
        value: Vec<Tlsa>,
        valid_until: std::time::Instant,
    ) {
        self.cache_tlsa
            .insert(key.into_fqdn().into_owned(), Arc::new(value), valid_until);
    }
}
