use mail_auth::{
    common::{lru::DnsCache, resolver::IntoFqdn},
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

use crate::core::Resolvers;

use super::{DnssecResolver, Tlsa, TlsaEntry};

impl DnssecResolver {
    pub fn with_capacity(
        config: ResolverConfig,
        options: ResolverOpts,
    ) -> Result<Self, ResolveError> {
        Ok(Self {
            resolver: AsyncResolver::tokio(config, options)?,
        })
    }
}

impl Resolvers {
    pub async fn tlsa_lookup<'x>(
        &self,
        key: impl IntoFqdn<'x>,
    ) -> mail_auth::Result<Option<Arc<Tlsa>>> {
        let key = key.into_fqdn();
        if let Some(value) = self.cache.tlsa.get(key.as_ref()) {
            return Ok(Some(value));
        }

        #[cfg(any(test, feature = "test"))]
        if true {
            return mail_auth::common::resolver::mock_resolve(key.as_ref());
        }

        let mut entries = Vec::new();
        let tlsa_lookup = match self.dnssec.resolver.tlsa_lookup(key.as_ref()).await {
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

        let mut has_end_entities = false;
        let mut has_intermediates = false;

        for record in tlsa_lookup.as_lookup().record_iter() {
            if let Some(tlsa) = record.data().and_then(|r| r.as_tlsa()) {
                let is_end_entity = match tlsa.cert_usage() {
                    CertUsage::DomainIssued => true,
                    CertUsage::TrustAnchor => false,
                    _ => continue,
                };
                if is_end_entity {
                    has_end_entities = true;
                } else {
                    has_intermediates = true;
                }
                entries.push(TlsaEntry {
                    is_end_entity,
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

        Ok(Some(self.cache.tlsa.insert(
            key.into_owned(),
            Arc::new(Tlsa {
                entries,
                has_end_entities,
                has_intermediates,
            }),
            tlsa_lookup.valid_until(),
        )))
    }

    #[cfg(test)]
    pub(crate) fn tlsa_add<'x>(
        &self,
        key: impl IntoFqdn<'x>,
        value: Tlsa,
        valid_until: std::time::Instant,
    ) {
        self.cache
            .tlsa
            .insert(key.into_fqdn().into_owned(), Arc::new(value), valid_until);
    }
}
