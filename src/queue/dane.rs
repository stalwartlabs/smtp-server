use mail_auth::{
    common::{
        lru::{DnsCache, LruCache},
        resolver::IntoFqdn,
    },
    sha1::Digest,
    sha2::{Sha256, Sha512},
    trust_dns_resolver::{
        config::{ResolverConfig, ResolverOpts},
        error::{ResolveError, ResolveErrorKind},
        proto::{
            error::ProtoErrorKind,
            rr::rdata::tlsa::{CertUsage, Matching, Selector},
        },
        AsyncResolver, TokioAsyncResolver,
    },
};
use rustls::Certificate;
use std::sync::Arc;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::{DomainStatus, Error};

pub struct DnssecResolver {
    pub resolver: TokioAsyncResolver,
    pub cache_tlsa: LruCache<String, Arc<Vec<Tlsa>>>,
}

#[derive(Debug)]
pub struct Tlsa {
    is_end_entity: bool,
    is_sha256: bool,
    is_spki: bool,
    data: Vec<u8>,
}

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

        /*#[cfg(test)]
        if true {
            return mock_resolve(key.as_ref());
        }*/

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

    pub async fn verify_dane(
        &self,
        span: &tracing::Span,
        hostname: &str,
        require_dane: bool,
        certificates: Option<&[Certificate]>,
    ) -> Result<(), DomainStatus> {
        let tlsa_records = match self.tlsa_lookup(format!("_25._tcp.{}.", hostname)).await {
            Ok(tlsa_records) => tlsa_records,
            Err(err) => {
                return if require_dane {
                    Err(if matches!(&err, mail_auth::Error::DNSRecordNotFound(_)) {
                        DomainStatus::PermanentFailure(Error::DaneError(format!(
                            "No TLSA records found for {:?}.",
                            hostname
                        )))
                    } else {
                        err.into()
                    })
                } else {
                    Ok(())
                };
            }
        };

        match (certificates, tlsa_records) {
            (Some(certificates), Some(tlsa_records)) => {
                let mut has_end_entities = false;
                let mut has_intermediates = false;

                for record in tlsa_records.iter() {
                    if record.is_end_entity {
                        has_end_entities = true;
                    } else {
                        has_intermediates = true;
                    }
                }

                if !has_end_entities {
                    return if require_dane {
                        tracing::debug!(
                            parent: span,
                            module = "dane",
                            event = "no-tlsa-records",
                            "No valid TLSA records were found for host {}.",
                            hostname,
                        );
                        Err(DomainStatus::PermanentFailure(Error::DaneError(format!(
                            "No valid TLSA records were found for host {:?}.",
                            hostname
                        ))))
                    } else {
                        Ok(())
                    };
                }

                let mut matched_end_entity = false;
                let mut matched_intermediate = false;
                'outer: for (pos, der_certificate) in certificates.iter().enumerate() {
                    // Parse certificate
                    let certificate = match X509Certificate::from_der(der_certificate.as_ref()) {
                        Ok((_, certificate)) => certificate,
                        Err(err) => {
                            tracing::debug!(
                                parent: span,
                                module = "dane",
                                event = "cert-parse-error",
                                "Failed to parse X.509 certificate for host {}: {}",
                                hostname,
                                err
                            );
                            return if require_dane {
                                Err(DomainStatus::TemporaryFailure(Error::DaneError(format!(
                                    "Failed to parse X.509 certificate for host {:?}.",
                                    hostname
                                ))))
                            } else {
                                Ok(())
                            };
                        }
                    };

                    // Match against TLSA records
                    let is_end_entity = pos == 0;
                    let mut sha256 = [None, None];
                    let mut sha512 = [None, None];
                    for record in tlsa_records.iter() {
                        if record.is_end_entity == is_end_entity {
                            let hash: &[u8] = if record.is_sha256 {
                                &sha256[usize::from(record.is_spki)].get_or_insert_with(|| {
                                    let mut hasher = Sha256::new();
                                    hasher.update(if record.is_spki {
                                        certificate.public_key().raw
                                    } else {
                                        der_certificate.as_ref()
                                    });
                                    hasher.finalize()
                                })[..]
                            } else {
                                &sha512[usize::from(record.is_spki)].get_or_insert_with(|| {
                                    let mut hasher = Sha512::new();
                                    hasher.update(if record.is_spki {
                                        certificate.public_key().raw
                                    } else {
                                        der_certificate.as_ref()
                                    });
                                    hasher.finalize()
                                })[..]
                            };

                            if hash == record.data {
                                tracing::debug!(
                                    parent: span,
                                    module = "dane",
                                    event = "info",
                                    hostname = hostname,
                                    certificate = if is_end_entity {
                                        "end-entity"
                                    } else {
                                        "intermediate"
                                    },
                                    "Matched TLSA record with hash {:x?}.",
                                    hash
                                );

                                if is_end_entity {
                                    matched_end_entity = true;
                                    if !has_intermediates {
                                        break 'outer;
                                    }
                                } else {
                                    matched_intermediate = true;
                                    break 'outer;
                                }
                            }
                        }
                    }
                }

                if (has_end_entities == matched_end_entity)
                    && (has_intermediates == matched_intermediate)
                {
                    tracing::info!(
                        parent: span,
                        module = "dane",
                        event = "success",
                        hostname = hostname,
                        "DANE authentication successful.",
                    );
                    Ok(())
                } else {
                    tracing::info!(
                        parent: span,
                        module = "dane",
                        event = "failure",
                        hostname = hostname,
                        "No matching certificates found in TLSA records.",
                    );
                    Err(DomainStatus::PermanentFailure(Error::DaneError(format!(
                        "No matching certificates found in TLSA records for host {:?}.",
                        hostname
                    ))))
                }
            }
            (_, None) => {
                if require_dane {
                    tracing::info!(
                        parent: span,
                        module = "dane",
                        event = "tlsa-dnssec-missing",
                        hostname = hostname,
                        "No TLSA DNSSEC records found."
                    );
                    Err(DomainStatus::PermanentFailure(Error::DaneError(format!(
                        "No TLSA DNSSEC records found for host {:?}.",
                        hostname
                    ))))
                } else {
                    Ok(())
                }
            }
            (None, _) => {
                if require_dane {
                    tracing::info!(
                        parent: span,
                        module = "dane",
                        event = "no-server-certs-found",
                        hostname = hostname,
                        "No certificates were provided."
                    );
                    Err(DomainStatus::TemporaryFailure(Error::DaneError(format!(
                        "No certificates were provided for host {:?}.",
                        hostname
                    ))))
                } else {
                    Ok(())
                }
            }
        }
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

#[cfg(test)]
mod test {
    use std::{
        collections::BTreeSet,
        fs::{self, File},
        io::{BufRead, BufReader},
        num::ParseIntError,
        path::PathBuf,
        time::{Duration, Instant},
    };

    use mail_auth::{
        common::lru::{DnsCache, LruCache},
        trust_dns_resolver::{
            config::{ResolverConfig, ResolverOpts},
            AsyncResolver,
        },
    };
    use rustls::Certificate;

    use crate::queue::{
        dane::{DnssecResolver, Tlsa},
        DomainStatus, Error,
    };

    #[tokio::test]
    async fn dane_test() {
        let conf = ResolverConfig::cloudflare_tls();
        let mut opts = ResolverOpts::default();
        opts.validate = true;
        opts.try_tcp_on_error = true;

        let r = DnssecResolver {
            resolver: AsyncResolver::tokio(conf, opts).unwrap(),
            cache_tlsa: LruCache::with_capacity(10),
        };

        // Add dns entries
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("resources");
        path.push("tests");
        path.push("dane");
        let mut file = path.clone();
        file.push("dns.txt");

        let mut hosts = BTreeSet::new();
        let mut tlsa = Vec::new();
        let mut hostname = String::new();

        for line in BufReader::new(File::open(file).unwrap()).lines() {
            let line = line.unwrap();
            let mut is_end_entity = false;
            for (pos, item) in line.split_whitespace().enumerate() {
                match pos {
                    0 => {
                        if hostname != item && !hostname.is_empty() {
                            r.tlsa_add(hostname, tlsa, Instant::now() + Duration::from_secs(30));
                            tlsa = Vec::new();
                        }
                        hosts.insert(item.strip_prefix("_25._tcp.").unwrap().to_string());
                        hostname = item.to_string();
                    }
                    1 => {
                        is_end_entity = item == "3";
                    }
                    4 => {
                        tlsa.push(Tlsa {
                            is_end_entity,
                            is_sha256: true,
                            is_spki: true,
                            data: decode_hex(item).unwrap(),
                        });
                    }
                    _ => (),
                }
                if pos == 0 {}
            }
        }
        r.tlsa_add(hostname, tlsa, Instant::now() + Duration::from_secs(30));

        // Add certificates
        assert!(!hosts.is_empty());
        for host in hosts {
            // Add certificates
            let mut certs = Vec::new();
            for num in 0..6 {
                let mut file = path.clone();
                file.push(format!("{}.{}.cert", host, num));
                if file.exists() {
                    certs.push(Certificate(fs::read(file).unwrap()));
                } else {
                    break;
                }
            }

            // Successful DANE verification
            assert_eq!(
                r.verify_dane(&tracing::info_span!("test_span"), &host, true, Some(&certs))
                    .await,
                Ok(())
            );

            // Failed DANE verification
            certs.remove(0);
            assert_eq!(
                r.verify_dane(&tracing::info_span!("test_span"), &host, true, Some(&certs))
                    .await,
                Err(DomainStatus::PermanentFailure(Error::DaneError(format!(
                    "No matching certificates found in TLSA records for host \"{}\".",
                    host
                ))))
            );
        }
    }

    pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }
}
