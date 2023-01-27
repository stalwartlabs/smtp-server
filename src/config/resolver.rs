use mail_auth::{
    common::lru::{DnsCache, LruCache},
    trust_dns_resolver::{
        config::{ResolverConfig, ResolverOpts},
        system_conf::read_system_conf,
    },
    IpLookupStrategy, Resolver,
};

use crate::{core::Resolvers, outbound::dane::DnssecResolver};

use super::{
    utils::{AsKey, ParseValue},
    Config,
};

impl Config {
    pub fn build_resolvers(&self) -> super::Result<Resolvers> {
        let (config, mut opts) = match self.value_require("resolver.type")? {
            "cloudflare" => (ResolverConfig::cloudflare(), ResolverOpts::default()),
            "cloudflare-tls" => (ResolverConfig::cloudflare_tls(), ResolverOpts::default()),
            "quad9" => (ResolverConfig::quad9(), ResolverOpts::default()),
            "quad9-tls" => (ResolverConfig::quad9_tls(), ResolverOpts::default()),
            "google" => (ResolverConfig::google(), ResolverOpts::default()),
            "system" => read_system_conf()
                .map_err(|err| format!("Failed to read system DNS config: {err}"))?,
            other => return Err(format!("Unknown resolver type {other:?}.")),
        };
        if let Some(concurrency) = self.property("resolver.concurrency")? {
            opts.num_concurrent_reqs = concurrency;
        }
        if let Some(timeout) = self.property("resolver.timeout")? {
            opts.timeout = timeout;
        }
        if let Some(preserve) = self.property("resolver.preserve-intermediates")? {
            opts.preserve_intermediates = preserve;
        }
        if let Some(try_tcp_on_error) = self.property("resolver.try-tcp-on-error")? {
            opts.try_tcp_on_error = try_tcp_on_error;
        }
        if let Some(attempts) = self.property("resolver.attempts")? {
            opts.attempts = attempts;
        }

        // Prepare DNSSEC resolver options
        let config_dnssec = config.clone();
        let mut opts_dnssec = opts;
        opts_dnssec.validate = true;

        let mut capacities = [1024usize; 5];
        for (pos, key) in ["txt", "mx", "ipv4", "ipv6", "ptr"].into_iter().enumerate() {
            if let Some(capacity) = self.property(("resolver.cache", key))? {
                capacities[pos] = capacity;
            }
        }

        Ok(Resolvers {
            dns: Resolver::with_capacities(
                config,
                opts,
                capacities[0],
                capacities[1],
                capacities[2],
                capacities[3],
                capacities[4],
            )
            .map_err(|err| format!("Failed to build DNS resolver: {err}"))?,
            dnssec: DnssecResolver::with_capacity(config_dnssec, opts_dnssec)
                .map_err(|err| format!("Failed to build DNSSEC resolver: {err}"))?,
            cache: crate::core::DnsCache {
                tlsa: LruCache::with_capacity(
                    self.property("resolver.cache.tlsa")?.unwrap_or(1024),
                ),
                mta_sts: LruCache::with_capacity(
                    self.property("resolver.cache.mta-sts")?.unwrap_or(1024),
                ),
            },
        })
    }
}

impl ParseValue for IpLookupStrategy {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        Ok(match value.to_lowercase().as_str() {
            "ipv4-only" => IpLookupStrategy::Ipv4Only,
            "ipv6-only" => IpLookupStrategy::Ipv6Only,
            //"ipv4-and-ipv6" => IpLookupStrategy::Ipv4AndIpv6,
            "ipv6-then-ipv4" => IpLookupStrategy::Ipv6thenIpv4,
            "ipv4-then-ipv6" => IpLookupStrategy::Ipv4thenIpv6,
            _ => {
                return Err(format!(
                    "Invalid IP lookup strategy {:?} for property {:?}.",
                    value,
                    key.as_key()
                ))
            }
        })
    }
}
