use std::time::Duration;

use tokio::sync::mpsc;

use super::{Config, ConfigContext, Host};

impl Config {
    pub fn parse_remote_hosts(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for id in self.sub_keys("remote") {
            let host = self.parse_host(id)?;
            ctx.hosts.insert(id.to_string(), host);
        }

        Ok(())
    }

    fn parse_host(&self, id: &str) -> super::Result<Host> {
        let (channel_tx, channel_rx) = mpsc::channel(1024);

        Ok(Host {
            address: self.property_require(("remote", id, "address"))?,
            port: self.property_require(("remote", id, "port"))?,
            protocol: self.property_require(("remote", id, "protocol"))?,
            concurrency: self.property(("remote", id, "concurrency"))?.unwrap_or(10),
            tls_implicit: self
                .property(("remote", id, "tls.implicit"))?
                .unwrap_or(true),
            tls_allow_invalid_certs: self
                .property(("remote", id, "tls.allow-invalid-certs"))?
                .unwrap_or(false),
            username: self.property(("remote", id, "auth.username"))?,
            secret: self.property(("remote", id, "auth.secret"))?,
            cache_entries: self
                .property(("remote", id, "cache.entries"))?
                .unwrap_or(1024),
            cache_ttl_positive: self
                .property(("remote", id, "cache.ttl.positive"))?
                .unwrap_or(Duration::from_secs(86400)),
            cache_ttl_negative: self
                .property(("remote", id, "cache.ttl.positive"))?
                .unwrap_or(Duration::from_secs(86400)),
            timeout: self
                .property(("remote", id, "timeout"))?
                .unwrap_or(Duration::from_secs(60)),
            max_errors: self.property(("remote", id, "limits.errors"))?.unwrap_or(3),
            max_requests: self
                .property(("remote", id, "limits.requests"))?
                .unwrap_or(50),
            channel_tx,
            channel_rx,
            ref_count: 0,
        })
    }
}
