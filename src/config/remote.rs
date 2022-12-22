use std::sync::Arc;

use super::{Config, ConfigContext, Host};

impl Config {
    pub fn parse_remote_hosts(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for id in self.sub_keys("remote") {
            let host = self.parse_host(id, ctx)?;
            ctx.hosts.insert(id.to_string(), Arc::new(host));
        }

        Ok(())
    }

    fn parse_host(&self, _id: &str, _ctx: &ConfigContext) -> super::Result<Host> {
        Ok(Host {
            address: todo!(),
            port: todo!(),
            protocol: todo!(),
            concurrency: todo!(),
            tls_implicit: todo!(),
            username: todo!(),
            secret: todo!(),
            cache_entries: todo!(),
            cache_ttl_positive: todo!(),
            cache_ttl_negative: todo!(),
            tls_allow_invalid_certs: todo!(),
            timeout: todo!(),
        })
    }
}
