use std::sync::Arc;

use super::{Config, ConfigContext, Host};

impl Config {
    pub fn parse_remote(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for id in self.sub_keys("remote") {
            let host = self.parse_host(id, ctx)?;
            ctx.hosts.insert(id.to_string(), Arc::new(host));
        }

        Ok(())
    }

    fn parse_host(&self, _id: &str, _ctx: &ConfigContext) -> super::Result<Host> {
        Ok(Host {})
    }
}
