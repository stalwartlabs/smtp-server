use super::{Config, ConfigContext, Connect, IfBlock};

impl Config {
    fn parse_stage_connect(&self, ctx: &ConfigContext) -> super::Result<Connect> {
        Ok(Connect {
            script: self.parse_if_block::<String>("stage.connect.script", ctx)?,
            concurrency: self
                .parse_if_block::<u64>("stage.connect.concurrency", ctx)?
                .unwrap_or_else(|| IfBlock::new(10000)),
            throttle: self.parse_throttle_list("stage.connect.throttle", ctx)?,
        })
    }
}
