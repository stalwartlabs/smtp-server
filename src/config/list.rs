use std::{
    fs::File,
    io::{BufRead, BufReader},
    sync::Arc,
};

use ahash::AHashSet;

use super::{Config, ConfigContext, List};

impl Config {
    pub fn parse_lists(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for id in self.sub_keys("scripts") {
            let list = self.parse_list(id, ctx)?;
            ctx.lists.insert(id.to_string(), Arc::new(list));
        }

        Ok(())
    }

    fn parse_list(&self, id: &str, ctx: &ConfigContext) -> super::Result<List> {
        let mut list = List {
            entries: AHashSet::new(),
            host: None,
        };
        for (_, value) in self.values(("scripts", id)) {
            if let Some(file) = value.strip_prefix("file://") {
                for line in BufReader::new(File::open(file).map_err(|err| {
                    format!("Failed to read file {:?} for list {:?}: {}", value, id, err)
                })?)
                .lines()
                {
                    list.entries.insert(line.map_err(|err| {
                        format!("Failed to read file {:?} for list {:?}: {}", value, id, err)
                    })?);
                }
            } else if let Some(remote) = value.strip_prefix("remote://") {
                if list.host.is_none() {
                    if let Some(host) = ctx.hosts.get(remote) {
                        list.host = host.clone().into();
                    } else {
                        return Err(format!(
                            "Remote host {:?} not found for list {:?}.",
                            remote, id
                        ));
                    }
                } else {
                    return Err(format!(
                        "Multiple remote hosts specified for list {:?}.",
                        id
                    ));
                }
            } else if !value.is_empty() {
                list.entries.insert(value.trim().to_string());
            }
        }

        Ok(list)
    }
}
