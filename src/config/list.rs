use std::{
    collections::hash_map::Entry,
    fs::File,
    io::{BufRead, BufReader},
    sync::Arc,
};

use ahash::AHashSet;

use super::{Config, ConfigContext, List};

impl Config {
    pub fn parse_lists(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for id in self.sub_keys("list.inline") {
            let list = self.parse_list_inline(id)?;
            ctx.lists.insert(id.to_string(), Arc::new(list));
        }

        for id in self.sub_keys("list.local") {
            let list = self.parse_list_local(id)?;
            match ctx.lists.entry(id.to_string()) {
                Entry::Vacant(e) => {
                    e.insert(list.into());
                }
                Entry::Occupied(_) => {
                    return Err(format!("Duplicate list {:?} found.", id));
                }
            }
        }

        for id in self.sub_keys("list.remote") {
            let list = self.parse_list_remote(id, ctx)?;
            match ctx.lists.entry(id.to_string()) {
                Entry::Vacant(e) => {
                    e.insert(list.into());
                }
                Entry::Occupied(_) => {
                    return Err(format!("Duplicate list {:?} found.", id));
                }
            }
        }

        Ok(())
    }

    fn parse_list_local(&self, id: &str) -> super::Result<List> {
        let mut entries = AHashSet::new();

        for (_, value) in self.values(("list.local", id)) {
            for line in BufReader::new(File::open(value).map_err(|err| {
                format!("Failed to read file {:?} for list {:?}: {}", value, id, err)
            })?)
            .lines()
            {
                entries.insert(line.map_err(|err| {
                    format!("Failed to read file {:?} for list {:?}: {}", value, id, err)
                })?);
            }
        }

        Ok(List::Local(entries))
    }

    fn parse_list_remote(&self, id: &str, ctx: &ConfigContext) -> super::Result<List> {
        let mut iter = self.values(("list.remote", id));
        if let Some((_, remote)) = iter.next() {
            if let Some(host) = ctx.hosts.get(remote) {
                if iter.next().is_none() {
                    Ok(List::Remote(host.clone()))
                } else {
                    Err(format!(
                        "Multiple remote hosts specified for list {:?}.",
                        id
                    ))
                }
            } else {
                Err(format!(
                    "Remote host {:?} not found for list {:?}.",
                    remote, id
                ))
            }
        } else {
            Err(format!("Remote host not specified for list {:?}.", id))
        }
    }

    fn parse_list_inline(&self, id: &str) -> super::Result<List> {
        let mut entries = AHashSet::new();

        for (_, value) in self.values(("list.inline", id)) {
            entries.insert(value.to_string());
        }

        Ok(List::Local(entries))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

    use ahash::{AHashMap, AHashSet};

    use crate::config::{Config, ConfigContext, Host, List};

    #[test]
    fn parse_lists() {
        let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file.push("resources");
        file.push("tests");
        file.push("config");
        file.push("lists.toml");

        let mut list_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        list_path.push("resources");
        list_path.push("tests");
        list_path.push("lists");
        let mut list1 = list_path.clone();
        list1.push("test-list1.txt");
        let mut list2 = list_path.clone();
        list2.push("test-list2.txt");

        let toml = fs::read_to_string(file)
            .unwrap()
            .replace("{LIST1}", list1.as_path().to_str().unwrap())
            .replace("{LIST2}", list2.as_path().to_str().unwrap());

        let config = Config::parse(&toml).unwrap();
        let mut context = ConfigContext::default();
        let remote = Arc::new(Host::default());
        context.hosts.insert("lmtp".to_string(), remote.clone());

        config.parse_lists(&mut context).unwrap();

        assert_eq!(
            context.lists,
            AHashMap::from_iter([
                (
                    "local-domains".to_string(),
                    Arc::new(List::Local(AHashSet::from_iter([
                        "example.org".to_string(),
                        "example.net".to_string()
                    ])))
                ),
                (
                    "spammer-domain".to_string(),
                    Arc::new(List::Local(AHashSet::from_iter([
                        "thatdomain.net".to_string()
                    ])))
                ),
                (
                    "local-users".to_string(),
                    Arc::new(List::Local(AHashSet::from_iter([
                        "user1@domain.org".to_string(),
                        "user2@domain.org".to_string(),
                    ])))
                ),
                (
                    "power-users".to_string(),
                    Arc::new(List::Local(AHashSet::from_iter([
                        "user1@domain.org".to_string(),
                        "user2@domain.org".to_string(),
                        "user3@example.net".to_string(),
                        "user4@example.net".to_string(),
                        "user5@example.net".to_string()
                    ])))
                ),
                (
                    "local-addresses".to_string(),
                    Arc::new(List::Remote(remote))
                ),
            ])
        );
    }
}
