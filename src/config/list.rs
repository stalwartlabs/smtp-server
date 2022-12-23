use std::{
    fs::File,
    io::{BufRead, BufReader},
    sync::Arc,
};

use ahash::AHashSet;

use super::{Config, ConfigContext, List};

impl Config {
    pub fn parse_lists(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for id in self.sub_keys("list") {
            let list = self.parse_list(id, ctx)?;
            ctx.lists.insert(id.to_string(), Arc::new(list));
        }

        Ok(())
    }

    fn parse_list(&self, id: &str, ctx: &mut ConfigContext) -> super::Result<List> {
        match self.value(("list", id, "type")).unwrap_or_default() {
            "inline" => {
                let mut entries = AHashSet::new();

                for (_, value) in self.values(("list", id, "items")) {
                    entries.insert(value.to_string());
                }

                Ok(List::Local(entries))
            }
            "remote" => {
                let remote = self.value_require(("list", id, "host"))?;

                if let Some(host) = ctx.hosts.get_mut(remote) {
                    host.ref_count += 1;
                    Ok(List::Remote(host.channel_tx.clone().into()))
                } else {
                    Err(format!(
                        "Remote host {:?} not found for list {:?}.",
                        remote, id
                    ))
                }
            }
            "file" => {
                let mut entries = AHashSet::new();

                for (_, value) in self.values(("list", id, "path")) {
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
            "" => Err(format!("Missing 'type' property for list {:?}.", id)),
            invalid => Err(format!(
                "Invalid list type {:?} for list {:?}.",
                invalid, id
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

    use ahash::{AHashMap, AHashSet};

    use crate::config::{Config, ConfigContext, List};

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
        config.parse_remote_hosts(&mut context).unwrap();
        config.parse_lists(&mut context).unwrap();

        let mut expected_lists = AHashMap::from_iter([
            (
                "local-domains".to_string(),
                Arc::new(List::Local(AHashSet::from_iter([
                    "example.org".to_string(),
                    "example.net".to_string(),
                ]))),
            ),
            (
                "spammer-domains".to_string(),
                Arc::new(List::Local(AHashSet::from_iter([
                    "thatdomain.net".to_string()
                ]))),
            ),
            (
                "local-users".to_string(),
                Arc::new(List::Local(AHashSet::from_iter([
                    "user1@domain.org".to_string(),
                    "user2@domain.org".to_string(),
                ]))),
            ),
            (
                "power-users".to_string(),
                Arc::new(List::Local(AHashSet::from_iter([
                    "user1@domain.org".to_string(),
                    "user2@domain.org".to_string(),
                    "user3@example.net".to_string(),
                    "user4@example.net".to_string(),
                    "user5@example.net".to_string(),
                ]))),
            ),
            (
                "local-addresses".to_string(),
                context.lists.get("local-addresses").unwrap().clone(),
            ),
        ]);

        for (key, list) in context.lists {
            assert_eq!(
                Some(list),
                expected_lists.remove(&key),
                "failed for {}",
                key
            );
        }
    }
}
