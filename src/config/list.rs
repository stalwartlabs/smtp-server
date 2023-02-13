use std::{
    fs::File,
    io::{BufRead, BufReader},
    sync::Arc,
};

use ahash::AHashSet;

use crate::lookup::Lookup;

use super::{Config, ConfigContext};

impl Config {
    pub fn parse_lists(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for id in self.sub_keys("list") {
            ctx.lookup
                .insert(format!("list/{id}"), Arc::new(self.parse_list(id)?));
        }

        Ok(())
    }

    fn parse_list(&self, id: &str) -> super::Result<Lookup> {
        let mut entries = AHashSet::new();
        for (_, value) in self.values(("list", id)) {
            if let Some(path) = value.strip_prefix("file://") {
                for line in BufReader::new(File::open(path).map_err(|err| {
                    format!("Failed to read file {path:?} for list {id:?}: {err}")
                })?)
                .lines()
                {
                    let line_ = line.map_err(|err| {
                        format!("Failed to read file {path:?} for list {id:?}: {err}")
                    })?;
                    let line = line_.trim();
                    if !line.is_empty() {
                        entries.insert(line.to_string());
                    }
                }
            } else {
                entries.insert(value.to_string());
            }
        }
        Ok(Lookup::Local(entries))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

    use ahash::{AHashMap, AHashSet};

    use crate::{
        config::{Config, ConfigContext},
        lookup::Lookup,
    };

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
                "list/local-domains".to_string(),
                Arc::new(Lookup::Local(AHashSet::from_iter([
                    "example.org".to_string(),
                    "example.net".to_string(),
                ]))),
            ),
            (
                "list/spammer-domains".to_string(),
                Arc::new(Lookup::Local(AHashSet::from_iter([
                    "thatdomain.net".to_string()
                ]))),
            ),
            (
                "list/local-users".to_string(),
                Arc::new(Lookup::Local(AHashSet::from_iter([
                    "user1@domain.org".to_string(),
                    "user2@domain.org".to_string(),
                ]))),
            ),
            (
                "list/power-users".to_string(),
                Arc::new(Lookup::Local(AHashSet::from_iter([
                    "user1@domain.org".to_string(),
                    "user2@domain.org".to_string(),
                    "user3@example.net".to_string(),
                    "user4@example.net".to_string(),
                    "user5@example.net".to_string(),
                ]))),
            ),
            (
                "remote/lmtp".to_string(),
                context.lookup.get("remote/lmtp").unwrap().clone(),
            ),
        ]);

        for (key, list) in context.lookup {
            assert_eq!(Some(list), expected_lists.remove(&key), "failed for {key}");
        }
    }
}
