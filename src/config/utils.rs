use std::str::FromStr;

use super::Config;

impl Config {
    pub fn property<T: FromStr>(
        &self,
        group: &str,
        id: &str,
        key: &str,
    ) -> super::Result<Option<T>> {
        self.value(&format!("{}.{}.{}", group, id, key))
    }

    pub fn value<T: FromStr>(&self, key: &str) -> super::Result<Option<T>> {
        if let Some(value) = self.keys.get(key) {
            match T::from_str(value) {
                Ok(result) => Ok(Some(result)),
                Err(_) => Err(format!("Invalid value {:?} for key {:?}.", value, key)),
            }
        } else {
            Ok(None)
        }
    }

    pub fn sub_keys<'x, 'y: 'x>(&'y self, prefix: &'x str) -> impl Iterator<Item = &str> + 'x {
        let mut last_key = "";
        self.keys.keys().filter_map(move |key| {
            let key = key.strip_prefix(prefix)?.strip_prefix('.')?;
            let key = if let Some((key, _)) = key.split_once('.') {
                key
            } else {
                key
            };
            if last_key != key {
                last_key = key;
                Some(key)
            } else {
                None
            }
        })
    }

    pub fn take_value(&mut self, key: &str) -> Option<String> {
        self.keys.remove(key)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::config::Config;

    #[test]
    fn toml_utils() {
        let toml = r#"
[queues."z"]
retry = [0, 1, 15, 60, 90]
value = "hi"

[queues."x"]
retry = [3, 60]
value = "hi 2"

[queues.a]
retry = [1, 2, 3, 4]
value = "hi 3"

[servers."my relay"]
hostname = "mx.example.org"

[[servers."my relay".transaction.auth.limits]]
idle = 10

[[servers."my relay".transaction.auth.limits]]
idle = 20

[servers."submissions"]
hostname = "submit.example.org"
ip = a:b::1:1
"#;
        let config = Config::parse(toml).unwrap();

        assert_eq!(
            config.sub_keys("queues").collect::<Vec<_>>(),
            ["a", "x", "z"]
        );
        assert_eq!(
            config.sub_keys("servers").collect::<Vec<_>>(),
            ["my relay", "submissions"]
        );
        assert_eq!(
            config.sub_keys("queues.z.retry").collect::<Vec<_>>(),
            ["0", "1", "2", "3", "4"]
        );
        assert_eq!(
            config
                .value::<u32>("servers.my relay.transaction.auth.limits.1.idle")
                .unwrap()
                .unwrap(),
            20
        );
        assert_eq!(
            config
                .property::<IpAddr>("servers", "submissions", "ip")
                .unwrap()
                .unwrap(),
            "a:b::1:1".parse::<IpAddr>().unwrap()
        );
    }
}
