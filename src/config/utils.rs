use std::str::FromStr;

use super::Config;

impl Config {
    pub fn property<T: FromStr>(&self, key: impl IntoKey) -> super::Result<Option<T>> {
        let key = key.into_key();
        if let Some(value) = self.keys.get(&key) {
            match T::from_str(value) {
                Ok(result) => Ok(Some(result)),
                Err(_) => Err(format!("Invalid value {:?} for key {:?}.", value, key)),
            }
        } else {
            Ok(None)
        }
    }

    pub fn property_or_default<T: FromStr>(
        &self,
        key: impl IntoKey,
        default: impl IntoKey,
    ) -> super::Result<Option<T>> {
        match self.property(key) {
            Ok(None) => self.property(default),
            result => result,
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

    pub fn properties<T: FromStr>(
        &self,
        prefix: impl IntoKey,
    ) -> impl Iterator<Item = (&str, super::Result<T>)> {
        let prefix = prefix.as_prefix();
        self.keys.iter().filter_map(move |(key, value)| {
            if key.starts_with(&prefix) {
                (
                    key.as_str(),
                    T::from_str(value)
                        .map_err(|_| format!("Invalid value {:?} for key {:?}.", value, key)),
                )
                    .into()
            } else {
                None
            }
        })
    }

    pub fn properties_or_default<T: FromStr>(
        &self,
        prefix: impl IntoKey,
        default: impl IntoKey,
    ) -> impl Iterator<Item = (&str, super::Result<T>)> {
        let mut prefix = prefix.as_prefix();

        self.properties(if self.keys.keys().any(|k| k.starts_with(&prefix)) {
            prefix.truncate(prefix.len() - 1);
            prefix
        } else {
            default.into_key()
        })
    }

    pub fn value(&self, key: &str) -> Option<&str> {
        self.keys.get(key).map(|s| s.as_str())
    }

    pub fn take_value(&mut self, key: &str) -> Option<String> {
        self.keys.remove(key)
    }

    pub fn file_contents(&self, key: impl IntoKey) -> super::Result<Vec<u8>> {
        let key_ = key.clone();
        if let Some(value) = self.property::<String>(key_)? {
            if value.starts_with("file://") {
                std::fs::read(&value).map_err(|err| {
                    format!(
                        "Failed to read file {:?} for key {:?}: {}",
                        value,
                        key.into_key(),
                        err
                    )
                })
            } else {
                Ok(value.into_bytes())
            }
        } else {
            Err(format!(
                "Property {:?} not found in configuration file.",
                key.into_key()
            ))
        }
    }
}

pub trait ParseKey {
    fn parse_key<T: FromStr>(&self, key: &str) -> super::Result<T>;
}

impl ParseKey for &str {
    fn parse_key<T: FromStr>(&self, key: &str) -> super::Result<T> {
        match T::from_str(self) {
            Ok(result) => Ok(result),
            Err(_) => Err(format!("Invalid value {:?} for key {:?}.", self, key)),
        }
    }
}

impl ParseKey for String {
    fn parse_key<T: FromStr>(&self, key: &str) -> super::Result<T> {
        match T::from_str(self) {
            Ok(result) => Ok(result),
            Err(_) => Err(format!("Invalid value {:?} for key {:?}.", self, key)),
        }
    }
}

pub trait IntoKey: Clone {
    fn into_key(self) -> String;
    fn as_prefix(&self) -> String;
}

impl IntoKey for &str {
    fn into_key(self) -> String {
        self.into()
    }

    fn as_prefix(&self) -> String {
        format!("{}.", self)
    }
}

impl IntoKey for String {
    fn into_key(self) -> String {
        self
    }

    fn as_prefix(&self) -> String {
        format!("{}.", self)
    }
}

impl IntoKey for (&str, &str) {
    fn into_key(self) -> String {
        format!("{}.{}", self.0, self.1)
    }

    fn as_prefix(&self) -> String {
        format!("{}.{}.", self.0, self.1)
    }
}

impl IntoKey for (&str, &str, &str) {
    fn into_key(self) -> String {
        format!("{}.{}.{}", self.0, self.1, self.2)
    }

    fn as_prefix(&self) -> String {
        format!("{}.{}.{}.", self.0, self.1, self.2)
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
                .property::<u32>("servers.my relay.transaction.auth.limits.1.idle")
                .unwrap()
                .unwrap(),
            20
        );
        assert_eq!(
            config
                .property::<IpAddr>(("servers", "submissions", "ip"))
                .unwrap()
                .unwrap(),
            "a:b::1:1".parse::<IpAddr>().unwrap()
        );
    }
}
