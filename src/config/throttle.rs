use std::collections::hash_map::Entry;

use super::{
    utils::{AsKey, ParseKey, ParseValue},
    Config, ConfigContext, EnvelopeKey, Throttle, ThrottleRate,
};

impl Config {
    pub fn parse_throttle(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for id in self.sub_keys("throttle") {
            let throttle = self.parse_throttle_item(("throttle", id))?;
            match ctx.throttle.entry(id.to_string()) {
                Entry::Vacant(e) => {
                    e.insert(throttle.into());
                }
                Entry::Occupied(_) => {
                    return Err(format!("Duplicate throttle {:?} found.", id));
                }
            }
        }

        Ok(())
    }

    fn parse_throttle_item(&self, prefix: impl AsKey) -> super::Result<Throttle> {
        let prefix = prefix.as_key();
        let throttle = Throttle {
            key: self.parse_values((prefix.as_str(), "key"))?,
            concurrency: self.property((prefix.as_str(), "concurrency"))?,
            rate: self.property((prefix.as_str(), "rate"))?,
        };

        // Validate
        if throttle.key.is_empty() {
            Err(format!("No throttle keys found in {:?}", prefix))
        } else if throttle.rate.is_none() && throttle.concurrency.is_none() {
            Err(format!(
                concat!(
                    "Throttle {:?} needs to define a ",
                    "valid 'rate' or 'concurrency' property."
                ),
                prefix
            ))
        } else {
            Ok(throttle)
        }
    }
}

impl ParseValue for ThrottleRate {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        if let Some((requests, period)) = value.split_once('/') {
            Ok(ThrottleRate {
                requests: requests
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .and_then(|r| if r > 0 { Some(r) } else { None })
                    .ok_or_else(|| {
                        format!(
                            "Invalid rate value {:?} for property {:?}.",
                            value,
                            key.as_key()
                        )
                    })?,
                period: period.parse_key(key)?,
            })
        } else if ["false", "none", "unlimited"].contains(&value) {
            Ok(ThrottleRate::default())
        } else {
            Err(format!(
                "Invalid rate value {:?} for property {:?}.",
                value,
                key.as_key()
            ))
        }
    }
}

impl ParseValue for EnvelopeKey {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        Ok(match value {
            "rcpt" => EnvelopeKey::Recipient,
            "rcpt-domain" => EnvelopeKey::RecipientDomain,
            "sender" => EnvelopeKey::Sender,
            "sender-domain" => EnvelopeKey::SenderDomain,
            "listener" => EnvelopeKey::Listener,
            "mx" => EnvelopeKey::Mx,
            "remote-ip" => EnvelopeKey::RemoteIp,
            "local-ip" => EnvelopeKey::LocalIp,
            "priority" => EnvelopeKey::Priority,
            "authenticated-as" => EnvelopeKey::AuthenticatedAs,
            _ => {
                return Err(format!(
                    "Invalid context key {:?} for property {:?}.",
                    value,
                    key.as_key()
                ))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc, time::Duration};

    use ahash::AHashMap;

    use crate::config::{Config, ConfigContext, EnvelopeKey, Throttle, ThrottleRate};

    #[test]
    fn parse_throttle() {
        let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file.push("resources");
        file.push("tests");
        file.push("config");
        file.push("throttle.toml");

        let config = Config::parse(&fs::read_to_string(file).unwrap()).unwrap();
        let mut context = ConfigContext::default();
        config.parse_throttle(&mut context).unwrap();

        assert_eq!(
            context.throttle,
            AHashMap::from_iter([
                (
                    "remote".to_string(),
                    Arc::new(Throttle {
                        key: vec![EnvelopeKey::RemoteIp, EnvelopeKey::AuthenticatedAs],
                        concurrency: 100.into(),
                        rate: ThrottleRate {
                            requests: 50,
                            period: Duration::from_secs(30)
                        }
                        .into()
                    })
                ),
                (
                    "sender".to_string(),
                    Arc::new(Throttle {
                        key: vec![EnvelopeKey::SenderDomain],
                        concurrency: 10000.into(),
                        rate: None
                    })
                )
            ])
        );
    }
}
