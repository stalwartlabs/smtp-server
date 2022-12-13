use super::{
    utils::{AsKey, ParseKey, ParseValue},
    Config, ConfigContext, ContextKey, IfBlock, Throttle, ThrottleRate,
};

impl Config {
    pub fn parse_throttle_list(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
    ) -> super::Result<Vec<Throttle>> {
        let mut result = Vec::new();
        let key = prefix.as_key();

        for array_pos in self.sub_keys(prefix) {
            result.push(self.parse_throttle((key.as_str(), array_pos), ctx)?);
        }

        Ok(result)
    }

    pub fn parse_throttle(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
    ) -> super::Result<Throttle> {
        let prefix = prefix.as_key();
        let throttle = Throttle {
            key: self.parse_values((prefix.as_str(), "key"))?,
            concurrency: if let Some(concurrency) =
                self.parse_if_block::<u64>((prefix.as_str(), "concurrency"), ctx)?
            {
                concurrency
            } else {
                IfBlock::default()
            },
            rate: if let Some(rate) =
                self.parse_if_block::<ThrottleRate>((prefix.as_str(), "rate"), ctx)?
            {
                rate
            } else {
                IfBlock::default()
            },
        };

        // Validate
        if throttle.key.is_empty() {
            Err(format!("No throttle keys found in {:?}", prefix))
        } else if throttle.rate.default.requests == 0 && throttle.concurrency.default == 0 {
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

impl ParseValue for ContextKey {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        Ok(match value {
            "rcpt" => ContextKey::Recipient,
            "rcpt-domain" => ContextKey::RecipientDomain,
            "sender" => ContextKey::Sender,
            "sender-domain" => ContextKey::SenderDomain,
            "listener" => ContextKey::Listener,
            "mx" => ContextKey::Mx,
            "remote-ip" => ContextKey::RemoteIp,
            "local-ip" => ContextKey::LocalIp,
            "priority" => ContextKey::Priority,
            "authenticated-as" => ContextKey::AuthenticatedAs,
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
    use std::{fs, path::PathBuf, time::Duration};

    use crate::config::{
        Config, ConfigContext, ContextKey, IfBlock, IfThen, Rule, Throttle, ThrottleRate,
    };

    #[test]
    fn parse_throttle() {
        let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file.push("resources");
        file.push("tests");
        file.push("config");
        file.push("throttle.toml");

        let config = Config::parse(&fs::read_to_string(file).unwrap()).unwrap();
        let mut context = ConfigContext::default();
        let rule = Rule::default();
        context.rules.insert("rule1".to_string(), rule.clone());

        config.parse_lists(&mut context).unwrap();

        assert_eq!(
            config.parse_throttle_list("throttle", &context).unwrap(),
            vec![
                Throttle {
                    key: vec![ContextKey::RemoteIp, ContextKey::AuthenticatedAs],
                    concurrency: IfBlock {
                        if_then: vec![],
                        default: 100
                    },
                    rate: IfBlock {
                        if_then: vec![IfThen {
                            rules: vec![rule.clone()],
                            then: ThrottleRate {
                                requests: 50,
                                period: Duration::from_secs(30)
                            }
                        }],
                        default: ThrottleRate {
                            requests: 0,
                            period: Duration::from_secs(0)
                        }
                    }
                },
                Throttle {
                    key: vec![ContextKey::SenderDomain],
                    concurrency: IfBlock {
                        if_then: vec![IfThen {
                            rules: vec![rule],
                            then: 10000
                        }],
                        default: 100
                    },
                    rate: IfBlock {
                        if_then: vec![],
                        default: ThrottleRate {
                            requests: 0,
                            period: Duration::from_secs(0)
                        }
                    }
                }
            ]
        );
    }
}
