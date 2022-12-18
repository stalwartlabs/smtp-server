use super::{
    utils::{AsKey, ParseKey, ParseValue},
    *,
};

impl Config {
    pub fn parse_throttle(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
        available_envelope_keys: &[EnvelopeKey],
        available_throttle_keys: u16,
    ) -> super::Result<Vec<Throttle>> {
        let prefix_ = prefix.as_key();
        let mut throttles = Vec::new();
        for array_pos in self.sub_keys(prefix) {
            throttles.push(self.parse_throttle_item(
                (&prefix_, array_pos),
                ctx,
                available_envelope_keys,
                available_throttle_keys,
            )?);
        }

        Ok(throttles)
    }

    fn parse_throttle_item(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
        available_envelope_keys: &[EnvelopeKey],
        available_throttle_keys: u16,
    ) -> super::Result<Throttle> {
        let prefix = prefix.as_key();
        let mut keys = 0;
        for (key_, value) in self.values((&prefix, "key")) {
            let key = match value {
                "rcpt" => THROTTLE_RCPT,
                "rcpt-domain" => THROTTLE_RCPT_DOMAIN,
                "sender" => THROTTLE_SENDER,
                "sender-domain" => THROTTLE_SENDER_DOMAIN,
                "authenticated-as" => THROTTLE_AUTH_AS,
                "listener" => THROTTLE_LISTENER,
                "mx" => THROTTLE_MX,
                "remote-ip" => THROTTLE_REMOTE_IP,
                "local-ip" => THROTTLE_LOCAL_IP,
                "helo-domain" => THROTTLE_HELO_DOMAIN,
                _ => {
                    return Err(format!(
                        "Invalid throttle key {:?} found in {:?}",
                        value, key_
                    ))
                }
            };
            if (key & available_throttle_keys) != 0 {
                keys |= key;
            } else {
                return Err(format!(
                    "Throttle key {:?} is not available in this context for property {:?}",
                    value, key_
                ));
            }
        }

        if keys == 0 {
            return Err(format!("No throttle keys found in {:?}", prefix));
        }

        let throttle = Throttle {
            condition: if self.values((&prefix, "if")).next().is_some() {
                self.parse_condition((&prefix, "if"), ctx, available_envelope_keys)?
            } else {
                Vec::with_capacity(0)
            },
            keys,
            concurrency: self
                .property::<u64>((prefix.as_str(), "concurrency"))?
                .filter(|&v| v > 0),
            rate: self
                .property::<ThrottleRate>((prefix.as_str(), "rate"))?
                .filter(|v| v.requests > 0),
        };

        // Validate
        if throttle.rate.is_none() && throttle.concurrency.is_none() {
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
    use std::{fs, path::PathBuf, time::Duration};

    use crate::config::{
        Condition, ConditionOp, ConditionValue, Config, ConfigContext, EnvelopeKey, IpAddrMask,
        Throttle, ThrottleRate, THROTTLE_AUTH_AS, THROTTLE_REMOTE_IP, THROTTLE_SENDER_DOMAIN,
    };

    #[test]
    fn parse_throttle() {
        let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file.push("resources");
        file.push("tests");
        file.push("config");
        file.push("throttle.toml");

        let available_keys = vec![
            EnvelopeKey::Recipient,
            EnvelopeKey::RecipientDomain,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::AuthenticatedAs,
            EnvelopeKey::Listener,
            EnvelopeKey::Mx,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
            EnvelopeKey::Priority,
        ];

        let config = Config::parse(&fs::read_to_string(file).unwrap()).unwrap();
        let context = ConfigContext::default();
        let throttle = config
            .parse_throttle("throttle", &context, &available_keys, u16::MAX)
            .unwrap();

        assert_eq!(
            throttle,
            vec![
                Throttle {
                    condition: vec![Condition::Match {
                        key: EnvelopeKey::RemoteIp,
                        op: ConditionOp::Equal,
                        value: ConditionValue::IpAddrMask(IpAddrMask::V4 {
                            addr: "127.0.0.1".parse().unwrap(),
                            mask: u32::MAX
                        }),
                        not: false
                    }],
                    keys: THROTTLE_REMOTE_IP | THROTTLE_AUTH_AS,
                    concurrency: 100.into(),
                    rate: ThrottleRate {
                        requests: 50,
                        period: Duration::from_secs(30)
                    }
                    .into()
                },
                Throttle {
                    condition: vec![],
                    keys: THROTTLE_SENDER_DOMAIN,
                    concurrency: 10000.into(),
                    rate: None
                }
            ]
        );
    }
}
