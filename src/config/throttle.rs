use super::{
    utils::{AsKey, ParseKey, ParseValue},
    Config, ConfigContext, IfBlock, Throttle, ThrottleKey, ThrottleRate,
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
        } else {
            Err(format!(
                "Invalid rate value {:?} for property {:?}.",
                value,
                key.as_key()
            ))
        }
    }
}

impl ParseValue for ThrottleKey {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        Ok(match value {
            "rcpt-domain" => ThrottleKey::RecipientDomain,
            "sender-domain" => ThrottleKey::SenderDomain,
            "listener" => ThrottleKey::Listener,
            "mx" => ThrottleKey::Mx,
            "remote-ip" => ThrottleKey::RemoteIp,
            "local-ip" => ThrottleKey::LocalIp,
            _ => {
                return Err(format!(
                    "Invalid throttle key {:?} for property {:?}.",
                    value,
                    key.as_key()
                ))
            }
        })
    }
}
