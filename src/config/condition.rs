use std::{collections::hash_map::Entry, net::IpAddr};

use super::{
    utils::{AsKey, ParseKey, ParseValue},
    Condition, Conditions, Config, ConfigContext, IpAddrMask, Server, StringMatch,
};

impl Config {
    pub fn parse_rules(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for rule_name in self.sub_keys("rule") {
            match ctx.rules.entry(rule_name.to_string()) {
                Entry::Vacant(e) => {
                    e.insert(
                        self.parse_conditions(("rule", rule_name), &ctx.servers)?
                            .into(),
                    );
                }
                Entry::Occupied(_) => {
                    return Err(format!("Duplicate rule {:?} found.", rule_name));
                }
            }
        }

        Ok(())
    }

    fn parse_conditions(&self, key: impl AsKey, listeners: &[Server]) -> super::Result<Conditions> {
        let mut conditions = Vec::new();
        let prefix = key.as_prefix();

        for (key_, value) in &self.keys {
            if let Some(key) = key_.strip_prefix(&prefix) {
                let property = if let Some((property, _)) = key.split_once('.') {
                    property
                } else {
                    key
                };
                match property {
                    "rcpt" => {
                        let value = value.parse_key(key_.as_str())?;
                        if let Some(Condition::Recipient(values)) = conditions.last_mut() {
                            values.push(value);
                        } else {
                            conditions.push(Condition::Recipient(vec![value]));
                        }
                    }
                    "rcpt-domain" => {
                        let value = value.parse_key(key_.as_str())?;
                        if let Some(Condition::RecipientDomain(values)) = conditions.last_mut() {
                            values.push(value);
                        } else {
                            conditions.push(Condition::RecipientDomain(vec![value]));
                        }
                    }
                    "sender" => {
                        let value = value.parse_key(key_.as_str())?;
                        if let Some(Condition::Sender(values)) = conditions.last_mut() {
                            values.push(value);
                        } else {
                            conditions.push(Condition::Sender(vec![value]));
                        }
                    }
                    "sender-domain" => {
                        let value = value.parse_key(key_.as_str())?;
                        if let Some(Condition::SenderDomain(values)) = conditions.last_mut() {
                            values.push(value);
                        } else {
                            conditions.push(Condition::SenderDomain(vec![value]));
                        }
                    }
                    "mx" => {
                        let value = value.parse_key(key_.as_str())?;
                        if let Some(Condition::Mx(values)) = conditions.last_mut() {
                            values.push(value);
                        } else {
                            conditions.push(Condition::Mx(vec![value]));
                        }
                    }
                    "priority" => {
                        let value = value.parse_key(key_.as_str())?;
                        if let Some(Condition::Priority(values)) = conditions.last_mut() {
                            values.push(value);
                        } else {
                            conditions.push(Condition::Priority(vec![value]));
                        }
                    }
                    "listener" => {
                        let value = listeners
                            .iter()
                            .find_map(|s| {
                                if s.id.eq_ignore_ascii_case(value) {
                                    s.internal_id.into()
                                } else {
                                    None
                                }
                            })
                            .ok_or_else(|| {
                                format!(
                                    "Listener with id {:?} does not exist for property {:?}.",
                                    value, key_
                                )
                            })?;
                        if let Some(Condition::Listener(values)) = conditions.last_mut() {
                            values.push(value);
                        } else {
                            conditions.push(Condition::Listener(vec![value]));
                        }
                    }
                    "local-ip" => {
                        let value = value.parse_key(key_.as_str())?;

                        if let Some(Condition::LocalIp(values)) = conditions.last_mut() {
                            values.push(value);
                        } else {
                            conditions.push(Condition::LocalIp(vec![value]));
                        }
                    }
                    "remote-ip" => {
                        let value = value.parse_key(key_.as_str())?;

                        if let Some(Condition::RemoteIp(values)) = conditions.last_mut() {
                            values.push(value);
                        } else {
                            conditions.push(Condition::RemoteIp(vec![value]));
                        }
                    }
                    _ => {
                        return Err(format!("Invalid property {:?}", key_));
                    }
                }
            }
        }

        Ok(Conditions { conditions })
    }
}

impl ParseValue for StringMatch {
    fn parse_value(_key: impl AsKey, value: &str) -> super::Result<Self> {
        Ok(if let Some(value) = value.strip_prefix("list:") {
            StringMatch::InList(value.into())
        } else if let Some(value) = value.strip_prefix("regex:") {
            StringMatch::RegexMatch(value.into())
        } else if let Some(value) = value.strip_prefix('*') {
            StringMatch::StartsWith(value.into())
        } else if let Some(value) = value.strip_suffix('*') {
            StringMatch::EndsWith(value.into())
        } else {
            StringMatch::EqualTo(value.into())
        })
    }
}

impl ParseValue for IpAddrMask {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        if let Some((addr, mask)) = value.rsplit_once('/') {
            if let (Ok(addr), Ok(mask)) =
                (addr.trim().parse::<IpAddr>(), mask.trim().parse::<u32>())
            {
                match addr {
                    IpAddr::V4(addr) if (8..=32).contains(&mask) => {
                        return Ok(IpAddrMask::V4 {
                            addr,
                            mask: u32::MAX << (32 - mask),
                        })
                    }
                    IpAddr::V6(addr) if (8..=128).contains(&mask) => {
                        return Ok(IpAddrMask::V6 {
                            addr,
                            mask: u128::MAX << (128 - mask),
                        })
                    }
                    _ => (),
                }
            }
        } else {
            match value.trim().parse::<IpAddr>() {
                Ok(IpAddr::V4(addr)) => {
                    return Ok(IpAddrMask::V4 {
                        addr,
                        mask: u32::MAX,
                    })
                }
                Ok(IpAddr::V6(addr)) => {
                    return Ok(IpAddrMask::V6 {
                        addr,
                        mask: u128::MAX,
                    })
                }
                _ => (),
            }
        }

        Err(format!(
            "Invalid IP address {:?} for property {:?}.",
            value,
            key.as_key()
        ))
    }
}
