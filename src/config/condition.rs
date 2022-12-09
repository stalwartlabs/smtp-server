use std::{net::IpAddr, str::FromStr};

use super::{
    utils::{AsKey, ParseKey},
    Condition, Config, IpAddrMask, StringMatch,
};

impl Config {
    pub fn parse_conditions(&self, key: impl AsKey) -> super::Result<Vec<Condition>> {
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
                        if let Some(Condition::Recipient(values)) = conditions.last_mut() {
                            values.push(value.parse_key(key_.as_str())?);
                        } else {
                            conditions
                                .push(Condition::Recipient(vec![value.parse_key(key_.as_str())?]));
                        }
                    }
                    "rcpt-domain" => {
                        if let Some(Condition::RecipientDomain(values)) = conditions.last_mut() {
                            values.push(value.parse_key(key_.as_str())?);
                        } else {
                            conditions.push(Condition::RecipientDomain(vec![
                                value.parse_key(key_.as_str())?
                            ]));
                        }
                    }
                    "sender" => {
                        if let Some(Condition::Sender(values)) = conditions.last_mut() {
                            values.push(value.parse_key(key_.as_str())?);
                        } else {
                            conditions
                                .push(Condition::Sender(vec![value.parse_key(key_.as_str())?]));
                        }
                    }
                    "sender-domain" => {
                        if let Some(Condition::SenderDomain(values)) = conditions.last_mut() {
                            values.push(value.parse_key(key_.as_str())?);
                        } else {
                            conditions.push(Condition::SenderDomain(vec![
                                value.parse_key(key_.as_str())?
                            ]));
                        }
                    }
                    "mx" => {
                        if let Some(Condition::Mx(values)) = conditions.last_mut() {
                            values.push(value.parse_key(key_.as_str())?);
                        } else {
                            conditions.push(Condition::Mx(vec![value.parse_key(key_.as_str())?]));
                        }
                    }
                    "priority" => {
                        if let Some(Condition::Priority(values)) = conditions.last_mut() {
                            values.push(value.parse_key(key_.as_str())?);
                        } else {
                            conditions
                                .push(Condition::Priority(vec![value.parse_key(key_.as_str())?]));
                        }
                    }
                    "listener" => {
                        if let Some(Condition::Listener(values)) = conditions.last_mut() {
                            values.push(value.parse_key(key_.as_str())?);
                        } else {
                            conditions
                                .push(Condition::Listener(vec![value.parse_key(key_.as_str())?]));
                        }
                    }
                    "local-ip" => {
                        if let Some(Condition::LocalIp(values)) = conditions.last_mut() {
                            values.push(value.parse_key(key_.as_str())?);
                        } else {
                            conditions
                                .push(Condition::LocalIp(vec![value.parse_key(key_.as_str())?]));
                        }
                    }
                    "remote-ip" => {
                        if let Some(Condition::RemoteIp(values)) = conditions.last_mut() {
                            values.push(value.parse_key(key_.as_str())?);
                        } else {
                            conditions
                                .push(Condition::RemoteIp(vec![value.parse_key(key_.as_str())?]));
                        }
                    }
                    _ => {
                        return Err(format!("Invalid property {:?}", key_));
                    }
                }
            }
        }

        Ok(conditions)
    }
}

impl FromStr for StringMatch {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(if let Some(value) = s.strip_prefix("list:") {
            StringMatch::InList(value.into())
        } else if let Some(value) = s.strip_prefix("regex:") {
            StringMatch::RegexMatch(value.into())
        } else if let Some(value) = s.strip_prefix('*') {
            StringMatch::StartsWith(value.into())
        } else if let Some(value) = s.strip_suffix('*') {
            StringMatch::EndsWith(value.into())
        } else {
            StringMatch::EqualTo(s.into())
        })
    }
}

impl FromStr for IpAddrMask {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((addr, mask)) = s.rsplit_once('/') {
            let mask = mask.trim().parse::<u32>().map_err(|_| ())?;
            match addr.trim().parse::<IpAddr>().map_err(|_| ())? {
                IpAddr::V4(addr) if (8..=32).contains(&mask) => Ok(IpAddrMask::V4 {
                    addr,
                    mask: u32::MAX << (32 - mask),
                }),
                IpAddr::V6(addr) if (8..=128).contains(&mask) => Ok(IpAddrMask::V6 {
                    addr,
                    mask: u128::MAX << (128 - mask),
                }),
                _ => Err(()),
            }
        } else {
            Ok(match s.trim().parse::<IpAddr>().map_err(|_| ())? {
                IpAddr::V4(addr) => IpAddrMask::V4 {
                    addr,
                    mask: u32::MAX,
                },
                IpAddr::V6(addr) => IpAddrMask::V6 {
                    addr,
                    mask: u128::MAX,
                },
            })
        }
    }
}
