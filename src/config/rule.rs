use std::{collections::hash_map::Entry, net::IpAddr};

use super::{
    utils::{AsKey, ParseValue},
    Config, ConfigContext, ContextKey, IpAddrMask, LogicalOp, Rule, RuleOp, RuleValue,
};

impl Config {
    pub fn parse_rules(&self, ctx: &mut ConfigContext) -> super::Result<()> {
        for rule_name in self.sub_keys("rule") {
            let rule = self.parse_rule(("rule", rule_name), ctx)?;
            match ctx.rules.entry(rule_name.to_string()) {
                Entry::Vacant(e) => {
                    e.insert(rule);
                }
                Entry::Occupied(_) => {
                    return Err(format!("Duplicate rule {:?} found.", rule_name));
                }
            }
        }

        Ok(())
    }

    fn parse_rule(&self, key_: impl AsKey, ctx: &ConfigContext) -> super::Result<Rule> {
        let prefix = key_.as_key();
        let op_str = self.value_require((&prefix, "op"))?;

        if ["any-of", "all-of", "none-of"].contains(&op_str) {
            let mut value = Vec::new();
            for array_pos in self.sub_keys((&prefix, "value")) {
                value.push(self.parse_rule((prefix.as_str(), "value", array_pos), ctx)?);
            }

            return Ok(Rule::Logical {
                op: match op_str {
                    "any-of" => LogicalOp::Or,
                    "all-of" => LogicalOp::And,
                    _ => LogicalOp::Not,
                },
                value,
            });
        }

        let key = self.property_require::<ContextKey>((&prefix, "key"))?;
        let op = self.property_require::<RuleOp>((&prefix, "op"))?;
        let value = match (key, op) {
            (ContextKey::Listener, RuleOp::Equal | RuleOp::NotEqual) => {
                let id = self.value_require((&prefix, "value"))?;
                RuleValue::UInt(
                    ctx.servers
                        .iter()
                        .find_map(|s| {
                            if s.id == id {
                                s.internal_id.into()
                            } else {
                                None
                            }
                        })
                        .ok_or_else(|| {
                            format!(
                                "Listener {:?} does not exist for property {:?}.",
                                id,
                                (&prefix, "value").as_key()
                            )
                        })?,
                )
            }
            (ContextKey::LocalIp | ContextKey::RemoteIp, RuleOp::Equal | RuleOp::EndsWith) => {
                RuleValue::IpAddrMask(self.property_require((&prefix, "value"))?)
            }
            (ContextKey::Priority, RuleOp::Equal | RuleOp::NotEqual) => {
                RuleValue::Int(self.property_require((&prefix, "value"))?)
            }
            (
                ContextKey::Recipient
                | ContextKey::RecipientDomain
                | ContextKey::Sender
                | ContextKey::SenderDomain
                | ContextKey::AuthenticatedAs
                | ContextKey::Mx,
                _,
            ) => {
                let value = self.value_require((&prefix, "value"))?;
                if op_str.contains("regex") {
                    RuleValue::Regex(value.to_string())
                } else if op_str.contains("in-list") {
                    if let Some(list) = ctx.lists.get(value) {
                        RuleValue::List(list.clone())
                    } else {
                        return Err(format!(
                            "List {:?} not found for property {:?}.",
                            value,
                            (&prefix, value).as_key()
                        ));
                    }
                } else {
                    RuleValue::String(value.to_string())
                }
            }
            _ => {
                return Err(format!(
                    "Invalid 'op'/'value' combination for key {:?}.",
                    key_.as_key()
                ));
            }
        };

        Ok(Rule::Condition { key, op, value })
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

impl ParseValue for RuleOp {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        Ok(match value {
            "eq" | "equal-to" | "in-list" | "regex" | "regex-match" => RuleOp::Equal,
            "new" | "not-equal-to" | "not-in-list" | "not-regex" | "not-regex-match" => {
                RuleOp::NotEqual
            }
            "starts-with" => RuleOp::StartsWith,
            "ends-with" => RuleOp::EndsWith,
            op => {
                return Err(format!(
                    "Invalid rule 'op' value {:?} for key {:?}.",
                    op,
                    key.as_key()
                ));
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

    use ahash::AHashMap;

    use crate::config::{
        Config, ConfigContext, ContextKey, IpAddrMask, List, LogicalOp, Rule, RuleOp, RuleValue,
        Server,
    };

    #[test]
    fn parse_rules() {
        let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file.push("resources");
        file.push("tests");
        file.push("config");
        file.push("rules.toml");

        let config = Config::parse(&fs::read_to_string(file).unwrap()).unwrap();
        let mut context = ConfigContext::default();
        let list = Arc::new(List::default());
        context.lists.insert("test-list".to_string(), list.clone());
        context.servers.push(Server {
            id: "smtp".to_string(),
            internal_id: 123,
            ..Default::default()
        });
        config.parse_rules(&mut context).unwrap();
        assert_eq!(
            context.rules,
            AHashMap::from_iter([
                (
                    "simple".to_string(),
                    Rule::Condition {
                        key: ContextKey::Listener,
                        op: RuleOp::Equal,
                        value: RuleValue::UInt(123)
                    }
                ),
                (
                    "is-authenticated".to_string(),
                    Rule::Condition {
                        key: ContextKey::AuthenticatedAs,
                        op: RuleOp::NotEqual,
                        value: RuleValue::String("".to_string())
                    }
                ),
                (
                    "expanded".to_string(),
                    Rule::Logical {
                        op: LogicalOp::And,
                        value: vec![
                            Rule::Condition {
                                key: ContextKey::SenderDomain,
                                op: RuleOp::StartsWith,
                                value: RuleValue::String("example".to_string())
                            },
                            Rule::Condition {
                                key: ContextKey::Mx,
                                op: RuleOp::Equal,
                                value: RuleValue::List(list),
                            }
                        ]
                    }
                ),
                (
                    "my-nested-rule".to_string(),
                    Rule::Logical {
                        op: LogicalOp::Or,
                        value: vec![
                            Rule::Condition {
                                key: ContextKey::RecipientDomain,
                                op: RuleOp::Equal,
                                value: RuleValue::String("example.org".to_string()),
                            },
                            Rule::Condition {
                                key: ContextKey::RemoteIp,
                                op: RuleOp::Equal,
                                value: RuleValue::IpAddrMask(IpAddrMask::V4 {
                                    addr: "192.168.0.0".parse().unwrap(),
                                    mask: u32::MAX << (32 - 24),
                                })
                            },
                            Rule::Logical {
                                op: LogicalOp::And,
                                value: vec![
                                    Rule::Condition {
                                        key: ContextKey::Recipient,
                                        op: RuleOp::StartsWith,
                                        value: RuleValue::String("no-reply@".to_string()),
                                    },
                                    Rule::Condition {
                                        key: ContextKey::Sender,
                                        op: RuleOp::EndsWith,
                                        value: RuleValue::String("@domain.org".to_string()),
                                    },
                                    Rule::Logical {
                                        op: LogicalOp::Not,
                                        value: vec![
                                            Rule::Condition {
                                                key: ContextKey::Priority,
                                                op: RuleOp::Equal,
                                                value: RuleValue::Int(1),
                                            },
                                            Rule::Condition {
                                                key: ContextKey::Priority,
                                                op: RuleOp::NotEqual,
                                                value: RuleValue::Int(-2),
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                )
            ])
        );
    }
}
