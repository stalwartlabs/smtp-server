use std::{collections::hash_map::Entry, net::IpAddr};

use regex::Regex;

use super::{
    utils::{AsKey, ParseValue},
    Config, ConfigContext, EnvelopeKey, IpAddrMask, Rule, RuleOp, RuleValue,
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

    fn parse_rule(&self, key_: impl AsKey, ctx: &ConfigContext) -> super::Result<Vec<Rule>> {
        let mut rules = Vec::new();
        let mut stack = Vec::new();
        let mut iter = None;
        let mut jmp_pos = Vec::new();
        let mut prefix = key_.as_key();
        let mut is_all = false;
        let mut is_not = false;

        'outer: loop {
            let op_str = self.value_require((&prefix, "op"))?;

            if ["any-of", "all-of", "none-of"].contains(&op_str) {
                stack.push((
                    std::mem::replace(
                        &mut iter,
                        self.sub_keys((&prefix, "value").as_key()).peekable().into(),
                    ),
                    std::mem::take(&mut prefix),
                    std::mem::take(&mut jmp_pos),
                    is_all,
                    is_not,
                ));

                match op_str {
                    "any-of" => {
                        if !is_not {
                            is_all = false;
                            is_not = false;
                        } else {
                            is_all = true;
                            is_not = true;
                        }
                    }
                    "all-of" => {
                        if !is_not {
                            is_all = true;
                            is_not = false;
                        } else {
                            is_all = false;
                            is_not = true;
                        }
                    }
                    _ => {
                        is_not = !is_not;
                        if !is_not {
                            is_all = true;
                            is_not = false;
                        } else {
                            is_all = false;
                            is_not = true;
                        }
                    }
                }
            } else {
                let key = self.property_require::<EnvelopeKey>((&prefix, "key"))?;
                let (op, op_is_not) = match op_str {
                    "eq" | "equal-to" | "in-list" | "regex" | "regex-match" => {
                        (RuleOp::Equal, false)
                    }
                    "ne" | "not-equal-to" | "not-in-list" | "not-regex" | "not-regex-match" => {
                        (RuleOp::Equal, true)
                    }
                    "starts-with" => (RuleOp::StartsWith, false),
                    "ends-with" => (RuleOp::EndsWith, false),
                    op => {
                        return Err(format!(
                            "Invalid rule 'op' value {:?} for key {:?}.",
                            op,
                            (&prefix, "op").as_key()
                        ));
                    }
                };

                let value = match (key, op) {
                    (EnvelopeKey::Listener, RuleOp::Equal) => {
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
                    (EnvelopeKey::LocalIp | EnvelopeKey::RemoteIp, RuleOp::Equal) => {
                        RuleValue::IpAddrMask(self.property_require((&prefix, "value"))?)
                    }
                    (EnvelopeKey::Priority, RuleOp::Equal) => {
                        RuleValue::Int(self.property_require((&prefix, "value"))?)
                    }
                    (
                        EnvelopeKey::Recipient
                        | EnvelopeKey::RecipientDomain
                        | EnvelopeKey::Sender
                        | EnvelopeKey::SenderDomain
                        | EnvelopeKey::AuthenticatedAs
                        | EnvelopeKey::Mx
                        | EnvelopeKey::LocalIp
                        | EnvelopeKey::RemoteIp,
                        _,
                    ) => {
                        let value = self.value_require((&prefix, "value"))?;
                        if op_str.contains("regex") {
                            RuleValue::Regex(Regex::new(value).map_err(|err| {
                                format!(
                                    "Failed to compile regular expression {:?} for key {:?}: {}.",
                                    value,
                                    (&prefix, value).as_key(),
                                    err
                                )
                            })?)
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
                rules.push(Rule::Condition {
                    key,
                    op,
                    value,
                    not: is_not ^ op_is_not,
                });
                if iter.as_mut().map_or(false, |it| it.peek().is_some()) {
                    jmp_pos.push(rules.len());
                    rules.push(if is_all {
                        Rule::JumpIfFalse {
                            positions: usize::MAX,
                        }
                    } else {
                        Rule::JumpIfTrue {
                            positions: usize::MAX,
                        }
                    });
                }
            }

            loop {
                if let Some(array_pos) = iter.as_mut().and_then(|it| it.next()) {
                    prefix = (stack.last().unwrap().1.as_str(), "value", array_pos).as_key();
                    break;
                } else if let Some((prev_iter, _, prev_jmp_pos, prev_is_all, prev_is_not)) =
                    stack.pop()
                {
                    let cur_pos = rules.len() - 1;
                    for pos in jmp_pos {
                        if let Rule::JumpIfFalse { positions } | Rule::JumpIfTrue { positions } =
                            &mut rules[pos]
                        {
                            *positions = cur_pos - pos;
                        }
                    }

                    iter = prev_iter;
                    jmp_pos = prev_jmp_pos;
                    is_all = prev_is_all;
                    is_not = prev_is_not;
                } else {
                    break 'outer;
                }
            }
        }

        Ok(rules)
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

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc};

    use ahash::AHashMap;

    use crate::config::{
        Config, ConfigContext, EnvelopeKey, IpAddrMask, List, Rule, RuleOp, RuleValue, Server,
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
        //println!("{:#?}", context.rules);
        assert_eq!(
            context.rules,
            AHashMap::from_iter([
                (
                    "simple".to_string(),
                    vec![Rule::Condition {
                        key: EnvelopeKey::Listener,
                        op: RuleOp::Equal,
                        value: RuleValue::UInt(123),
                        not: false,
                    }]
                ),
                (
                    "is-authenticated".to_string(),
                    vec![Rule::Condition {
                        key: EnvelopeKey::AuthenticatedAs,
                        op: RuleOp::Equal,
                        value: RuleValue::String("".to_string()),
                        not: true,
                    }]
                ),
                (
                    "expanded".to_string(),
                    vec![
                        Rule::Condition {
                            key: EnvelopeKey::SenderDomain,
                            op: RuleOp::StartsWith,
                            value: RuleValue::String("example".to_string()),
                            not: false,
                        },
                        Rule::JumpIfFalse { positions: 1 },
                        Rule::Condition {
                            key: EnvelopeKey::Mx,
                            op: RuleOp::Equal,
                            value: RuleValue::List(list),
                            not: false,
                        }
                    ]
                ),
                (
                    "my-nested-rule".to_string(),
                    vec![
                        Rule::Condition {
                            key: EnvelopeKey::RecipientDomain,
                            op: RuleOp::Equal,
                            value: RuleValue::String("example.org".to_string()),
                            not: false,
                        },
                        Rule::JumpIfTrue { positions: 9 },
                        Rule::Condition {
                            key: EnvelopeKey::RemoteIp,
                            op: RuleOp::Equal,
                            value: RuleValue::IpAddrMask(IpAddrMask::V4 {
                                addr: "192.168.0.0".parse().unwrap(),
                                mask: u32::MAX << (32 - 24),
                            }),
                            not: false,
                        },
                        Rule::JumpIfTrue { positions: 7 },
                        Rule::Condition {
                            key: EnvelopeKey::Recipient,
                            op: RuleOp::StartsWith,
                            value: RuleValue::String("no-reply@".to_string()),
                            not: false,
                        },
                        Rule::JumpIfFalse { positions: 5 },
                        Rule::Condition {
                            key: EnvelopeKey::Sender,
                            op: RuleOp::EndsWith,
                            value: RuleValue::String("@domain.org".to_string()),
                            not: false,
                        },
                        Rule::JumpIfFalse { positions: 3 },
                        Rule::Condition {
                            key: EnvelopeKey::Priority,
                            op: RuleOp::Equal,
                            value: RuleValue::Int(1),
                            not: true,
                        },
                        Rule::JumpIfFalse { positions: 1 },
                        Rule::Condition {
                            key: EnvelopeKey::Priority,
                            op: RuleOp::Equal,
                            value: RuleValue::Int(-2),
                            not: false,
                        }
                    ]
                )
            ])
        );
    }
}
