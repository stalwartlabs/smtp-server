use std::sync::Arc;

use ahash::AHashMap;

use super::{
    utils::{AsKey, ParseValues},
    Config, ConfigContext, IfBlock, IfThen,
};

impl Config {
    pub fn parse_if_block<T: Default + ParseValues>(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
    ) -> super::Result<Option<IfBlock<T>>> {
        let key = prefix.as_key();
        let prefix = prefix.as_prefix();

        let mut found_if = false;
        let mut found_else = usize::MAX;
        let mut found_then = false;

        // Parse conditions
        let mut if_block = IfBlock::new(T::default());
        let mut last_array_pos = usize::MAX;

        for (item, value) in &self.keys {
            if let Some(suffix_) = item.strip_prefix(&prefix) {
                if let Some((array_pos, suffix)) =
                    suffix_.split_once('.').and_then(|(array_pos, suffix)| {
                        (array_pos.parse::<usize>().ok()?, suffix).into()
                    })
                {
                    if suffix == "if" || suffix.starts_with("if.") {
                        if array_pos != last_array_pos {
                            if last_array_pos != usize::MAX && !found_then && !T::is_multivalue() {
                                return Err(format!(
                                    "Missing 'then' in 'if' condition {} for property {:?}.",
                                    last_array_pos + 1,
                                    key
                                ));
                            }

                            if_block.if_then.push(IfThen {
                                rules: Vec::new(),
                                then: T::default(),
                            });

                            found_then = false;
                            last_array_pos = array_pos;
                        }

                        if let Some(rules) = ctx.rules.get(value) {
                            if_block
                                .if_then
                                .last_mut()
                                .unwrap()
                                .rules
                                .push(rules.clone());
                        } else {
                            return Err(format!(
                                "Rule {:?} does not exist for property {:?}.",
                                value, key
                            ));
                        }

                        found_if = true;
                    } else if suffix == "else" || suffix.starts_with("else.") {
                        if found_else == usize::MAX {
                            if found_if {
                                if_block.default = self.parse_values((
                                    key.as_str(),
                                    suffix_.split_once(".else").unwrap().0,
                                    "else",
                                ))?;
                                found_else = array_pos;
                            } else {
                                return Err(format!(
                                    "Found 'else' before 'if' for property {:?}.",
                                    key
                                ));
                            }
                        } else if array_pos != found_else {
                            return Err(format!("Multiple 'else' found for property {:?}.", key));
                        }
                    } else if suffix == "then" || suffix.starts_with("then.") {
                        if found_else == usize::MAX {
                            if array_pos == last_array_pos {
                                if !found_then {
                                    if_block.if_then.last_mut().unwrap().then =
                                        self.parse_values((
                                            key.as_str(),
                                            suffix_.split_once(".then").unwrap().0,
                                            "then",
                                        ))?;
                                    found_then = true;
                                }
                            } else {
                                return Err(format!(
                                    "Found 'then' without 'if' for property {:?}.",
                                    key
                                ));
                            }
                        } else {
                            return Err(format!(
                                "Found 'then' in 'else' block for property {:?}.",
                                key
                            ));
                        }
                    } else {
                        return Err(format!("Invalid property {:?} found in 'if' block.", item));
                    }
                } else if !found_if {
                    // Found probably a multi-value, parse and return
                    if_block.default = self.parse_values(key.as_str())?;
                    return Ok(Some(if_block));
                } else {
                    return Err(format!("Invalid property {:?} found in 'if' block.", item));
                }
            } else if item == &key {
                // There is a single value, parse and return
                if_block.default = self.parse_values(key.as_str())?;
                return Ok(Some(if_block));
            }
        }

        if !found_if {
            Ok(None)
        } else if !found_then && !T::is_multivalue() {
            Err(format!(
                "Missing 'then' in 'if' condition {} for property {:?}.",
                last_array_pos + 1,
                key
            ))
        } else if found_else == usize::MAX && !T::is_multivalue() {
            Err(format!("Missing 'else' for property {:?}.", key))
        } else {
            Ok(Some(if_block))
        }
    }
}

impl<T: Default> IfBlock<T> {
    pub fn new(value: T) -> Self {
        Self {
            if_then: Vec::with_capacity(0),
            default: value,
        }
    }
}

impl<T: Default> IfBlock<Option<T>> {
    pub fn try_unwrap(self, key: &str) -> super::Result<IfBlock<T>> {
        let mut if_then = Vec::with_capacity(self.if_then.len());
        for if_clause in self.if_then {
            if_then.push(IfThen {
                rules: if_clause.rules,
                then: if_clause
                    .then
                    .ok_or_else(|| format!("Property {:?} cannot contain null values.", key))?,
            });
        }

        Ok(IfBlock {
            if_then,
            default: self
                .default
                .ok_or_else(|| format!("Property {:?} cannot contain null values.", key))?,
        })
    }
}

impl IfBlock<Option<String>> {
    pub fn map_if_block<T>(
        self,
        map: &AHashMap<String, Arc<T>>,
        key_name: &str,
        object_name: &str,
    ) -> super::Result<IfBlock<Option<Arc<T>>>> {
        let mut if_then = Vec::with_capacity(self.if_then.len());
        for (pos, if_clause) in self.if_then.into_iter().enumerate() {
            if_then.push(IfThen {
                rules: if_clause.rules,
                then: if let Some(then) = if_clause.then {
                    if let Some(value) = map.get(&then) {
                        Some(value.clone())
                    } else {
                        return Err(format!(
                            "Unable to find {} {:?} declared as 'if' number {}'s 'then' value for {:?}",
                            object_name, then, pos + 1, key_name
                        ));
                    }
                } else {
                    None
                },
            });
        }

        Ok(IfBlock {
            if_then,
            default: if let Some(default) = self.default {
                if let Some(value) = map.get(&default) {
                    Some(value.clone())
                } else {
                    return Err(format!(
                        "Unable to find {} {:?} declared as the 'else' value for {:?}",
                        object_name, default, key_name
                    ));
                }
            } else {
                None
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::Duration};

    use crate::config::{Config, ConfigContext, IfBlock, IfThen, LogicalOp, Rule};

    #[test]
    fn parse_if_blocks() {
        let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file.push("resources");
        file.push("tests");
        file.push("config");
        file.push("if-blocks.toml");

        let config = Config::parse(&fs::read_to_string(file).unwrap()).unwrap();

        // Create context and add some rules
        let mut context = ConfigContext::default();
        let rule1 = Rule::Logical {
            op: LogicalOp::And,
            value: vec![],
        };
        let rule2 = Rule::Logical {
            op: LogicalOp::Or,
            value: vec![],
        };
        context.rules.insert("rule1".to_string(), rule1.clone());
        context.rules.insert("rule2".to_string(), rule2.clone());

        assert_eq!(
            config
                .parse_if_block::<Option<Duration>>("durations", &context)
                .unwrap()
                .unwrap(),
            IfBlock {
                if_then: vec![
                    IfThen {
                        rules: vec![rule1.clone()],
                        then: Duration::from_secs(5 * 86400).into()
                    },
                    IfThen {
                        rules: vec![rule2.clone()],
                        then: Duration::from_secs(3600).into()
                    }
                ],
                default: None
            }
        );

        assert_eq!(
            config
                .parse_if_block::<Vec<String>>("string-list", &context)
                .unwrap()
                .unwrap(),
            IfBlock {
                if_then: vec![
                    IfThen {
                        rules: vec![rule1.clone()],
                        then: vec!["From".to_string(), "To".to_string(), "Date".to_string()]
                    },
                    IfThen {
                        rules: vec![rule2.clone()],
                        then: vec!["Other-ID".to_string()]
                    }
                ],
                default: vec![]
            }
        );

        assert_eq!(
            config
                .parse_if_block::<Vec<String>>("string-list-bis", &context)
                .unwrap()
                .unwrap(),
            IfBlock {
                if_then: vec![
                    IfThen {
                        rules: vec![rule1.clone()],
                        then: vec!["From".to_string(), "To".to_string(), "Date".to_string()]
                    },
                    IfThen {
                        rules: vec![rule2.clone()],
                        then: vec![]
                    }
                ],
                default: vec!["ID-Bis".to_string()]
            }
        );

        assert_eq!(
            config
                .parse_if_block::<String>("single-value", &context)
                .unwrap()
                .unwrap(),
            IfBlock {
                if_then: vec![],
                default: "hello world".to_string()
            }
        );

        assert_eq!(
            config
                .parse_if_block::<bool>("multi-rule", &context)
                .unwrap()
                .unwrap(),
            IfBlock {
                if_then: vec![IfThen {
                    rules: vec![rule1, rule2],
                    then: true
                }],
                default: false
            }
        );

        for bad_rule in [
            "bad-multi-value",
            "bad-if-without-then",
            "bad-if-without-else",
            "bad-multiple-else",
        ] {
            if let Ok(value) = config.parse_if_block::<u32>(bad_rule, &context) {
                panic!("Rule {:?} had unexpected result {:?}", bad_rule, value);
            }
        }
    }
}
