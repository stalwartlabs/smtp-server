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
        let prefix = prefix.as_prefix();
        let key = prefix.as_key();

        let mut found_if = false;
        let mut found_else = false;
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
                    if suffix == ".if" || suffix.starts_with(".if.") {
                        if array_pos != last_array_pos {
                            if last_array_pos != usize::MAX && !found_then {
                                return Err(format!(
                                    "Missing 'then' in 'if' condition {} for property {:?}.",
                                    last_array_pos + 1,
                                    key
                                ));
                            }

                            if_block.if_then.push(IfThen {
                                conditions: Vec::new(),
                                then: T::default(),
                            });

                            found_then = false;
                            last_array_pos = array_pos;
                        }

                        if let Some(conditions) = ctx.rules.get(value) {
                            if_block
                                .if_then
                                .last_mut()
                                .unwrap()
                                .conditions
                                .push(conditions.clone());
                        } else {
                            return Err(format!(
                                "Rule {:?} does not exist for property {:?}.",
                                value, key
                            ));
                        }

                        found_if = true;
                    } else if suffix == ".else" || suffix.starts_with(".else.") {
                        if !found_else {
                            if found_if {
                                if_block.default = self.parse_values((
                                    prefix.as_str(),
                                    suffix_.split_once(".else").unwrap().0,
                                    "else",
                                ))?;
                                found_else = true;
                            } else {
                                return Err(format!(
                                    "Found 'else' before 'if' for property {:?}.",
                                    key
                                ));
                            }
                        }
                    } else if suffix == ".then" || suffix.starts_with(".then.") {
                        if !found_else {
                            if array_pos == last_array_pos {
                                if !found_then {
                                    if_block.if_then.last_mut().unwrap().then =
                                        self.parse_values((
                                            prefix.as_str(),
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
                        return Err(format!("Invalid key {:?} found in 'if' block.", item));
                    }
                } else if !found_if {
                    // Found probably a multi-value, parse and return
                    if_block.default = self.parse_values(key.as_str())?;
                    return Ok(Some(if_block));
                } else {
                    return Err(format!("Invalid key {:?} found in 'if' block.", item));
                }
            } else if item == &key {
                // There is a single value, parse and return
                if_block.default = self.parse_values(key.as_str())?;
                return Ok(Some(if_block));
            }
        }

        if !found_if {
            Ok(None)
        } else if !found_then {
            Err(format!(
                "Missing 'then' in 'if' condition {} for property {:?}.",
                last_array_pos + 1,
                key
            ))
        } else if !found_else {
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
