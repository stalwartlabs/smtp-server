use std::net::{IpAddr, Ipv4Addr};

use crate::config::{ContextKey, IfBlock, IpAddrMask, LogicalOp, Rule, RuleOp, RuleValue};

use super::Context;

impl Context {
    pub fn eval<'x, T: Default>(&self, if_block: &'x IfBlock<T>) -> &'x T {
        for if_then in &if_block.if_then {
            let mut rules = if_then.rules.iter();
            let mut rules_stack = Vec::new();
            let mut rules_op = &LogicalOp::Or;
            let mut matched = false;

            'outer: loop {
                'inner: while let Some(rule) = rules.next() {
                    match rule {
                        Rule::Condition { key, op, value } => {
                            let result = match value {
                                RuleValue::String(value) => {
                                    let ctx_value = match key {
                                        ContextKey::Recipient => self.rcpt.as_str(),
                                        ContextKey::RecipientDomain => self.rcpt_domain.as_str(),
                                        ContextKey::Sender => self.sender.as_str(),
                                        ContextKey::SenderDomain => self.sender_domain.as_str(),
                                        ContextKey::AuthenticatedAs => {
                                            self.authenticated_as.as_str()
                                        }
                                        ContextKey::Mx => self.mx.as_str(),
                                        ContextKey::Listener
                                        | ContextKey::RemoteIp
                                        | ContextKey::LocalIp
                                        | ContextKey::Priority => {
                                            debug_assert!(
                                                false,
                                                "Invalid value for String context key."
                                            );
                                            ""
                                        }
                                    };
                                    match op {
                                        RuleOp::Equal => value.eq(ctx_value),
                                        RuleOp::NotEqual => value.ne(ctx_value),
                                        RuleOp::StartsWith => value.starts_with(ctx_value),
                                        RuleOp::EndsWith => value.ends_with(ctx_value),
                                    }
                                }
                                RuleValue::IpAddrMask(value) => {
                                    let ctx_value = match key {
                                        ContextKey::RemoteIp => self.remote_ip,
                                        ContextKey::LocalIp => self.local_ip,
                                        _ => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                                    };

                                    match op {
                                        RuleOp::Equal => value.matches(&ctx_value),
                                        RuleOp::NotEqual => !value.matches(&ctx_value),
                                        RuleOp::StartsWith | RuleOp::EndsWith => false,
                                    }
                                }
                                RuleValue::UInt(value) => {
                                    let ctx_value = if key == &ContextKey::Listener {
                                        &self.listener_id
                                    } else {
                                        debug_assert!(false, "Invalid value for UInt context key.");
                                        &u64::MAX
                                    };
                                    match op {
                                        RuleOp::Equal => value == ctx_value,
                                        RuleOp::NotEqual => value != ctx_value,
                                        RuleOp::StartsWith | RuleOp::EndsWith => false,
                                    }
                                }
                                RuleValue::Int(value) => {
                                    let ctx_value = if key == &ContextKey::Listener {
                                        &self.priority
                                    } else {
                                        debug_assert!(false, "Invalid value for UInt context key.");
                                        &i64::MAX
                                    };
                                    match op {
                                        RuleOp::Equal => value == ctx_value,
                                        RuleOp::NotEqual => value != ctx_value,
                                        RuleOp::StartsWith | RuleOp::EndsWith => false,
                                    }
                                }
                                RuleValue::List(value) => false,
                                RuleValue::Regex(value) => false,
                            };

                            match rules_op {
                                LogicalOp::And => {
                                    if result {
                                        matched = true;
                                    } else {
                                        matched = false;
                                        break 'inner;
                                    }
                                }
                                LogicalOp::Or => {
                                    if result {
                                        matched = true;
                                        break 'inner;
                                    }
                                }
                                LogicalOp::Not => {
                                    if !result {
                                        matched = true;
                                    } else {
                                        matched = false;
                                        break 'inner;
                                    }
                                }
                            }
                        }
                        Rule::Logical { op, value } => {
                            rules_stack.push((rules, rules_op));
                            rules = value.iter();
                            rules_op = op;
                        }
                    }
                }

                loop {
                    if let Some((prev_rules, prev_rules_op)) = rules_stack.pop() {
                        match rules_op {
                            LogicalOp::And => {
                                if !matched {
                                    continue;
                                }
                            }
                            LogicalOp::Or => {
                                if matched {
                                    continue;
                                }
                            }
                            LogicalOp::Not => {
                                if !matched {
                                    matched = true;
                                } else {
                                    matched = false;
                                    continue;
                                }
                            }
                        }
                        rules = prev_rules;
                        rules_op = prev_rules_op;
                        break;
                    } else {
                        break 'outer;
                    }
                }
            }

            if matched {
                return &if_then.then;
            }
        }

        &if_block.default
    }
}

impl IpAddrMask {
    pub fn matches(&self, remote: &IpAddr) -> bool {
        match self {
            IpAddrMask::V4 { addr, mask } => {
                if *mask == u32::MAX {
                    match remote {
                        IpAddr::V4(addr) => addr == remote,
                        IpAddr::V6(remote) => {
                            if let Some(remote) = remote.to_ipv4_mapped() {
                                addr == &remote
                            } else {
                                false
                            }
                        }
                    }
                } else {
                    u32::from_be_bytes(match remote {
                        IpAddr::V4(ip) => ip.octets(),
                        IpAddr::V6(ip) => {
                            if let Some(ip) = ip.to_ipv4() {
                                ip.octets()
                            } else {
                                return false;
                            }
                        }
                    }) & mask
                        == u32::from_be_bytes(addr.octets()) & mask
                }
            }
            IpAddrMask::V6 { addr, mask } => {
                if mask == &u128::MAX {
                    match remote {
                        IpAddr::V6(remote) => remote == addr,
                        IpAddr::V4(addr) => &addr.to_ipv6_mapped() == remote,
                    }
                } else {
                    u128::from_be_bytes(match remote {
                        IpAddr::V6(ip) => ip.octets(),
                        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
                    }) & mask
                        == u128::from_be_bytes(addr.octets()) & mask
                }
            }
        }
    }
}
