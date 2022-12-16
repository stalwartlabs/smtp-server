use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr},
};

use crate::config::{
    Condition, ConditionOp, ConditionValue, EnvelopeKey, IfBlock, IpAddrMask, List,
};

use super::Envelope;

impl<T: Default> IfBlock<T> {
    pub fn eval(&self, envelope: &Envelope) -> &T {
        for if_then in &self.if_then {
            if if_then.rules.eval(envelope) {
                return &if_then.then;
            }
        }

        &self.default
    }
}

pub trait ConditionEval {
    fn eval(&self, envelope: &Envelope) -> bool;
}

impl ConditionEval for Vec<Condition> {
    fn eval(&self, envelope: &Envelope) -> bool {
        let mut rules = self.iter();
        let mut matched = false;

        while let Some(rule) = rules.next() {
            match rule {
                Condition::Match {
                    key,
                    op,
                    value,
                    not,
                } => {
                    matched = match value {
                        ConditionValue::String(value) => {
                            let ctx_value = envelope.key_to_string(key);
                            match op {
                                ConditionOp::Equal => value.eq(ctx_value.as_ref()),
                                ConditionOp::StartsWith => ctx_value.starts_with(value),
                                ConditionOp::EndsWith => ctx_value.ends_with(value),
                            }
                        }
                        ConditionValue::IpAddrMask(value) => {
                            let ctx_value = match key {
                                EnvelopeKey::RemoteIp => envelope.remote_ip,
                                EnvelopeKey::LocalIp => envelope.local_ip,
                                _ => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                            };

                            match op {
                                ConditionOp::Equal => value.matches(&ctx_value),
                                ConditionOp::StartsWith | ConditionOp::EndsWith => false,
                            }
                        }
                        ConditionValue::UInt(value) => {
                            let ctx_value = if key == &EnvelopeKey::Listener {
                                &envelope.listener_id
                            } else {
                                debug_assert!(false, "Invalid value for UInt context key.");
                                &u16::MAX
                            };
                            match op {
                                ConditionOp::Equal => value == ctx_value,
                                ConditionOp::StartsWith | ConditionOp::EndsWith => false,
                            }
                        }
                        ConditionValue::Int(value) => {
                            let ctx_value = if key == &EnvelopeKey::Listener {
                                &envelope.priority
                            } else {
                                debug_assert!(false, "Invalid value for UInt context key.");
                                &i16::MAX
                            };
                            match op {
                                ConditionOp::Equal => value == ctx_value,
                                ConditionOp::StartsWith | ConditionOp::EndsWith => false,
                            }
                        }
                        ConditionValue::List(value) => {
                            let ctx_value = envelope.key_to_string(key);
                            match value.as_ref() {
                                List::Local(list) => match op {
                                    ConditionOp::Equal => list.contains(ctx_value.as_ref()),
                                    ConditionOp::StartsWith | ConditionOp::EndsWith => false,
                                },
                                List::Remote(_) => {
                                    let ococ = "fd";
                                    //TODO
                                    false
                                }
                            }
                        }
                        ConditionValue::Regex(value) => {
                            value.is_match(envelope.key_to_string(key).as_ref())
                        }
                    } ^ not;
                }
                Condition::JumpIfTrue { positions } => {
                    if matched {
                        //TODO use advance_by when stabilized
                        for _ in 0..*positions {
                            rules.next();
                        }
                    }
                }
                Condition::JumpIfFalse { positions } => {
                    if !matched {
                        //TODO use advance_by when stabilized
                        for _ in 0..*positions {
                            rules.next();
                        }
                    }
                }
            }
        }

        matched
    }
}

impl Envelope {
    pub fn key_to_string(&self, key: &EnvelopeKey) -> Cow<'_, str> {
        match key {
            EnvelopeKey::Recipient => self.rcpt.as_str().into(),
            EnvelopeKey::RecipientDomain => self.rcpt_domain.as_str().into(),
            EnvelopeKey::Sender => self.sender.as_str().into(),
            EnvelopeKey::SenderDomain => self.sender_domain.as_str().into(),
            EnvelopeKey::AuthenticatedAs => self.authenticated_as.as_str().into(),
            EnvelopeKey::Mx => self.mx.as_str().into(),
            EnvelopeKey::Listener => self.listener_id.to_string().into(),
            EnvelopeKey::RemoteIp => self.remote_ip.to_string().into(),
            EnvelopeKey::LocalIp => self.local_ip.to_string().into(),
            EnvelopeKey::Priority => self.priority.to_string().into(),
        }
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

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use crate::{
        config::{Config, ConfigContext, IfBlock, IfThen, Server},
        core::Envelope,
    };

    #[test]
    fn eval_if() {
        let mut file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        file.push("resources");
        file.push("tests");
        file.push("config");
        file.push("rules-eval.toml");

        let config = Config::parse(&fs::read_to_string(file).unwrap()).unwrap();
        let mut context = ConfigContext::default();
        context.servers.push(Server {
            id: "smtp".to_string(),
            internal_id: 123,
            ..Default::default()
        });
        context.servers.push(Server {
            id: "smtps".to_string(),
            internal_id: 456,
            ..Default::default()
        });
        config.parse_lists(&mut context).unwrap();
        let rules = config.parse_rules(&context).unwrap();

        let envelope = Envelope {
            local_ip: config.property_require("envelope.local-ip").unwrap(),
            remote_ip: config.property_require("envelope.remote-ip").unwrap(),
            sender_domain: config.property_require("envelope.sender-domain").unwrap(),
            sender: config.property_require("envelope.sender").unwrap(),
            rcpt_domain: config.property_require("envelope.rcpt-domain").unwrap(),
            rcpt: config.property_require("envelope.rcpt").unwrap(),
            authenticated_as: config
                .property_require("envelope.authenticated-as")
                .unwrap(),
            mx: config.property_require("envelope.mx").unwrap(),
            listener_id: config.property_require("envelope.listener-id").unwrap(),
            priority: config.property_require("envelope.priority").unwrap(),
        };

        for (key, rules) in rules {
            //println!("============= Testing {:?} ==================", key);
            let (_, expected_result) = key.rsplit_once('-').unwrap();
            assert_eq!(
                IfBlock {
                    if_then: vec![IfThen { rules, then: true }],
                    default: false,
                }
                .eval(&envelope),
                &expected_result.parse::<bool>().unwrap(),
                "failed for {:?}",
                key
            );
        }
    }
}
