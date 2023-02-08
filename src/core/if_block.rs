use std::net::{IpAddr, Ipv4Addr};

use crate::config::{
    Condition, ConditionOp, ConditionValue, Conditions, EnvelopeKey, IfBlock, IpAddrMask,
};

use super::Envelope;

impl<T: Default> IfBlock<T> {
    pub async fn eval(&self, envelope: &impl Envelope) -> &T {
        for if_then in &self.if_then {
            if if_then.conditions.eval(envelope).await {
                return &if_then.then;
            }
        }

        &self.default
    }
}

impl Conditions {
    pub async fn eval(&self, envelope: &impl Envelope) -> bool {
        let mut conditions = self.conditions.iter();
        let mut matched = false;

        while let Some(rule) = conditions.next() {
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
                                EnvelopeKey::RemoteIp => envelope.remote_ip(),
                                EnvelopeKey::LocalIp => envelope.local_ip(),
                                _ => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                            };

                            match op {
                                ConditionOp::Equal => value.matches(&ctx_value),
                                ConditionOp::StartsWith | ConditionOp::EndsWith => false,
                            }
                        }
                        ConditionValue::UInt(value) => {
                            let ctx_value = if key == &EnvelopeKey::Listener {
                                envelope.listener_id()
                            } else {
                                debug_assert!(false, "Invalid value for UInt context key.");
                                u16::MAX
                            };
                            match op {
                                ConditionOp::Equal => *value == ctx_value,
                                ConditionOp::StartsWith | ConditionOp::EndsWith => false,
                            }
                        }
                        ConditionValue::Int(value) => {
                            let ctx_value = if key == &EnvelopeKey::Listener {
                                envelope.priority()
                            } else {
                                debug_assert!(false, "Invalid value for UInt context key.");
                                i16::MAX
                            };
                            match op {
                                ConditionOp::Equal => *value == ctx_value,
                                ConditionOp::StartsWith | ConditionOp::EndsWith => false,
                            }
                        }
                        ConditionValue::Lookup(lookup) => {
                            let ctx_value = envelope.key_to_string(key);
                            if matches!(op, ConditionOp::Equal) {
                                if let Some(result) = lookup.contains(ctx_value.as_ref()).await {
                                    result
                                } else {
                                    return false;
                                }
                            } else {
                                false
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
                            conditions.next();
                        }
                    }
                }
                Condition::JumpIfFalse { positions } => {
                    if !matched {
                        //TODO use advance_by when stabilized
                        for _ in 0..*positions {
                            conditions.next();
                        }
                    }
                }
            }
        }

        matched
    }
}

impl IpAddrMask {
    pub fn matches(&self, remote: &IpAddr) -> bool {
        match self {
            IpAddrMask::V4 { addr, mask } => {
                if *mask == u32::MAX {
                    match remote {
                        IpAddr::V4(remote) => addr == remote,
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
                        IpAddr::V4(remote) => &remote.to_ipv6_mapped() == addr,
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
    use std::{fs, net::IpAddr, path::PathBuf};

    use crate::{
        config::{Config, ConfigContext, IfBlock, IfThen, Server},
        core::Envelope,
    };

    struct TestEnvelope {
        pub local_ip: IpAddr,
        pub remote_ip: IpAddr,
        pub sender_domain: String,
        pub sender: String,
        pub rcpt_domain: String,
        pub rcpt: String,
        pub helo_domain: String,
        pub authenticated_as: String,
        pub mx: String,
        pub listener_id: u16,
        pub priority: i16,
    }

    impl Envelope for TestEnvelope {
        fn local_ip(&self) -> IpAddr {
            self.local_ip
        }

        fn remote_ip(&self) -> IpAddr {
            self.remote_ip
        }

        fn sender_domain(&self) -> &str {
            self.sender_domain.as_str()
        }

        fn sender(&self) -> &str {
            self.sender.as_str()
        }

        fn rcpt_domain(&self) -> &str {
            self.rcpt_domain.as_str()
        }

        fn rcpt(&self) -> &str {
            self.rcpt.as_str()
        }

        fn helo_domain(&self) -> &str {
            self.helo_domain.as_str()
        }

        fn authenticated_as(&self) -> &str {
            self.authenticated_as.as_str()
        }

        fn mx(&self) -> &str {
            self.mx.as_str()
        }

        fn listener_id(&self) -> u16 {
            self.listener_id
        }

        fn priority(&self) -> i16 {
            self.priority
        }
    }

    #[tokio::test]
    async fn eval_if() {
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
        let conditions = config.parse_conditions(&context).unwrap();

        let envelope = TestEnvelope {
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
            listener_id: config.property_require("envelope.listener").unwrap(),
            priority: config.property_require("envelope.priority").unwrap(),
            helo_domain: config.property_require("envelope.helo-domain").unwrap(),
        };

        for (key, conditions) in conditions {
            //println!("============= Testing {:?} ==================", key);
            let (_, expected_result) = key.rsplit_once('-').unwrap();
            assert_eq!(
                IfBlock {
                    if_then: vec![IfThen {
                        conditions,
                        then: true
                    }],
                    default: false,
                }
                .eval(&envelope)
                .await,
                &expected_result.parse::<bool>().unwrap(),
                "failed for {key:?}"
            );
        }
    }
}
