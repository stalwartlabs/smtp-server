use std::{fs, time::Duration};

use mail_send::Credentials;

use super::{
    throttle::ParseTrottleKey,
    utils::{AsKey, ParseValue},
    *,
};

impl Config {
    pub fn parse_queue(&self, ctx: &ConfigContext) -> super::Result<QueueConfig> {
        let available_envelope_keys = [
            EnvelopeKey::RecipientDomain,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
        ];
        let available_throttle_keys = THROTTLE_RCPT_DOMAIN
            | THROTTLE_SENDER
            | THROTTLE_SENDER_DOMAIN
            | THROTTLE_MX
            | THROTTLE_REMOTE_IP
            | THROTTLE_LOCAL_IP;

        let next_hop = self
            .parse_if_block::<Option<String>>("queue.next-hop", ctx, &available_envelope_keys)?
            .unwrap_or_else(|| IfBlock::new(None));

        let path = self.property_require::<PathBuf>("global.spool.path")?;
        if !path.exists() {
            fs::create_dir(&path)
                .map_err(|err| format!("Failed to create spool directory {:?}: {}", path, err))?;
        }

        // Parse throttle
        let mut throttle = QueueThrottle {
            sender: Vec::new(),
            recipient: Vec::new(),
        };
        let all_throttles = self.parse_throttle(
            "queue.throttle",
            ctx,
            &available_envelope_keys,
            available_throttle_keys,
        )?;
        for t in all_throttles {
            if (t.keys
                & (THROTTLE_RCPT_DOMAIN | THROTTLE_MX | THROTTLE_REMOTE_IP | THROTTLE_LOCAL_IP))
                != 0
                || t.conditions.conditions.iter().any(|c| {
                    matches!(
                        c,
                        Condition::Match {
                            key: EnvelopeKey::RecipientDomain
                                | EnvelopeKey::Mx
                                | EnvelopeKey::RemoteIp
                                | EnvelopeKey::LocalIp,
                            ..
                        }
                    )
                })
            {
                throttle.recipient.push(t);
            } else {
                throttle.sender.push(t);
            }
        }

        Ok(QueueConfig {
            path,
            hash: self
                .property::<u64>("global.spool.hash")?
                .unwrap_or(32)
                .next_power_of_two(),
            retry: self
                .parse_if_block("queue.retry", ctx, &available_envelope_keys)?
                .unwrap_or_else(|| {
                    IfBlock::new(vec![
                        Duration::from_secs(0),
                        Duration::from_secs(2 * 60),
                        Duration::from_secs(5 * 60),
                        Duration::from_secs(10 * 60),
                        Duration::from_secs(15 * 60),
                        Duration::from_secs(30 * 60),
                        Duration::from_secs(3600),
                        Duration::from_secs(2 * 3600),
                    ])
                }),
            notify: self
                .parse_if_block("queue.notify", ctx, &available_envelope_keys)?
                .unwrap_or_else(|| {
                    IfBlock::new(vec![
                        Duration::from_secs(86400),
                        Duration::from_secs(2 * 86400),
                    ])
                }),
            source_ips: self
                .parse_if_block("queue.source-ips", ctx, &available_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(Vec::new())),
            next_hop: IfBlock {
                if_then: {
                    let mut if_then = Vec::with_capacity(next_hop.if_then.len());

                    for i in next_hop.if_then {
                        if_then.push(IfThen {
                            conditions: i.conditions,
                            then: if let Some(then) = i.then {
                                Some(
                                    ctx.hosts
                                        .get(&then)
                                        .ok_or_else(|| {
                                            format!(
                                "Relay host {:?} not found for property \"queue.next-hop\".",
                                then
                            )
                                        })?
                                        .into(),
                                )
                            } else {
                                None
                            },
                        });
                    }

                    if_then
                },
                default: if let Some(default) = next_hop.default {
                    Some(
                        ctx.hosts
                            .get(&default)
                            .ok_or_else(|| {
                                format!(
                                    "Relay host {:?} not found for property \"queue.next-hop\".",
                                    default
                                )
                            })?
                            .into(),
                    )
                } else {
                    None
                },
            },
            tls: self
                .parse_if_block("queue.tls", ctx, &available_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(true)),
            attempts_max: self
                .parse_if_block("queue.limits.attempts", ctx, &available_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(100)),
            lifetime_max: self
                .parse_if_block("queue.limits.lifetime", ctx, &available_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 86400))),
            throttle,
            capacity: self.parse_queue_capacity(ctx)?,
        })
    }

    fn parse_queue_capacity(&self, ctx: &ConfigContext) -> super::Result<QueueCapacities> {
        let mut capacities = QueueCapacities {
            sender: Vec::new(),
            rcpt: Vec::new(),
            rcpt_domain: Vec::new(),
        };

        for array_pos in self.sub_keys("queue.capacity") {
            let capacity = self.parse_queue_capacity_item(("queue.capacity", array_pos), ctx)?;

            if (capacity.keys & THROTTLE_RCPT) != 0
                || capacity.conditions.conditions.iter().any(|c| {
                    matches!(
                        c,
                        Condition::Match {
                            key: EnvelopeKey::Recipient,
                            ..
                        }
                    )
                })
            {
                capacities.rcpt.push(capacity);
            } else if (capacity.keys & THROTTLE_RCPT_DOMAIN) != 0
                || capacity.conditions.conditions.iter().any(|c| {
                    matches!(
                        c,
                        Condition::Match {
                            key: EnvelopeKey::RecipientDomain,
                            ..
                        }
                    )
                })
            {
                capacities.rcpt_domain.push(capacity);
            } else {
                capacities.sender.push(capacity);
            }
        }

        Ok(capacities)
    }

    fn parse_queue_capacity_item(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
    ) -> super::Result<QueueCapacity> {
        let prefix = prefix.as_key();
        let mut keys = 0;
        for (key_, value) in self.values((&prefix, "key")) {
            let key = value.parse_throttle_key(key_)?;
            if (key
                & (THROTTLE_RCPT_DOMAIN | THROTTLE_RCPT | THROTTLE_SENDER | THROTTLE_SENDER_DOMAIN))
                != 0
            {
                keys |= key;
            } else {
                return Err(format!(
                    "Key {:?} is not available in this context for property {:?}",
                    value, key_
                ));
            }
        }

        let capacity = QueueCapacity {
            conditions: if self.values((&prefix, "match")).next().is_some() {
                self.parse_condition(
                    (&prefix, "match"),
                    ctx,
                    &[
                        EnvelopeKey::Recipient,
                        EnvelopeKey::RecipientDomain,
                        EnvelopeKey::Sender,
                        EnvelopeKey::SenderDomain,
                        EnvelopeKey::Priority,
                    ],
                )?
            } else {
                Conditions {
                    conditions: Vec::with_capacity(0),
                }
            },
            keys,
            size: self
                .property::<usize>((prefix.as_str(), "size"))?
                .filter(|&v| v > 0),
            messages: self
                .property::<usize>((prefix.as_str(), "messages"))?
                .filter(|&v| v > 0),
        };

        // Validate
        if capacity.size.is_none() && capacity.messages.is_none() {
            Err(format!(
                concat!(
                    "Queue capacity {:?} needs to define a ",
                    "valid 'size' and/or 'messages' property."
                ),
                prefix
            ))
        } else {
            Ok(capacity)
        }
    }
}

impl From<&Host> for RelayHost {
    fn from(host: &Host) -> Self {
        RelayHost {
            address: host.address.to_string(),
            port: host.port,
            protocol: host.protocol,
            auth: if let (Some(username), Some(secret)) = (&host.username, &host.secret) {
                Credentials::new(username.to_string(), secret.to_string()).into()
            } else {
                None
            },
            tls_implicit: host.tls_implicit,
            tls_allow_invalid_certs: host.tls_allow_invalid_certs,
        }
    }
}

impl ParseValue for PathBuf {
    fn parse_value(_key: impl utils::AsKey, value: &str) -> super::Result<Self> {
        Ok(PathBuf::from(value))
    }
}
