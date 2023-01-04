use std::{fs, time::Duration};

use mail_send::Credentials;

use super::{
    throttle::ParseTrottleKey,
    utils::{AsKey, ParseValue},
    *,
};

impl Config {
    pub fn parse_queue(&self, ctx: &ConfigContext) -> super::Result<QueueConfig> {
        let rcpt_envelope_keys = [
            EnvelopeKey::RecipientDomain,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
        ];
        let sender_envelope_keys = [
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
        ];
        let mx_envelope_keys = [
            EnvelopeKey::RecipientDomain,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
            EnvelopeKey::Mx,
        ];
        let host_envelope_keys = [
            EnvelopeKey::RecipientDomain,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
            EnvelopeKey::LocalIp,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::Mx,
        ];

        let next_hop = self
            .parse_if_block::<Option<String>>("queue.outbound.next-hop", ctx, &rcpt_envelope_keys)?
            .unwrap_or_else(|| IfBlock::new(None));

        // Parse throttle
        let mut throttle = QueueThrottle {
            sender: Vec::new(),
            rcpt: Vec::new(),
            host: Vec::new(),
        };
        let all_throttles = self.parse_throttle(
            "queue.throttle",
            ctx,
            &rcpt_envelope_keys,
            THROTTLE_RCPT_DOMAIN
                | THROTTLE_SENDER
                | THROTTLE_SENDER_DOMAIN
                | THROTTLE_MX
                | THROTTLE_REMOTE_IP
                | THROTTLE_LOCAL_IP,
        )?;
        for t in all_throttles {
            if (t.keys & (THROTTLE_MX | THROTTLE_REMOTE_IP | THROTTLE_LOCAL_IP)) != 0
                || t.conditions.conditions.iter().any(|c| {
                    matches!(
                        c,
                        Condition::Match {
                            key: EnvelopeKey::Mx | EnvelopeKey::RemoteIp | EnvelopeKey::LocalIp,
                            ..
                        }
                    )
                })
            {
                throttle.host.push(t);
            } else if (t.keys & (THROTTLE_RCPT_DOMAIN)) != 0
                || t.conditions.conditions.iter().any(|c| {
                    matches!(
                        c,
                        Condition::Match {
                            key: EnvelopeKey::RecipientDomain,
                            ..
                        }
                    )
                })
            {
                throttle.rcpt.push(t);
            } else {
                throttle.sender.push(t);
            }
        }

        let default_ehlo_hostname = self.value_require("server.hostname")?;

        let config = QueueConfig {
            path: self
                .parse_if_block("queue.path", ctx, &sender_envelope_keys)?
                .ok_or("Missing \"queue.path\" property.")?,
            hash: self
                .parse_if_block("queue.hash", ctx, &sender_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(32)),

            retry: self
                .parse_if_block("queue.schedule.retry", ctx, &host_envelope_keys)?
                .unwrap_or_else(|| {
                    IfBlock::new(vec![
                        Duration::from_secs(60),
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
                .parse_if_block("queue.schedule.notify", ctx, &rcpt_envelope_keys)?
                .unwrap_or_else(|| {
                    IfBlock::new(vec![
                        Duration::from_secs(86400),
                        Duration::from_secs(3 * 86400),
                    ])
                }),
            expire: self
                .parse_if_block("queue.schedule.expire", ctx, &rcpt_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 86400))),
            ehlo_name: self
                .parse_if_block("queue.outbound.ehlo-hostname", ctx, &sender_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(default_ehlo_hostname.to_string())),
            max_mx: self
                .parse_if_block("queue.outbound.limits.mx", ctx, &rcpt_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(5)),
            max_multihomed: self
                .parse_if_block("queue.outbound.limits.multihomed", ctx, &rcpt_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(2)),
            source_ipv4: self
                .parse_if_block("queue.outbound.source-ip.v4", ctx, &mx_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(Vec::new())),
            source_ipv6: self
                .parse_if_block("queue.outbound.source-ip.v6", ctx, &mx_envelope_keys)?
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
                                "Host {:?} not found for property \"queue.next-hop\".",
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
            tls_dane: self
                .parse_if_block("queue.outbound.tls.dane", ctx, &host_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(RequireOptional::Optional)),
            tls_mta_sts: self
                .parse_if_block("queue.outbound.tls.mta_sts", ctx, &rcpt_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(RequireOptional::Optional)),
            tls_start: self
                .parse_if_block("queue.outbound.tls.tls", ctx, &host_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(RequireOptional::Optional)),
            throttle,
            quota: self.parse_queue_quota(ctx)?,
            timeout_connect: self
                .parse_if_block("queue.outbound.timeouts.connect", ctx, &host_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
            timeout_greeting: self
                .parse_if_block("queue.outbound.timeouts.greeting", ctx, &host_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
            timeout_tls: self
                .parse_if_block("queue.outbound.timeouts.tls", ctx, &host_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(3 * 60))),
            timeout_ehlo: self
                .parse_if_block("queue.outbound.timeouts.ehlo", ctx, &host_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
            timeout_mail: self
                .parse_if_block(
                    "queue.outbound.timeouts.mail-from",
                    ctx,
                    &host_envelope_keys,
                )?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
            timeout_rcpt: self
                .parse_if_block("queue.outbound.timeouts.rcpt-to", ctx, &host_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(5 * 60))),
            timeout_data: self
                .parse_if_block("queue.outbound.timeouts.data", ctx, &host_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(10 * 60))),
            timeout_mta_sts: self
                .parse_if_block("queue.outbound.timeouts.mta-sts", ctx, &rcpt_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(Duration::from_secs(10 * 60))),
        };

        if config.retry.has_empty_list() {
            Err("Property \"queue.schedule.retry\" cannot contain empty lists.".to_string())
        } else if config.notify.has_empty_list() {
            Err("Property \"queue.schedule.notify\" cannot contain empty lists.".to_string())
        } else {
            Ok(config)
        }
    }

    fn parse_queue_quota(&self, ctx: &ConfigContext) -> super::Result<QueueQuotas> {
        let mut capacities = QueueQuotas {
            sender: Vec::new(),
            rcpt: Vec::new(),
            rcpt_domain: Vec::new(),
        };

        for array_pos in self.sub_keys("queue.quota") {
            let quota = self.parse_queue_quota_item(("queue.quota", array_pos), ctx)?;

            if (quota.keys & THROTTLE_RCPT) != 0
                || quota.conditions.conditions.iter().any(|c| {
                    matches!(
                        c,
                        Condition::Match {
                            key: EnvelopeKey::Recipient,
                            ..
                        }
                    )
                })
            {
                capacities.rcpt.push(quota);
            } else if (quota.keys & THROTTLE_RCPT_DOMAIN) != 0
                || quota.conditions.conditions.iter().any(|c| {
                    matches!(
                        c,
                        Condition::Match {
                            key: EnvelopeKey::RecipientDomain,
                            ..
                        }
                    )
                })
            {
                capacities.rcpt_domain.push(quota);
            } else {
                capacities.sender.push(quota);
            }
        }

        Ok(capacities)
    }

    fn parse_queue_quota_item(
        &self,
        prefix: impl AsKey,
        ctx: &ConfigContext,
    ) -> super::Result<QueueQuota> {
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

        let quota = QueueQuota {
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
        if quota.size.is_none() && quota.messages.is_none() {
            Err(format!(
                concat!(
                    "Queue quota {:?} needs to define a ",
                    "valid 'size' and/or 'messages' property."
                ),
                prefix
            ))
        } else {
            Ok(quota)
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

impl ParseValue for RequireOptional {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        match value {
            "optional" => Ok(RequireOptional::Optional),
            "require" | "required" => Ok(RequireOptional::Require),
            "disable" | "disabled" | "none" | "false" => Ok(RequireOptional::Disable),
            _ => Err(format!(
                "Invalid TLS option value {:?} for key {:?}.",
                value,
                key.as_key()
            )),
        }
    }
}

impl ParseValue for Ipv4Addr {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid IPv4 value {:?} for key {:?}.", value, key.as_key()))
    }
}

impl ParseValue for Ipv6Addr {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        value
            .parse()
            .map_err(|_| format!("Invalid IPv6 value {:?} for key {:?}.", value, key.as_key()))
    }
}

impl ParseValue for PathBuf {
    fn parse_value(_key: impl utils::AsKey, value: &str) -> super::Result<Self> {
        let path = PathBuf::from(value);

        if !path.exists() {
            fs::create_dir(&path)
                .map_err(|err| format!("Failed to create spool directory {:?}: {}", path, err))?;
        }

        Ok(path)
    }
}
