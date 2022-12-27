use std::{fs, time::Duration};

use mail_send::Credentials;

use super::{utils::ParseValue, *};

impl Config {
    pub fn parse_queue(&self, ctx: &ConfigContext) -> super::Result<Queue> {
        let available_envelope_keys = [
            EnvelopeKey::Recipient,
            EnvelopeKey::RecipientDomain,
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
        ];
        let available_throttle_keys =
            THROTTLE_RCPT_DOMAIN | THROTTLE_MX | THROTTLE_REMOTE_IP | THROTTLE_LOCAL_IP;

        let relay_host = self
            .parse_if_block::<Option<String>>("queue.relay-host", ctx, &available_envelope_keys)?
            .unwrap_or_else(|| IfBlock::new(None));

        let path = self.property_require::<PathBuf>("global.spool.path")?;
        if !path.exists() {
            fs::create_dir(&path)
                .map_err(|err| format!("Failed to create spool directory {:?}: {}", path, err))?;
        }

        Ok(Queue {
            path,
            hash: self.property("global.spool.hash")?.unwrap_or(32),
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
                .parse_if_block(
                    "queue.notify",
                    ctx,
                    &[
                        EnvelopeKey::Sender,
                        EnvelopeKey::SenderDomain,
                        EnvelopeKey::Priority,
                    ],
                )?
                .unwrap_or_else(|| {
                    IfBlock::new(vec![
                        Duration::from_secs(86400),
                        Duration::from_secs(2 * 86400),
                    ])
                }),
            source_ips: self
                .parse_if_block("queue.source-ips", ctx, &available_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(Vec::new())),
            relay_host: IfBlock {
                if_then: {
                    let mut if_then = Vec::with_capacity(relay_host.if_then.len());

                    for i in relay_host.if_then {
                        if_then.push(IfThen {
                            conditions: i.conditions,
                            then: if let Some(then) = i.then {
                                Some(
                                    ctx.hosts
                                        .get(&then)
                                        .ok_or_else(|| {
                                            format!(
                                "Relay host {:?} not found for property \"queue.relay-host\".",
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
                default: if let Some(default) = relay_host.default {
                    Some(
                        ctx.hosts
                            .get(&default)
                            .ok_or_else(|| {
                                format!(
                                    "Relay host {:?} not found for property \"queue.relay-host\".",
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
            messages_max: self
                .parse_if_block("queue.limits.messages", ctx, &available_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(1024 * 1024)),
            size_max: self
                .parse_if_block("queue.limits.size", ctx, &available_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(1024 * 1024 * 1024)),
            throttle: self.parse_throttle(
                "queue.throttle",
                ctx,
                &available_envelope_keys,
                available_throttle_keys,
            )?,
        })
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
