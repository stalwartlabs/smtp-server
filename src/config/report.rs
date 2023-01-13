use super::{
    utils::AsKey, AggregateReport, Config, ConfigContext, EnvelopeKey, IfBlock, Report,
    ReportConfig,
};

impl Config {
    pub fn parse_reports(&self, ctx: &ConfigContext) -> super::Result<ReportConfig> {
        let sender_envelope_keys = [
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
            EnvelopeKey::AuthenticatedAs,
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
        ];
        let rcpt_envelope_keys = [
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
            EnvelopeKey::RecipientDomain,
        ];

        let default_hostname = self.value_require("server.hostname")?;
        Ok(ReportConfig {
            dkim: self.parse_report(ctx, "dkim", default_hostname, &sender_envelope_keys)?,
            spf: self.parse_report(ctx, "spf", default_hostname, &sender_envelope_keys)?,
            dmarc: self.parse_report(ctx, "dmarc", default_hostname, &sender_envelope_keys)?,
            dmarc_aggregate: self.parse_aggregate_report(
                ctx,
                "dmarc",
                default_hostname,
                &sender_envelope_keys,
            )?,
            tls: self.parse_aggregate_report(ctx, "tls", default_hostname, &rcpt_envelope_keys)?,
            path: self
                .parse_if_block("report.path", ctx, &sender_envelope_keys)?
                .ok_or("Missing \"report.path\" property.")?,
            submitter: self
                .parse_if_block("report.submitter", ctx, &[EnvelopeKey::RecipientDomain])?
                .unwrap_or_else(|| IfBlock::new(default_hostname.to_string())),
            hash: self
                .parse_if_block("report.hash", ctx, &sender_envelope_keys)?
                .unwrap_or_else(|| IfBlock::new(32)),
            analyze: self
                .values("report.analyze")
                .map(|(_, v)| v.to_string())
                .collect(),
        })
    }

    fn parse_report(
        &self,
        ctx: &ConfigContext,
        id: &str,
        default_hostname: &str,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<Report> {
        Ok(Report {
            name: self
                .parse_if_block(("report", id, "from-name"), ctx, available_keys)?
                .unwrap_or_else(|| IfBlock::new("Mail Delivery Subsystem".to_string())),
            address: self
                .parse_if_block(("report", id, "from-address"), ctx, available_keys)?
                .unwrap_or_else(|| IfBlock::new(format!("MAILER-DAEMON@{}", default_hostname))),
            subject: self
                .parse_if_block(("report", id, "subject"), ctx, available_keys)?
                .unwrap_or_else(|| IfBlock::new(format!("{} Report", id.to_ascii_uppercase()))),
            sign: self
                .parse_if_block::<Vec<String>>(("report", id, "sign"), ctx, available_keys)?
                .unwrap_or_default()
                .map_if_block(&ctx.signers, &("report", id, "sign").as_key(), "signature")?,
            send: self
                .parse_if_block(("report", id, "send"), ctx, available_keys)?
                .unwrap_or_default(),
        })
    }

    fn parse_aggregate_report(
        &self,
        ctx: &ConfigContext,
        id: &str,
        default_hostname: &str,
        available_keys: &[EnvelopeKey],
    ) -> super::Result<AggregateReport> {
        let rcpt_envelope_keys = [EnvelopeKey::RecipientDomain];

        Ok(AggregateReport {
            name: self
                .parse_if_block(
                    ("report", id, "aggregate.from-name"),
                    ctx,
                    &rcpt_envelope_keys,
                )?
                .unwrap_or_else(|| {
                    IfBlock::new(format!("{} Aggregate Report", id.to_ascii_uppercase()))
                }),
            address: self
                .parse_if_block(
                    ("report", id, "aggregate.from-address"),
                    ctx,
                    &rcpt_envelope_keys,
                )?
                .unwrap_or_else(|| IfBlock::new(format!("noreply-{}@{}", id, default_hostname))),
            subject: self
                .parse_if_block(
                    ("report", id, "aggregate.subject"),
                    ctx,
                    &rcpt_envelope_keys,
                )?
                .unwrap_or_else(|| {
                    IfBlock::new(format!("{} Aggregage Report", id.to_ascii_uppercase()))
                }),
            org_name: self
                .parse_if_block(
                    ("report", id, "aggregate.org-name"),
                    ctx,
                    &rcpt_envelope_keys,
                )?
                .unwrap_or_default(),
            contact_info: self
                .parse_if_block(
                    ("report", id, "aggregate.contact-info"),
                    ctx,
                    &rcpt_envelope_keys,
                )?
                .unwrap_or_default(),
            send: self
                .parse_if_block(("report", id, "aggregate.send"), ctx, available_keys)?
                .unwrap_or_default(),
            sign: self
                .parse_if_block::<Vec<String>>(
                    ("report", id, "aggregate.sign"),
                    ctx,
                    &rcpt_envelope_keys,
                )?
                .unwrap_or_default()
                .map_if_block(
                    &ctx.signers,
                    &("report", id, "aggregate.sign").as_key(),
                    "signature",
                )?,
            max_size: self
                .parse_if_block(
                    ("report", id, "aggregate.max-size"),
                    ctx,
                    &rcpt_envelope_keys,
                )?
                .unwrap_or_else(|| IfBlock::new(25 * 1024 * 1024)),
        })
    }
}
