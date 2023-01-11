use super::{utils::AsKey, Config, ConfigContext, EnvelopeKey, IfBlock, Report, ReportConfig};

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
            dmarc_aggregate: self
                .parse_if_block("report.dmarc.aggregate", ctx, &sender_envelope_keys)?
                .unwrap_or_default(),
            tls: self.parse_report(ctx, "tls", default_hostname, &rcpt_envelope_keys)?,
            tls_aggregate: self
                .parse_if_block("report.tls.aggregate", ctx, &rcpt_envelope_keys)?
                .unwrap_or_default(),
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
            analyze: self
                .parse_if_block(("report", id, "analyze"), ctx, available_keys)?
                .unwrap_or_else(|| IfBlock::new(true)),
        })
    }
}
