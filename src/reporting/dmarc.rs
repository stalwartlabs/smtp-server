use mail_auth::{
    common::verify::VerifySignature,
    dmarc::Report,
    report::{AuthFailureType, IdentityAlignment, PolicyPublished, Record, SPFDomainScope},
    ArcOutput, AuthenticatedMessage, AuthenticationResults, DkimOutput, DkimResult, DmarcOutput,
    SpfResult,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{core::Session, queue::DomainPart};

use super::{DmarcEvent, Event};

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    #[allow(clippy::too_many_arguments)]
    pub async fn send_dmarc_report(
        &self,
        message: &AuthenticatedMessage<'_>,
        auth_results: &AuthenticationResults<'_>,
        rejected: bool,
        dmarc_output: DmarcOutput,
        dkim_output: &[DkimOutput<'_>],
        arc_output: &Option<ArcOutput<'_>>,
    ) {
        let dmarc_record = dmarc_output.dmarc_record_cloned().unwrap();
        let config = &self.core.report.config.dmarc;

        // Send failure report
        if let (Some(failure_rate), Some(report_options)) =
            (config.send.eval(self).await, dmarc_output.failure_report())
        {
            // Verify that any external reporting addresses are authorized
            let rcpts = match self
                .core
                .resolvers
                .dns
                .verify_dmarc_report_address(dmarc_output.domain(), dmarc_record.ruf())
                .await
            {
                Some(rcpts) => {
                    if !rcpts.is_empty() {
                        rcpts
                            .into_iter()
                            .filter_map(|rcpt| {
                                if self.throttle_rcpt(rcpt.uri(), failure_rate, "dmarc") {
                                    rcpt.uri().into()
                                } else {
                                    None
                                }
                            })
                            .collect()
                    } else {
                        if !dmarc_record.ruf().is_empty() {
                            let log = "df";
                            tracing::warn!("log");
                        }
                        vec![]
                    }
                }
                None => {
                    let log = "df";
                    tracing::warn!("log");
                    vec![]
                }
            };

            // Throttle recipient
            if !rcpts.is_empty() {
                let mut report = Vec::with_capacity(128);
                let from_addr = config.address.eval(self).await;
                let mut auth_failure = self
                    .new_auth_failure(AuthFailureType::Dmarc, rejected)
                    .with_authentication_results(auth_results.to_string())
                    .with_headers(message.raw_headers());

                // Report the first failed signature
                let dkim_failed = if let (
                    Report::Dkim | Report::DkimSpf | Report::All | Report::Any,
                    Some(signature),
                ) = (
                    &report_options,
                    dkim_output.iter().find_map(|o| {
                        let s = o.signature()?;
                        if !matches!(o.result(), DkimResult::Pass) {
                            Some(s)
                        } else {
                            None
                        }
                    }),
                ) {
                    auth_failure = auth_failure
                        .with_dkim_domain(signature.domain())
                        .with_dkim_selector(signature.selector())
                        .with_dkim_identity(signature.identity());
                    true
                } else {
                    false
                };

                // Report SPF failure
                let spf_failed = if let (
                    Report::Spf | Report::DkimSpf | Report::All | Report::Any,
                    Some(output),
                ) = (
                    &report_options,
                    self.data
                        .spf_ehlo
                        .as_ref()
                        .and_then(|s| {
                            if s.result() != SpfResult::Pass {
                                s.into()
                            } else {
                                None
                            }
                        })
                        .or_else(|| {
                            self.data.spf_mail_from.as_ref().and_then(|s| {
                                if s.result() != SpfResult::Pass {
                                    s.into()
                                } else {
                                    None
                                }
                            })
                        }),
                ) {
                    auth_failure =
                        auth_failure.with_spf_dns(format!("txt : {} : v=SPF1", output.domain()));
                    // TODO use DNS record
                    true
                } else {
                    false
                };

                auth_failure
                    .with_identity_alignment(if dkim_failed && spf_failed {
                        IdentityAlignment::DkimSpf
                    } else if dkim_failed {
                        IdentityAlignment::Dkim
                    } else {
                        IdentityAlignment::Spf
                    })
                    .write_rfc5322(
                        config.name.eval(self).await,
                        from_addr,
                        &rcpts.join(", "),
                        config.subject.eval(self).await,
                        &mut report,
                    )
                    .ok();

                // Send report
                self.send_report(from_addr, rcpts.into_iter(), report, &config.sign)
                    .await;
            }
        }

        // Send agregate reports
        let interval = match self.core.report.config.dmarc_aggregate.eval(self).await {
            Some(interval) if !dmarc_record.rua().is_empty() => interval,
            _ => return,
        };

        // Verify that any external reporting addresses are authorized
        /*let rua = match self
            .core
            .resolvers
            .dns
            .verify_dmarc_report_address(dmarc_output.domain(), dmarc_record.rua())
            .await
        {
            Some(rcpts) => {
                if !rcpts.is_empty() {
                    rcpts
                        .into_iter()
                        .map(|u| u.uri().to_string())
                        .collect::<Vec<_>>()
                } else {
                    let log = "df";
                    tracing::warn!("log");
                    return;
                }
            }
            None => {
                let log = "df";
                tracing::warn!("log");
                return;
            }
        };*/

        // Create DMARC report record
        let mut report_record = Record::new()
            .with_dmarc_output(&dmarc_output)
            .with_dkim_output(dkim_output)
            .with_source_ip(self.data.remote_ip)
            .with_header_from(message.from().domain_part())
            .with_envelope_from(
                self.data
                    .mail_from
                    .as_ref()
                    .map(|mf| mf.domain.as_str())
                    .unwrap_or_else(|| self.data.helo_domain.as_str()),
            );
        if let Some(spf_ehlo) = &self.data.spf_ehlo {
            report_record = report_record.with_spf_output(spf_ehlo, SPFDomainScope::Helo);
        }
        if let Some(spf_mail_from) = &self.data.spf_mail_from {
            report_record = report_record.with_spf_output(spf_mail_from, SPFDomainScope::MailFrom);
        }
        if let Some(arc_output) = arc_output {
            report_record = report_record.with_arc_output(arc_output);
        }

        // Submit DMARC report event
        if let Err(err) = self
            .core
            .report
            .tx
            .send(Event::Dmarc(Box::new(DmarcEvent {
                policy: PolicyPublished::from(dmarc_output),
                report_record,
                dmarc_record,
                interval: *interval,
            })))
            .await
        {
            // log
            let log = "re";
        }
    }
}
