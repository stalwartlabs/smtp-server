use std::{collections::hash_map::Entry, path::PathBuf, sync::Arc};

use ahash::AHashMap;
use mail_auth::{
    common::verify::VerifySignature,
    dmarc::{self, URI},
    report::{AuthFailureType, IdentityAlignment, PolicyPublished, Record, Report, SPFDomainScope},
    ArcOutput, AuthenticatedMessage, AuthenticationResults, DkimOutput, DkimResult, DmarcOutput,
    SpfResult,
};
use serde::{Deserialize, Serialize};
use tokio::{
    fs,
    io::{AsyncRead, AsyncWrite},
};

use crate::{
    config::AggregateFrequency,
    core::{Core, Session},
    queue::{DomainPart, InstantFromTimestamp, Schedule},
};

use super::{
    scheduler::{
        json_append, json_read, json_write, ReportPath, ReportPolicy, ReportType, Scheduler, ToHash,
    },
    DmarcEvent,
};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DmarcFormat {
    rua: Vec<URI>,
    policy: PolicyPublished,
    records: Vec<Record>,
}

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
                            tracing::debug!(
                                parent: &self.span,
                                context = "report",
                                report = "dkim",
                                event = "unauthorized-ruf",
                                ruf = ?dmarc_record.ruf(),
                                "Unauthorized external reporting addresses"
                            );
                        }
                        vec![]
                    }
                }
                None => {
                    tracing::debug!(
                        parent: &self.span,
                        context = "report",
                        report = "dmarc",
                        event = "dns-failure",
                        ruf = ?dmarc_record.ruf(),
                        "Failed to validate external report addresses",
                    );
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
                    dmarc::Report::Dkim
                    | dmarc::Report::DkimSpf
                    | dmarc::Report::All
                    | dmarc::Report::Any,
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
                    dmarc::Report::Spf
                    | dmarc::Report::DkimSpf
                    | dmarc::Report::All
                    | dmarc::Report::Any,
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
                        (config.name.eval(self).await.as_str(), from_addr.as_str()),
                        &rcpts.join(", "),
                        config.subject.eval(self).await,
                        &mut report,
                    )
                    .ok();

                tracing::info!(
                    parent: &self.span,
                    context = "report",
                    report = "dmarc",
                    event = "queue",
                    rcpt = ?rcpts,
                    "Queueing DMARC authentication failure report."
                );

                // Send report
                self.core
                    .send_report(
                        from_addr,
                        rcpts.into_iter(),
                        report,
                        &config.sign,
                        &self.span,
                    )
                    .await;
            } else {
                tracing::debug!(
                    parent: &self.span,
                    context = "report",
                    report = "dmarc",
                    event = "throttle",
                    ruf = ?dmarc_record.ruf(),
                );
            }
        }

        // Send agregate reports
        let interval = self
            .core
            .report
            .config
            .dmarc_aggregate
            .send
            .eval(self)
            .await;

        if matches!(interval, AggregateFrequency::Never) || dmarc_record.rua().is_empty() {
            return;
        }

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
        self.core
            .schedule_report(DmarcEvent {
                domain: dmarc_output.into_domain(),
                report_record,
                dmarc_record,
                interval: *interval,
            })
            .await;
    }
}

pub trait GenerateDmarcReport {
    fn generate_dmarc_report(&self, domain: ReportPolicy<String>, path: ReportPath<PathBuf>);
}

impl GenerateDmarcReport for Arc<Core> {
    fn generate_dmarc_report(&self, domain: ReportPolicy<String>, path: ReportPath<PathBuf>) {
        let core = self.clone();
        tokio::spawn(async move {
            let deliver_at = path.created + path.deliver_at.as_secs();
            let span = tracing::info_span!(
                "dmarc-report",
                domain = domain.inner,
                range_from = path.created,
                range_to = deliver_at,
                size = path.size,
            );

            // Deserialize report
            let dmarc = if let Some(dmarc) = json_read::<DmarcFormat>(&path.path, &span).await {
                dmarc
            } else {
                return;
            };

            // Verify external reporting addresses
            let rua = match core
                .resolvers
                .dns
                .verify_dmarc_report_address(&domain.inner, &dmarc.rua)
                .await
            {
                Some(rcpts) => {
                    if !rcpts.is_empty() {
                        rcpts
                            .into_iter()
                            .map(|u| u.uri().to_string())
                            .collect::<Vec<_>>()
                    } else {
                        tracing::info!(
                            parent: &span,
                            event = "failed",
                            reason = "unauthorized-rua",
                            rua = ?dmarc.rua,
                            "Unauthorized external reporting addresses"
                        );
                        let _ = fs::remove_file(&path.path).await;
                        return;
                    }
                }
                None => {
                    tracing::info!(
                        parent: &span,
                        event = "failed",
                        reason = "dns-failure",
                        rua = ?dmarc.rua,
                        "Failed to validate external report addresses",
                    );
                    let _ = fs::remove_file(&path.path).await;
                    return;
                }
            };

            // Group duplicates
            let mut record_map = AHashMap::with_capacity(dmarc.records.len());
            for record in dmarc.records {
                match record_map.entry(record) {
                    Entry::Occupied(mut e) => {
                        *e.get_mut() += 1;
                    }
                    Entry::Vacant(e) => {
                        e.insert(1u32);
                    }
                }
            }

            // Create report
            let config = &core.report.config.dmarc_aggregate;
            let mut report = Report::new()
                .with_policy_published(dmarc.policy)
                .with_date_range_begin(path.created)
                .with_date_range_end(deliver_at)
                .with_report_id(format!("{}_{}", domain.policy, path.created))
                .with_email(config.address.eval(&domain.inner.as_str()).await);
            if let Some(org_name) = config.org_name.eval(&domain.inner.as_str()).await {
                report = report.with_org_name(org_name);
            }
            if let Some(contact_info) = config.contact_info.eval(&domain.inner.as_str()).await {
                report = report.with_extra_contact_info(contact_info);
            }
            for (record, count) in record_map {
                report.add_record(record.with_count(count));
            }
            let from_addr = config.address.eval(&domain.inner.as_str()).await;
            let mut message = Vec::with_capacity(path.size);
            let _ = report.write_rfc5322(
                core.report
                    .config
                    .submitter
                    .eval(&domain.inner.as_str())
                    .await,
                (
                    config.name.eval(&domain.inner.as_str()).await.as_str(),
                    from_addr.as_str(),
                ),
                rua.iter().map(|a| a.as_str()),
                &mut message,
            );

            // Send report
            core.send_report(from_addr, rua.iter(), message, &config.sign, &span)
                .await;

            if let Err(err) = fs::remove_file(&path.path).await {
                tracing::warn!(
                    context = "report",
                    event = "error",
                    "Failed to remove report file {}: {}",
                    path.path.display(),
                    err
                );
            }
        });
    }
}

impl Scheduler {
    pub async fn schedule_dmarc(&mut self, event: Box<DmarcEvent>, core: &Core) {
        let max_size = core
            .report
            .config
            .dmarc_aggregate
            .max_size
            .eval(&event.domain.as_str())
            .await;

        let policy = event.dmarc_record.to_hash();
        let (create, path) = match self.reports.entry(ReportType::Dmarc(ReportPolicy {
            inner: event.domain,
            policy,
        })) {
            Entry::Occupied(e) => (None, e.into_mut().dmarc_path()),
            Entry::Vacant(e) => {
                let domain = e.key().domain_name().to_string();
                let created = event.interval.from_timestamp();
                let deliver_at = created + event.interval.as_secs();

                self.main.push(Schedule {
                    due: deliver_at.to_instant(),
                    inner: e.key().clone(),
                });
                let path = core
                    .build_report_path(ReportType::Dmarc(&domain), policy, created, event.interval)
                    .await;
                let v = e.insert(ReportType::Dmarc(ReportPath {
                    path,
                    deliver_at: event.interval,
                    created,
                    size: 0,
                }));
                (domain.into(), v.dmarc_path())
            }
        };

        if let Some(domain) = create {
            // Serialize report
            let entry = DmarcFormat {
                rua: event.dmarc_record.rua().to_vec(),
                policy: PolicyPublished::from_record(domain, &event.dmarc_record),
                records: vec![event.report_record],
            };
            let bytes_written = json_write(&path.path, &entry).await;

            if bytes_written > 0 {
                path.size += bytes_written;
            } else {
                // Something went wrong, remove record
                self.reports.remove(&ReportType::Dmarc(ReportPolicy {
                    inner: entry.policy.domain,
                    policy,
                }));
            }
        } else if path.size < *max_size {
            // Append to existing report
            path.size += json_append(&path.path, &event.report_record).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use mail_auth::{
        dmarc::URI,
        report::{Alignment, Disposition, PolicyPublished, Record},
    };

    use crate::reporting::dmarc::DmarcFormat;

    #[test]
    fn strip_json() {
        let mut d = DmarcFormat {
            rua: vec![
                URI {
                    uri: "hello".to_string(),
                    max_size: 0,
                },
                URI {
                    uri: "world".to_string(),
                    max_size: 0,
                },
            ],
            policy: PolicyPublished {
                domain: "example.org".to_string(),
                version_published: None,
                adkim: Alignment::Relaxed,
                aspf: Alignment::Strict,
                p: Disposition::Quarantine,
                sp: Disposition::Reject,
                testing: false,
                fo: None,
            },
            records: vec![Record::default()
                .with_count(1)
                .with_envelope_from("domain.net")
                .with_envelope_to("other.org")],
        };
        let mut s = serde_json::to_string(&d).unwrap();
        s.truncate(s.len() - 2);

        let r = Record::default()
            .with_count(2)
            .with_envelope_from("otherdomain.net")
            .with_envelope_to("otherother.org");
        let rs = serde_json::to_string(&r).unwrap();

        d.records.push(r);

        assert_eq!(
            serde_json::from_str::<DmarcFormat>(&format!("{},{}]}}", s, rs)).unwrap(),
            d
        );
    }
}
