use std::{
    collections::hash_map::Entry,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use mail_auth::{
    mta_sts::{ReportUri, TlsRpt},
    report::tlsrpt::{FailureDetails, PolicyDetails, PolicyType},
};
use serde::{Deserialize, Serialize};
use std::fmt::Write;

use crate::{
    core::Core,
    outbound::mta_sts::{Mode, MxPattern},
    queue::Schedule,
};

use super::{
    scheduler::{json_append, json_write, ReportPath, ReportPolicy, ReportType, Scheduler, ToHash},
    TlsEvent,
};

#[derive(Clone)]
pub struct TlsRptOptions {
    pub record: Arc<TlsRpt>,
    pub interval: Duration,
}

#[derive(Serialize, Deserialize)]
struct TlsFormat {
    rua: Vec<ReportUri>,
    policy: PolicyDetails,
    records: Vec<Option<FailureDetails>>,
}

pub trait GenerateTlsReport {
    fn generate_tls_report(&self, domain: String, paths: ReportPath<Vec<ReportPolicy<PathBuf>>>);
}

impl GenerateTlsReport for Arc<Core> {
    fn generate_tls_report(&self, domain: String, path: ReportPath<Vec<ReportPolicy<PathBuf>>>) {
        let core = self.clone();
        tokio::spawn(async {
            //TODO
        });
    }
}

impl Scheduler {
    pub async fn schedule_tls(&mut self, event: Box<TlsEvent>, core: &Core) {
        let max_size = core
            .report
            .config
            .tls
            .max_size
            .eval(&event.domain.as_str())
            .await;
        let policy_hash = event.policy.to_hash();

        let (path, pos, create) = match self.reports.entry(ReportType::Tls(event.domain)) {
            Entry::Occupied(e) => {
                if let ReportType::Tls(path) = e.get() {
                    if let Some(pos) = path.path.iter().position(|p| p.policy == policy_hash) {
                        (e.into_mut().tls_path(), pos, None)
                    } else {
                        let pos = path.path.len();
                        let domain = e.key().domain_name().to_string();
                        let path = e.into_mut().tls_path();
                        path.path.push(ReportPolicy {
                            inner: core
                                .build_report_path(&domain, policy_hash, path.deliver_at, "tls")
                                .await,
                            policy: policy_hash,
                        });
                        (path, pos, domain.into())
                    }
                } else {
                    unreachable!()
                }
            }
            Entry::Vacant(e) => {
                self.main.push(Schedule {
                    due: Instant::now() + event.interval,
                    inner: e.key().clone(),
                });
                let domain = e.key().domain_name().to_string();
                let created = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let deliver_at = created + event.interval.as_secs();
                let path = core
                    .build_report_path(&domain, policy_hash, deliver_at, "tls")
                    .await;
                let v = e.insert(ReportType::Tls(ReportPath {
                    path: vec![ReportPolicy {
                        inner: path,
                        policy: policy_hash,
                    }],
                    size: 0,
                    created,
                    deliver_at,
                }));
                (v.tls_path(), 0, domain.into())
            }
        };

        if let Some(domain) = create {
            let mut policy = PolicyDetails {
                policy_type: PolicyType::NoPolicyFound,
                policy_string: vec![],
                policy_domain: domain,
                mx_host: vec![],
            };

            match event.policy {
                super::PolicyType::Tlsa(tlsa) => {
                    policy.policy_type = PolicyType::Tlsa;
                    if let Some(tlsa) = tlsa {
                        for entry in &tlsa.entries {
                            policy.policy_string.push(format!(
                                "{} {} {} {}",
                                if entry.is_end_entity { 3 } else { 2 },
                                i32::from(entry.is_spki),
                                if entry.is_sha256 { 1 } else { 2 },
                                entry
                                    .data
                                    .iter()
                                    .fold(String::with_capacity(64), |mut s, b| {
                                        write!(s, "{:02X}", b).ok();
                                        s
                                    })
                            ));
                        }
                    }
                }
                super::PolicyType::Sts(sts) => {
                    policy.policy_type = PolicyType::Sts;
                    if let Some(sts) = sts {
                        policy.policy_string.push("version: STSv1".to_string());
                        policy.policy_string.push(format!(
                            "mode: {}",
                            match sts.mode {
                                Mode::Enforce => "enforce",
                                Mode::Testing => "testing",
                                Mode::None => "none",
                            }
                        ));
                        policy
                            .policy_string
                            .push(format!("max_age: {}", sts.max_age));
                        for mx in &sts.mx {
                            let mx = match mx {
                                MxPattern::Equals(mx) => mx.to_string(),
                                MxPattern::StartsWith(mx) => format!("*.{}", mx),
                            };
                            policy.policy_string.push(format!("mx: {}", mx));
                            policy.mx_host.push(mx);
                        }
                    }
                }
                _ => (),
            }

            // Create report entry
            let entry = TlsFormat {
                rua: event.tls_record.rua.clone(),
                policy,
                records: vec![event.failure],
            };
            let bytes_written = json_write(&path.path[pos].inner, &entry).await;

            if bytes_written > 0 {
                path.size = bytes_written;
            } else {
                // Something went wrong, remove record
                if let Entry::Occupied(mut e) = self
                    .reports
                    .entry(ReportType::Tls(entry.policy.policy_domain))
                {
                    if let ReportType::Tls(path) = e.get_mut() {
                        path.path.retain(|p| p.policy != policy_hash);
                        if path.path.is_empty() {
                            e.remove_entry();
                        }
                    }
                }
            }
        } else if path.size < *max_size {
            // Append to existing report
            path.size += json_append(&path.path[pos].inner, &event.failure).await;
        }
    }
}
