use ahash::{AHashMap, AHasher};
use mail_auth::{
    common::{base32::Base32Writer, headers::Writer},
    dmarc::Dmarc,
};

use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::BinaryHeap,
    hash::{Hash, Hasher},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
    sync::mpsc,
};

use crate::{core::Core, queue::Schedule};

use super::{dmarc::GenerateDmarcReport, tls::GenerateTlsReport, Event};

pub type ReportKey = ReportType<ReportPolicy<String>, String>;
pub type ReportValue = ReportType<ReportPath<PathBuf>, ReportPath<Vec<ReportPolicy<PathBuf>>>>;

pub struct Scheduler {
    short_wait: Duration,
    long_wait: Duration,
    pub main: BinaryHeap<Schedule<ReportKey>>,
    pub reports: AHashMap<ReportKey, ReportValue>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ReportType<T, U> {
    Dmarc(T),
    Tls(U),
}

pub struct ReportPath<T> {
    pub path: T,
    pub size: usize,
    pub created: u64,
    pub deliver_at: u64,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ReportPolicy<T> {
    pub inner: T,
    pub policy: u64,
}

impl SpawnReport for mpsc::Receiver<Event> {
    fn spawn(mut self, core: Arc<Core>, mut scheduler: Scheduler) {
        tokio::spawn(async move {
            loop {
                match tokio::time::timeout(scheduler.wake_up_time(), self.recv()).await {
                    Ok(Some(event)) => match event {
                        Event::Dmarc(event) => {
                            scheduler.schedule_dmarc(event, &core).await;
                        }
                        Event::Tls(event) => {
                            scheduler.schedule_tls(event, &core).await;
                        }
                        Event::Stop => break,
                    },
                    Ok(None) => break,
                    Err(_) => {
                        while let Some(report) = scheduler.next_due() {
                            match report {
                                (ReportType::Dmarc(domain), ReportType::Dmarc(path)) => {
                                    core.generate_dmarc_report(domain, path);
                                }
                                (ReportType::Tls(domain), ReportType::Tls(path)) => {
                                    core.generate_tls_report(domain, path);
                                }
                                _ => unreachable!(),
                            }
                        }
                    }
                }
            }
        });
    }
}

impl Core {
    pub async fn build_report_path(
        &self,
        domain: &str,
        policy: u64,
        deliver_at: u64,
        rtype: &str,
    ) -> PathBuf {
        // Build base path
        let mut path = self.report.config.path.eval(&domain).await.clone();
        path.push((policy % *self.report.config.hash.eval(&domain).await).to_string());
        let _ = fs::create_dir(&path).await;

        // Build filename
        use std::fmt::Write;
        let mut w = Base32Writer::with_capacity(domain.len() + 16);
        w.write(domain.as_bytes());
        let mut file = w.finalize();
        let _ = write!(file, "_{}_{}_{}.rpt", rtype, policy, deliver_at);
        path.push(file);
        path
    }
}

impl Scheduler {
    pub fn next_due(&mut self) -> Option<(ReportKey, ReportValue)> {
        let item = self.main.peek()?;
        if item.due <= Instant::now() {
            let item = self.main.pop().unwrap();
            self.reports
                .remove(&item.inner)
                .map(|policy| (item.inner, policy))
        } else {
            None
        }
    }

    pub fn wake_up_time(&self) -> Duration {
        self.main
            .peek()
            .map(|item| {
                item.due
                    .checked_duration_since(Instant::now())
                    .unwrap_or(self.short_wait)
            })
            .unwrap_or(self.long_wait)
    }
}

pub async fn json_write(path: &PathBuf, entry: &impl Serialize) -> usize {
    if let Ok(bytes) = serde_json::to_vec(entry) {
        // Save serialized report
        let bytes_written = bytes.len() - 2;
        match fs::File::create(&path).await {
            Ok(mut file) => match file.write_all(&bytes[..bytes_written]).await {
                Ok(_) => bytes_written,
                Err(err) => {
                    tracing::error!(
                        module = "report",
                        event = "error",
                        "Failed to write to report file {}: {}",
                        path.display(),
                        err
                    );
                    0
                }
            },
            Err(err) => {
                tracing::error!(
                    module = "report",
                    event = "error",
                    "Failed to create report file {}: {}",
                    path.display(),
                    err
                );
                0
            }
        }
    } else {
        0
    }
}

pub async fn json_append(path: &PathBuf, entry: &impl Serialize) -> usize {
    let mut bytes = Vec::with_capacity(128);
    bytes.push(b',');
    if serde_json::to_writer(&mut bytes, entry).is_ok() {
        let err = match OpenOptions::new().append(true).open(&path).await {
            Ok(mut file) => match file.write_all(&bytes).await {
                Ok(_) => return bytes.len() + 1,
                Err(err) => err,
            },
            Err(err) => err,
        };
        tracing::error!(
            module = "report",
            event = "error",
            "Failed to append report to {}: {}",
            path.display(),
            err
        );
    }
    0
}

pub async fn json_read<T: DeserializeOwned>(path: &PathBuf) -> Option<T> {
    match fs::read_to_string(&path).await {
        Ok(mut json) => {
            json.push_str("]}");
            match serde_json::from_str(&json) {
                Ok(report) => Some(report),
                Err(err) => {
                    tracing::error!(
                        module = "report",
                        event = "error",
                        "Failed to deserialize report file {}: {}",
                        path.display(),
                        err
                    );
                    None
                }
            }
        }
        Err(err) => {
            tracing::error!(
                module = "report",
                event = "error",
                "Failed to read report file {}: {}",
                path.display(),
                err
            );
            None
        }
    }
}

impl ReportKey {
    pub fn domain_name(&self) -> &str {
        match self {
            ReportType::Dmarc(domain) => domain.inner.as_str(),
            ReportType::Tls(domain) => domain.as_str(),
        }
    }
}

impl ReportValue {
    pub fn dmarc_path(&mut self) -> &mut ReportPath<PathBuf> {
        match self {
            ReportType::Dmarc(path) => path,
            ReportType::Tls(_) => unreachable!(),
        }
    }

    pub fn tls_path(&mut self) -> &mut ReportPath<Vec<ReportPolicy<PathBuf>>> {
        match self {
            ReportType::Tls(path) => path,
            ReportType::Dmarc(_) => unreachable!(),
        }
    }
}

pub trait ToHash {
    fn to_hash(&self) -> u64;
}

impl ToHash for Dmarc {
    fn to_hash(&self) -> u64 {
        let mut hasher = AHasher::default();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

impl ToHash for super::PolicyType {
    fn to_hash(&self) -> u64 {
        let mut hasher = AHasher::default();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

pub trait ToTimestamp {
    fn to_timestamp(&self) -> u64;
}

impl ToTimestamp for Duration {
    fn to_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            + self.as_secs()
    }
}

pub trait SpawnReport {
    fn spawn(self, core: Arc<Core>, scheduler: Scheduler);
}
