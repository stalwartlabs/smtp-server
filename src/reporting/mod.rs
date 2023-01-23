use std::{sync::Arc, time::SystemTime};

use mail_auth::{
    common::headers::HeaderWriter,
    dmarc::Dmarc,
    mta_sts::TlsRpt,
    report::{
        tlsrpt::FailureDetails, AuthFailureType, DeliveryResult, Feedback, FeedbackType, Record,
    },
};
use mail_parser::DateTime;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    config::{AddressMatch, AggregateFrequency, DkimSigner, IfBlock},
    core::{Core, Session},
    outbound::{dane::Tlsa, mta_sts::Policy},
    queue::{DomainPart, Message},
    USER_AGENT,
};

pub mod analysis;
pub mod dkim;
pub mod dmarc;
pub mod scheduler;
pub mod spf;
pub mod tls;

#[derive(Debug)]
pub enum Event {
    Dmarc(Box<DmarcEvent>),
    Tls(Box<TlsEvent>),
    Stop,
}

#[derive(Debug)]
pub struct DmarcEvent {
    pub domain: String,
    pub report_record: Record,
    pub dmarc_record: Arc<Dmarc>,
    pub interval: AggregateFrequency,
}

#[derive(Debug)]
pub struct TlsEvent {
    pub domain: String,
    pub policy: PolicyType,
    pub failure: Option<FailureDetails>,
    pub tls_record: Arc<TlsRpt>,
    pub interval: AggregateFrequency,
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum PolicyType {
    Tlsa(Option<Arc<Tlsa>>),
    Sts(Option<Arc<Policy>>),
    None,
}

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub fn new_auth_failure(&self, ft: AuthFailureType, rejected: bool) -> Feedback<'_> {
        Feedback::new(FeedbackType::AuthFailure)
            .with_auth_failure(ft)
            .with_arrival_date(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()) as i64,
            )
            .with_source_ip(self.data.remote_ip)
            .with_reporting_mta(&self.instance.hostname)
            .with_user_agent(USER_AGENT)
            .with_delivery_result(if rejected {
                DeliveryResult::Reject
            } else {
                DeliveryResult::Unspecified
            })
    }

    pub fn is_report(&self) -> bool {
        for addr_match in &self.core.report.config.analysis.addresses {
            for addr in &self.data.rcpt_to {
                match addr_match {
                    AddressMatch::StartsWith(prefix) if addr.address_lcase.starts_with(prefix) => {
                        return true
                    }
                    AddressMatch::EndsWith(suffix) if addr.address_lcase.ends_with(suffix) => {
                        return true
                    }
                    AddressMatch::Equals(value) if addr.address_lcase.eq(value) => return true,
                    _ => (),
                }
            }
        }

        false
    }
}

impl Core {
    pub async fn send_report(
        &self,
        from_addr: &str,
        rcpts: impl Iterator<Item = impl AsRef<str>>,
        report: Vec<u8>,
        sign_config: &IfBlock<Vec<Arc<DkimSigner>>>,
        span: &tracing::Span,
    ) {
        // Build message
        let from_addr_lcase = from_addr.to_lowercase();
        let from_addr_domain = from_addr_lcase.domain_part().to_string();
        let mut message = Message::new_boxed(from_addr, from_addr_lcase, from_addr_domain);
        for rcpt_ in rcpts {
            let rcpt = rcpt_.as_ref();
            let rcpt_lcase = rcpt.to_lowercase();
            let rcpt_domain = rcpt_lcase.domain_part().to_string();

            message
                .add_recipient(rcpt, rcpt_lcase, rcpt_domain, &self.queue.config)
                .await;
        }

        // Sign message
        let signature = message.sign(sign_config, &report, span).await;

        // Queue message
        self.queue
            .queue_message(message, signature.as_deref(), &report, span)
            .await;
    }

    pub async fn schedule_report(&self, report: impl Into<Event>) {
        if self.report.tx.send(report.into()).await.is_err() {
            tracing::warn!(contex = "report", "Channel send failed.");
        }
    }
}

impl Message {
    pub async fn sign(
        &mut self,
        config: &IfBlock<Vec<Arc<DkimSigner>>>,
        bytes: &[u8],
        span: &tracing::Span,
    ) -> Option<Vec<u8>> {
        let signers = config.eval(self).await;
        if !signers.is_empty() {
            let mut headers = Vec::with_capacity(64);
            for signer in signers.iter() {
                match signer.sign(bytes) {
                    Ok(signature) => {
                        signature.write_header(&mut headers);
                    }
                    Err(err) => {
                        tracing::warn!(parent: span,
                        context = "dkim",
                        event = "sign-failed",
                        reason = %err);
                    }
                }
            }
            if !headers.is_empty() {
                return Some(headers);
            }
        }
        None
    }
}

impl AggregateFrequency {
    pub fn from_timestamp(&self) -> u64 {
        let mut dt = DateTime::from_timestamp(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()) as i64,
        );
        (match self {
            AggregateFrequency::Hourly => {
                dt.minute = 0;
                dt.second = 0;
                dt.to_timestamp()
            }
            AggregateFrequency::Daily => {
                dt.hour = 0;
                dt.minute = 0;
                dt.second = 0;
                dt.to_timestamp()
            }
            AggregateFrequency::Weekly => {
                let dow = dt.day_of_week();
                dt.hour = 0;
                dt.minute = 0;
                dt.second = 0;
                dt.to_timestamp() - (86400 * 7 * dow as i64)
            }
            AggregateFrequency::Never => dt.to_timestamp(),
        }) as u64
    }

    pub fn as_secs(&self) -> u64 {
        match self {
            AggregateFrequency::Hourly => 3600,
            AggregateFrequency::Daily => 86400,
            AggregateFrequency::Weekly => 7 * 86400,
            AggregateFrequency::Never => 0,
        }
    }
}

impl From<DmarcEvent> for Event {
    fn from(value: DmarcEvent) -> Self {
        Event::Dmarc(Box::new(value))
    }
}

impl From<TlsEvent> for Event {
    fn from(value: TlsEvent) -> Self {
        Event::Tls(Box::new(value))
    }
}

impl From<Arc<Tlsa>> for PolicyType {
    fn from(value: Arc<Tlsa>) -> Self {
        PolicyType::Tlsa(Some(value))
    }
}

impl From<Arc<Policy>> for PolicyType {
    fn from(value: Arc<Policy>) -> Self {
        PolicyType::Sts(Some(value))
    }
}

impl From<&Arc<Tlsa>> for PolicyType {
    fn from(value: &Arc<Tlsa>) -> Self {
        PolicyType::Tlsa(Some(value.clone()))
    }
}

impl From<&Arc<Policy>> for PolicyType {
    fn from(value: &Arc<Policy>) -> Self {
        PolicyType::Sts(Some(value.clone()))
    }
}

impl From<(&Option<Arc<Policy>>, &Option<Arc<Tlsa>>)> for PolicyType {
    fn from(value: (&Option<Arc<Policy>>, &Option<Arc<Tlsa>>)) -> Self {
        match value {
            (Some(value), _) => PolicyType::Sts(Some(value.clone())),
            (_, Some(value)) => PolicyType::Tlsa(Some(value.clone())),
            _ => PolicyType::None,
        }
    }
}
