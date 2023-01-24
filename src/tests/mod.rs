use std::{path::PathBuf, time::Duration};

use dashmap::DashMap;
use mail_auth::{
    common::lru::{DnsCache, LruCache},
    trust_dns_resolver::config::{ResolverConfig, ResolverOpts},
    IpLookupStrategy, Resolver,
};
use mail_send::smtp::tls::build_tls_connector;
use smtp_proto::{AUTH_LOGIN, AUTH_PLAIN};
use tokio::sync::mpsc;

use crate::{
    config::{
        utils::ParseValues, AggregateReport, ArcAuthConfig, Auth, Config, ConfigContext, Connect,
        Data, DkimAuthConfig, DmarcAuthConfig, Dsn, Ehlo, EnvelopeKey, Extensions, IfBlock,
        IpRevAuthConfig, Mail, MailAuthConfig, QueueConfig, QueueOutboundSourceIp,
        QueueOutboundTimeout, QueueOutboundTls, QueueQuotas, QueueThrottle, Rcpt, Report,
        ReportAnalysis, ReportConfig, SessionConfig, SessionThrottle, SpfAuthConfig, Throttle,
        VerifyStrategy,
    },
    core::{
        throttle::{ConcurrencyLimiter, ThrottleKeyHasherBuilder},
        Core, QueueCore, ReportCore, Resolvers, SessionCore, TlsConnectors,
    },
    outbound::dane::DnssecResolver,
};

pub mod inbound;
pub mod outbound;
pub mod queue;
pub mod remote;
pub mod reporting;
pub mod session;

pub trait ParseTestConfig {
    fn parse_if<T: Default + ParseValues>(&self, ctx: &ConfigContext) -> IfBlock<T>;
    fn parse_throttle(&self, ctx: &ConfigContext) -> Vec<Throttle>;
    fn parse_quota(&self, ctx: &ConfigContext) -> QueueQuotas;
    fn parse_queue_throttle(&self, ctx: &ConfigContext) -> QueueThrottle;
}

impl ParseTestConfig for &str {
    fn parse_if<T: Default + ParseValues>(&self, ctx: &ConfigContext) -> IfBlock<T> {
        Config::parse(&format!("test = {}\n", self))
            .unwrap()
            .parse_if_block(
                "test",
                ctx,
                &[
                    EnvelopeKey::Recipient,
                    EnvelopeKey::RecipientDomain,
                    EnvelopeKey::Sender,
                    EnvelopeKey::SenderDomain,
                    EnvelopeKey::Mx,
                    EnvelopeKey::HeloDomain,
                    EnvelopeKey::AuthenticatedAs,
                    EnvelopeKey::Listener,
                    EnvelopeKey::RemoteIp,
                    EnvelopeKey::LocalIp,
                    EnvelopeKey::Priority,
                ],
            )
            .unwrap()
            .unwrap()
    }

    fn parse_throttle(&self, ctx: &ConfigContext) -> Vec<Throttle> {
        Config::parse(self)
            .unwrap()
            .parse_throttle(
                "throttle",
                ctx,
                &[
                    EnvelopeKey::Recipient,
                    EnvelopeKey::RecipientDomain,
                    EnvelopeKey::Sender,
                    EnvelopeKey::SenderDomain,
                    EnvelopeKey::Mx,
                    EnvelopeKey::HeloDomain,
                    EnvelopeKey::AuthenticatedAs,
                    EnvelopeKey::Listener,
                    EnvelopeKey::RemoteIp,
                    EnvelopeKey::LocalIp,
                    EnvelopeKey::Priority,
                ],
                u16::MAX,
            )
            .unwrap()
    }

    fn parse_quota(&self, ctx: &ConfigContext) -> QueueQuotas {
        Config::parse(self).unwrap().parse_queue_quota(ctx).unwrap()
    }

    fn parse_queue_throttle(&self, ctx: &ConfigContext) -> QueueThrottle {
        Config::parse(self)
            .unwrap()
            .parse_queue_throttle(ctx)
            .unwrap()
    }
}

impl Core {
    pub fn test() -> Self {
        Core {
            worker_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(num_cpus::get())
                .build()
                .unwrap(),
            session: SessionCore::test(),
            queue: QueueCore::test(),
            resolvers: Resolvers {
                dns: Resolver::new_system_conf().unwrap(),
                dnssec: DnssecResolver::with_capacity(
                    ResolverConfig::cloudflare(),
                    ResolverOpts::default(),
                )
                .unwrap(),
                cache: crate::core::DnsCache {
                    tlsa: LruCache::with_capacity(100),
                    mta_sts: LruCache::with_capacity(100),
                },
            },
            mail_auth: MailAuthConfig::test(),
            report: ReportCore::test(),
        }
    }
}

impl SessionCore {
    pub fn test() -> Self {
        SessionCore {
            config: SessionConfig::test(),
            concurrency: ConcurrencyLimiter::new(100),
            throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                10,
                ThrottleKeyHasherBuilder::default(),
                16,
            ),
        }
    }
}

impl SessionConfig {
    pub fn test() -> Self {
        Self {
            timeout: IfBlock::new(Duration::from_secs(10)),
            duration: IfBlock::new(Duration::from_secs(10)),
            transfer_limit: IfBlock::new(1024 * 1024),
            throttle: SessionThrottle {
                connect: vec![],
                mail_from: vec![],
                rcpt_to: vec![],
            },
            connect: Connect {
                script: IfBlock::new(None),
            },
            ehlo: Ehlo {
                script: IfBlock::new(None),
                require: IfBlock::new(true),
            },
            extensions: Extensions {
                pipelining: IfBlock::new(true),
                chunking: IfBlock::new(true),
                requiretls: IfBlock::new(true),
                no_soliciting: IfBlock::new("domain.org".to_string().into()),
                future_release: IfBlock::new(None),
                deliver_by: IfBlock::new(None),
                mt_priority: IfBlock::new(None),
                dsn: IfBlock::new(true),
            },
            auth: Auth {
                script: IfBlock::new(None),
                lookup: IfBlock::new(None),
                mechanisms: IfBlock::new(AUTH_PLAIN | AUTH_LOGIN),
                require: IfBlock::new(false),
                errors_max: IfBlock::new(10),
                errors_wait: IfBlock::new(Duration::from_secs(1)),
            },
            mail: Mail {
                script: IfBlock::new(None),
            },
            rcpt: Rcpt {
                script: IfBlock::new(None),
                relay: IfBlock::new(false),
                lookup_domains: IfBlock::new(None),
                lookup_addresses: IfBlock::new(None),
                lookup_expn: IfBlock::new(None),
                lookup_vrfy: IfBlock::new(None),
                errors_max: IfBlock::new(3),
                errors_wait: IfBlock::new(Duration::from_secs(1)),
                max_recipients: IfBlock::new(3),
            },
            data: Data {
                script: IfBlock::new(None),
                max_messages: IfBlock::new(10),
                max_message_size: IfBlock::new(1024 * 1024),
                max_received_headers: IfBlock::new(10),
                add_received: IfBlock::new(true),
                add_received_spf: IfBlock::new(true),
                add_return_path: IfBlock::new(true),
                add_auth_results: IfBlock::new(true),
                add_message_id: IfBlock::new(true),
                add_date: IfBlock::new(true),
            },
        }
    }
}

impl QueueCore {
    pub fn test() -> Self {
        Self {
            config: QueueConfig::test(),
            throttle: DashMap::with_capacity_and_hasher_and_shard_amount(
                10,
                ThrottleKeyHasherBuilder::default(),
                16,
            ),
            quota: DashMap::with_capacity_and_hasher_and_shard_amount(
                10,
                ThrottleKeyHasherBuilder::default(),
                16,
            ),
            tx: mpsc::channel(1024).0,
            id_seq: 0.into(),
            connectors: TlsConnectors {
                pki_verify: build_tls_connector(false),
                dummy_verify: build_tls_connector(true),
            },
        }
    }
}

impl QueueConfig {
    pub fn test() -> Self {
        Self {
            path: Default::default(),
            hash: IfBlock::new(10),
            retry: IfBlock::new(vec![Duration::from_secs(10)]),
            notify: IfBlock::new(vec![Duration::from_secs(20)]),
            expire: IfBlock::new(Duration::from_secs(10)),
            hostname: IfBlock::new("mx.example.org".to_string()),
            next_hop: Default::default(),
            max_mx: IfBlock::new(5),
            max_multihomed: IfBlock::new(5),
            source_ip: QueueOutboundSourceIp {
                ipv4: IfBlock::new(vec![]),
                ipv6: IfBlock::new(vec![]),
            },
            ip_strategy: IfBlock::new(IpLookupStrategy::Ipv4thenIpv6),
            tls: QueueOutboundTls {
                dane: IfBlock::new(crate::config::RequireOptional::Optional),
                mta_sts: IfBlock::new(crate::config::RequireOptional::Optional),
                start: IfBlock::new(crate::config::RequireOptional::Optional),
            },
            dsn: Dsn {
                name: IfBlock::new("Mail Delivery Subsystem".to_string()),
                address: IfBlock::new("MAILER-DAEMON@example.org".to_string()),
                sign: IfBlock::default(),
            },
            timeout: QueueOutboundTimeout {
                connect: IfBlock::new(Duration::from_secs(1)),
                greeting: IfBlock::new(Duration::from_secs(1)),
                tls: IfBlock::new(Duration::from_secs(1)),
                ehlo: IfBlock::new(Duration::from_secs(1)),
                mail: IfBlock::new(Duration::from_secs(1)),
                rcpt: IfBlock::new(Duration::from_secs(1)),
                data: IfBlock::new(Duration::from_secs(1)),
                mta_sts: IfBlock::new(Duration::from_secs(1)),
            },
            throttle: QueueThrottle {
                sender: vec![],
                rcpt: vec![],
                host: vec![],
            },
            quota: QueueQuotas {
                sender: vec![],
                rcpt: vec![],
                rcpt_domain: vec![],
            },
        }
    }
}

impl MailAuthConfig {
    pub fn test() -> Self {
        Self {
            dkim: DkimAuthConfig {
                verify: IfBlock::new(VerifyStrategy::Relaxed),
                sign: IfBlock::default(),
            },
            arc: ArcAuthConfig {
                verify: IfBlock::new(VerifyStrategy::Relaxed),
                seal: IfBlock::default(),
            },
            spf: SpfAuthConfig {
                verify_ehlo: IfBlock::new(VerifyStrategy::Relaxed),
                verify_mail_from: IfBlock::new(VerifyStrategy::Relaxed),
            },
            dmarc: DmarcAuthConfig {
                verify: IfBlock::new(VerifyStrategy::Relaxed),
            },
            iprev: IpRevAuthConfig {
                verify: IfBlock::new(VerifyStrategy::Relaxed),
            },
        }
    }
}

impl ReportCore {
    pub fn test() -> Self {
        Self {
            config: ReportConfig::test(),
            tx: mpsc::channel(1024).0,
        }
    }
}

impl ReportConfig {
    pub fn test() -> Self {
        Self {
            path: Default::default(),
            hash: IfBlock::new(10),
            submitter: IfBlock::new("example.org".to_string()),
            analysis: ReportAnalysis {
                addresses: vec![],
                forward: true,
                store: None,
                report_id: 0.into(),
            },
            dkim: Report::test(),
            spf: Report::test(),
            dmarc: Report::test(),
            dmarc_aggregate: AggregateReport::test(),
            tls: AggregateReport::test(),
        }
    }
}

impl Report {
    pub fn test() -> Self {
        Self {
            name: IfBlock::default(),
            address: IfBlock::default(),
            subject: IfBlock::default(),
            sign: IfBlock::default(),
            send: IfBlock::default(),
        }
    }
}

impl AggregateReport {
    pub fn test() -> Self {
        Self {
            name: IfBlock::default(),
            address: IfBlock::default(),
            org_name: IfBlock::default(),
            contact_info: IfBlock::default(),
            send: IfBlock::default(),
            sign: IfBlock::default(),
            max_size: IfBlock::default(),
        }
    }
}

pub struct TempDir {
    pub temp_dir: PathBuf,
    pub delete: bool,
}

pub fn make_temp_dir(name: &str, delete: bool) -> TempDir {
    let mut temp_dir = std::env::temp_dir();
    temp_dir.push(name);
    if !temp_dir.exists() {
        let _ = std::fs::create_dir(&temp_dir);
    } else if delete {
        let _ = std::fs::remove_dir_all(&temp_dir);
        let _ = std::fs::create_dir(&temp_dir);
    }
    TempDir { temp_dir, delete }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if self.delete {
            let _ = std::fs::remove_dir_all(&self.temp_dir);
        }
    }
}

pub fn add_test_certs(config: &str) -> String {
    let mut cert_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cert_path.push("resources");
    cert_path.push("tests");
    cert_path.push("certs");
    let mut cert = cert_path.clone();
    cert.push("tls_cert.pem");
    let mut pk = cert_path.clone();
    pk.push("tls_privatekey.pem");

    config
        .replace("{CERT}", cert.as_path().to_str().unwrap())
        .replace("{PK}", pk.as_path().to_str().unwrap())
}

pub struct QueueReceiver {
    _temp_dir: TempDir,
    pub queue_rx: mpsc::Receiver<crate::queue::Event>,
}

pub struct ReportReceiver {
    pub report_rx: mpsc::Receiver<crate::reporting::Event>,
}

impl Core {
    pub fn init_test_queue(&mut self, test_name: &str) -> QueueReceiver {
        let _temp_dir = make_temp_dir(test_name, true);
        self.queue.config.path = IfBlock::new(_temp_dir.temp_dir.clone());

        let (queue_tx, queue_rx) = mpsc::channel(128);
        self.queue.tx = queue_tx;

        QueueReceiver {
            _temp_dir,
            queue_rx,
        }
    }

    pub fn init_test_report(&mut self) -> ReportReceiver {
        let (report_tx, report_rx) = mpsc::channel(128);
        self.report.tx = report_tx;
        ReportReceiver { report_rx }
    }
}
