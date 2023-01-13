use std::{
    borrow::Cow,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use mail_auth::{
    mta_sts::TlsRpt,
    report::tlsrpt::{FailureDetails, ResultType},
};
use mail_send::{Credentials, SmtpClient};
use rand::{seq::SliceRandom, Rng};
use smtp_proto::MAIL_REQUIRETLS;

use crate::{
    config::{RelayHost, ServerProtocol, TlsStrategy},
    core::Core,
    queue::ErrorDetails,
    reporting::{tls::TlsRptOptions, PolicyType, TlsEvent},
};

use super::{
    mta_sts,
    session::{read_greeting, say_helo, try_start_tls, SessionParams, StartTlsResult},
};
use crate::queue::{
    manager::Queue, throttle, DeliveryAttempt, Domain, Error, Event, Message, OnHold,
    QueueEnvelope, Schedule, Status, WorkerResult,
};

impl DeliveryAttempt {
    pub async fn try_deliver(mut self, core: Arc<Core>, queue: &mut Queue) {
        // Check that the message still has recipients to be delivered
        let has_pending_delivery = self.message.has_pending_delivery();

        // Send any due Delivery Status Notifications
        core.queue.send_dsn(&mut self.message).await;

        if has_pending_delivery {
            // Re-queue the message if its not yet due for delivery
            let due = self.message.next_delivery_event();
            if due > Instant::now() {
                // Save changes to disk
                self.message.save_changes().await;

                queue.main.push(Schedule {
                    due,
                    inner: self.message,
                });
                return;
            }
        } else {
            // All message recipients expired, do not re-queue. (DSN has been already sent)
            self.message.remove().await;
            return;
        }

        // Throttle sender
        for throttle in &core.queue.config.throttle.sender {
            if let Err(err) = core
                .queue
                .is_allowed(
                    throttle,
                    self.message.as_ref(),
                    &mut self.in_flight,
                    &self.span,
                )
                .await
            {
                // Save changes to disk
                self.message.save_changes().await;

                match err {
                    throttle::Error::Concurrency { limiter } => {
                        queue.on_hold.push(OnHold {
                            next_due: self.message.next_event_after(Instant::now()),
                            limiters: vec![limiter],
                            message: self.message,
                        });
                    }
                    throttle::Error::Rate { retry_at } => {
                        queue.main.push(Schedule {
                            due: retry_at,
                            inner: self.message,
                        });
                    }
                }
                return;
            }
        }

        let coco = "add logging";

        tokio::spawn(async move {
            let queue_config = &core.queue.config;
            let mut on_hold = Vec::new();
            let no_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

            let mut domains = std::mem::take(&mut self.message.domains);
            let mut recipients = std::mem::take(&mut self.message.recipients);
            'next_domain: for (domain_idx, domain) in domains.iter_mut().enumerate() {
                // Only process domains due for delivery
                if !matches!(&domain.status, Status::Scheduled | Status::TemporaryFailure(_)
                if domain.retry.due <= Instant::now())
                {
                    continue;
                }

                // Create new span
                let span = tracing::info_span!(
                    parent: &self.span,
                    "attempt",
                    "domain" = domain.domain,
                );

                // Build envelope
                let mut envelope = QueueEnvelope {
                    message: self.message.as_ref(),
                    domain: &domain.domain,
                    mx: "",
                    remote_ip: no_ip,
                    local_ip: no_ip,
                };

                // Throttle recipient domain
                let mut in_flight = Vec::new();
                for throttle in &queue_config.throttle.rcpt {
                    if let Err(err) = core
                        .queue
                        .is_allowed(throttle, &envelope, &mut in_flight, &span)
                        .await
                    {
                        domain.set_throttle_error(err, &mut on_hold);
                        continue 'next_domain;
                    }
                }

                // Prepare TLS strategy
                let mut tls_strategy = TlsStrategy {
                    mta_sts: *queue_config.tls.mta_sts.eval(&envelope).await,
                    ..Default::default()
                };

                // Obtain TLS reporting
                let tls_report =
                    if let Some(interval) = core.report.config.tls.send.eval(&envelope).await {
                        match core
                            .resolvers
                            .dns
                            .txt_lookup::<TlsRpt>(format!("_smtp._tls.{}.", envelope.domain))
                            .await
                        {
                            Ok(record) => TlsRptOptions {
                                record,
                                interval: *interval,
                            }
                            .into(),
                            Err(_) => None,
                        }
                    } else {
                        None
                    };

                // Obtain MTA-STS policy for domain
                let mta_sts_policy = if tls_strategy.try_mta_sts() {
                    match core
                        .lookup_mta_sts_policy(
                            envelope.domain,
                            *queue_config.timeout.mta_sts.eval(&envelope).await,
                        )
                        .await
                    {
                        Ok(mta_sts_policy) => mta_sts_policy.into(),
                        Err(err) => {
                            // Report MTA-STS error
                            if let Some(tls_report) = &tls_report {
                                if !matches!(
                                    &err,
                                    mta_sts::Error::Dns(
                                        mail_auth::Error::DnsError(_)
                                            | mail_auth::Error::DnsRecordNotFound(_)
                                    )
                                ) {
                                    core.schedule_report(TlsEvent {
                                        policy: PolicyType::Sts(None),
                                        domain: envelope.domain.to_string(),
                                        failure: FailureDetails::new(&err)
                                            .with_failure_reason_code(err.to_string())
                                            .into(),
                                        tls_record: tls_report.record.clone(),
                                        interval: tls_report.interval,
                                    })
                                    .await;
                                }
                            }

                            if tls_strategy.is_mta_sts_required() {
                                domain.set_status(err, queue_config.retry.eval(&envelope).await);
                                continue 'next_domain;
                            }

                            None
                        }
                    }
                } else {
                    None
                };

                // Obtain remote hosts list
                let mx_list;
                let remote_hosts =
                    if let Some(next_hop) = queue_config.next_hop.eval(&envelope).await {
                        vec![RemoteHost::Relay(next_hop)]
                    } else {
                        // Lookup MX
                        mx_list = match core.resolvers.dns.mx_lookup(&domain.domain).await {
                            Ok(mx) => mx,
                            Err(err) => {
                                domain.set_status(err, queue_config.retry.eval(&envelope).await);
                                continue 'next_domain;
                            }
                        };

                        if !mx_list.is_empty() {
                            // Obtain max number of MX hosts to process
                            let max_mx = *queue_config.max_mx.eval(&envelope).await;
                            let mut remote_hosts = Vec::with_capacity(max_mx);

                            for mx in mx_list.iter() {
                                if mx.exchanges.len() > 1 {
                                    let mut slice = mx.exchanges.iter().collect::<Vec<_>>();
                                    slice.shuffle(&mut rand::thread_rng());
                                    for remote_host in slice {
                                        remote_hosts.push(RemoteHost::MX(remote_host.as_str()));
                                        if remote_hosts.len() == max_mx {
                                            break;
                                        }
                                    }
                                } else if let Some(remote_host) = mx.exchanges.first() {
                                    remote_hosts.push(RemoteHost::MX(remote_host.as_str()));
                                    if remote_hosts.len() == max_mx {
                                        break;
                                    }
                                }
                            }
                            remote_hosts
                        } else {
                            // If an empty list of MXs is returned, the address is treated as if it was
                            // associated with an implicit MX RR with a preference of 0, pointing to that host.
                            vec![RemoteHost::MX(domain.domain.as_str())]
                        }
                    };

                // Try delivering message
                let max_multihomed = *queue_config.max_multihomed.eval(&envelope).await;
                let mut last_status = Status::Scheduled;
                'next_host: for remote_host in &remote_hosts {
                    // Validate MTA-STS
                    envelope.mx = remote_host.hostname();
                    if let Some(mta_sts_policy) = &mta_sts_policy {
                        if !mta_sts_policy.verify(envelope.mx) {
                            // Report MTA-STS failed verification
                            if let Some(tls_report) = &tls_report {
                                core.schedule_report(TlsEvent {
                                    policy: mta_sts_policy.into(),
                                    domain: envelope.domain.to_string(),
                                    failure: FailureDetails::new(ResultType::ValidationFailure)
                                        .with_receiving_mx_hostname(envelope.mx)
                                        .with_failure_reason_code("MX not authorized by policy.")
                                        .into(),
                                    tls_record: tls_report.record.clone(),
                                    interval: tls_report.interval,
                                })
                                .await;
                            }

                            if mta_sts_policy.enforce() {
                                last_status = Status::PermanentFailure(Error::MtaStsError(
                                    format!("MX {:?} not authorized by policy.", envelope.mx),
                                ));
                                continue 'next_host;
                            }
                        }
                    }

                    // Obtain source and remote IPs
                    let (source_ip, remote_ips) = match core
                        .resolve_host(remote_host, &envelope, max_multihomed)
                        .await
                    {
                        Ok(result) => result,
                        Err(status) => {
                            last_status = status;
                            continue 'next_host;
                        }
                    };

                    // Lookup DANE policy
                    let dane_policy = if tls_strategy.try_dane() {
                        match core
                            .resolvers
                            .tlsa_lookup(format!("_25._tcp.{}.", envelope.mx))
                            .await
                        {
                            Ok(Some(tlsa)) => {
                                if tlsa.has_end_entities {
                                    tlsa.into()
                                } else {
                                    tracing::debug!(
                                        parent: &span,
                                        module = "dane",
                                        event = "no-tlsa-records",
                                        "No valid TLSA records were found for host {}.",
                                        envelope.mx,
                                    );

                                    // Report invalid TLSA record
                                    if let Some(tls_report) = &tls_report {
                                        core.schedule_report(TlsEvent {
                                            policy: tlsa.into(),
                                            domain: envelope.domain.to_string(),
                                            failure: FailureDetails::new(ResultType::TlsaInvalid)
                                                .with_receiving_mx_hostname(envelope.mx)
                                                .with_failure_reason_code("Invalid TLSA record.")
                                                .into(),
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                    }

                                    if tls_strategy.is_dane_required() {
                                        last_status = Status::PermanentFailure(Error::DaneError(
                                            ErrorDetails {
                                                entity: envelope.mx.to_string(),
                                                details: "No valid TLSA records were found"
                                                    .to_string(),
                                            },
                                        ));
                                        continue 'next_host;
                                    }
                                    None
                                }
                            }
                            Ok(None) => {
                                if tls_strategy.is_dane_required() {
                                    // Report DANE required
                                    if let Some(tls_report) = &tls_report {
                                        core.schedule_report(TlsEvent {
                                            policy: PolicyType::Tlsa(None),
                                            domain: envelope.domain.to_string(),
                                            failure: FailureDetails::new(ResultType::DaneRequired)
                                                .with_receiving_mx_hostname(envelope.mx)
                                                .with_failure_reason_code(
                                                    "DANE is required by this host.",
                                                )
                                                .into(),
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                    }

                                    tracing::debug!(
                                        parent: &span,
                                        module = "dane",
                                        event = "tlsa-dnssec-missing",
                                        hostname = envelope.mx,
                                        "No TLSA DNSSEC records found."
                                    );

                                    last_status =
                                        Status::PermanentFailure(Error::DaneError(ErrorDetails {
                                            entity: envelope.mx.to_string(),
                                            details: "No TLSA DNSSEC records found".to_string(),
                                        }));
                                    continue 'next_host;
                                }
                                None
                            }
                            Err(err) => {
                                if tls_strategy.is_dane_required() {
                                    last_status =
                                        if matches!(&err, mail_auth::Error::DnsRecordNotFound(_)) {
                                            Status::PermanentFailure(Error::DaneError(
                                                ErrorDetails {
                                                    entity: envelope.mx.to_string(),
                                                    details: "No TLSA records found".to_string(),
                                                },
                                            ))
                                        } else {
                                            err.into()
                                        };
                                    continue 'next_host;
                                }
                                None
                            }
                        }
                    } else {
                        None
                    };

                    // Try each IP address
                    envelope.local_ip = source_ip.unwrap_or(no_ip);
                    'next_ip: for remote_ip in remote_ips {
                        // Throttle remote host
                        let mut in_flight_host = Vec::new();
                        envelope.remote_ip = remote_ip;
                        for throttle in &queue_config.throttle.host {
                            if let Err(err) = core
                                .queue
                                .is_allowed(throttle, &envelope, &mut in_flight_host, &span)
                                .await
                            {
                                domain.set_throttle_error(err, &mut on_hold);
                                continue 'next_domain;
                            }
                        }

                        // Connect
                        let mut smtp_client = match if let Some(ip_addr) = source_ip {
                            SmtpClient::connect_using(
                                ip_addr,
                                SocketAddr::new(remote_ip, remote_host.port()),
                                *queue_config.timeout.connect.eval(&envelope).await,
                            )
                            .await
                        } else {
                            SmtpClient::connect(
                                SocketAddr::new(remote_ip, remote_host.port()),
                                *queue_config.timeout.connect.eval(&envelope).await,
                            )
                            .await
                        } {
                            Ok(smtp_client) => smtp_client,
                            Err(err) => {
                                last_status = Status::from_smtp_error(envelope.mx, "", err);
                                continue 'next_ip;
                            }
                        };

                        // Obtain TLS strategy
                        tls_strategy.dane = *queue_config.tls.dane.eval(&envelope).await;
                        tls_strategy.tls = *queue_config.tls.start.eval(&envelope).await;
                        let tls_connector = if !remote_host.allow_invalid_certs() {
                            &core.queue.connectors.pki_verify
                        } else {
                            &core.queue.connectors.dummy_verify
                        };

                        // Obtail session parameters
                        let params = SessionParams {
                            span: &span,
                            credentials: remote_host.credentials(),
                            is_smtp: remote_host.is_smtp(),
                            hostname: envelope.mx,
                            local_hostname: queue_config.hostname.eval(&envelope).await,
                            timeout_ehlo: *queue_config.timeout.ehlo.eval(&envelope).await,
                            timeout_mail: *queue_config.timeout.mail.eval(&envelope).await,
                            timeout_rcpt: *queue_config.timeout.rcpt.eval(&envelope).await,
                            timeout_data: *queue_config.timeout.data.eval(&envelope).await,
                        };

                        let delivery_result = if !remote_host.implicit_tls() {
                            // Read greeting
                            smtp_client.timeout =
                                *queue_config.timeout.greeting.eval(&envelope).await;
                            if let Err(status) = read_greeting(&mut smtp_client, envelope.mx).await
                            {
                                last_status = status;
                                continue 'next_host;
                            }

                            // Say EHLO
                            let capabilties = match say_helo(&mut smtp_client, &params).await {
                                Ok(capabilities) => capabilities,
                                Err(status) => {
                                    last_status = status;
                                    continue 'next_host;
                                }
                            };

                            // Try starting TLS
                            smtp_client.timeout = *queue_config.timeout.tls.eval(&envelope).await;
                            match try_start_tls(
                                smtp_client,
                                tls_connector,
                                envelope.mx,
                                &capabilties,
                            )
                            .await
                            {
                                StartTlsResult::Success { smtp_client } => {
                                    // Verify DANE
                                    if let Some(dane_policy) = &dane_policy {
                                        if let Err(status) = dane_policy.verify(
                                            &span,
                                            envelope.mx,
                                            smtp_client.tls_connection().peer_certificates(),
                                        ) {
                                            // Report DANE verification failure
                                            if let Some(tls_report) = &tls_report {
                                                core.schedule_report(TlsEvent {
                                                    policy: dane_policy.into(),
                                                    domain: envelope.domain.to_string(),
                                                    failure: FailureDetails::new(
                                                        ResultType::ValidationFailure,
                                                    )
                                                    .with_receiving_mx_hostname(envelope.mx)
                                                    .with_receiving_ip(remote_ip)
                                                    .with_failure_reason_code(
                                                        "No matching certificates found.",
                                                    )
                                                    .into(),
                                                    tls_record: tls_report.record.clone(),
                                                    interval: tls_report.interval,
                                                })
                                                .await;
                                            }

                                            last_status = status;
                                            continue 'next_host;
                                        }
                                    }

                                    // Report TLS success
                                    if let Some(tls_report) = &tls_report {
                                        core.schedule_report(TlsEvent {
                                            policy: (&mta_sts_policy, &dane_policy).into(),
                                            domain: envelope.domain.to_string(),
                                            failure: None,
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                    }

                                    // Deliver message over TLS
                                    self.message
                                        .deliver(
                                            smtp_client,
                                            recipients
                                                .iter_mut()
                                                .filter(|r| r.domain_idx == domain_idx),
                                            params,
                                        )
                                        .await
                                }
                                StartTlsResult::Unavailable {
                                    response,
                                    smtp_client,
                                } => {
                                    // Report unavailable STARTTLS
                                    if let Some(tls_report) = &tls_report {
                                        core.schedule_report(TlsEvent {
                                            policy: (&mta_sts_policy, &dane_policy).into(),
                                            domain: envelope.domain.to_string(),
                                            failure: FailureDetails::new(
                                                ResultType::StartTlsNotSupported,
                                            )
                                            .with_receiving_mx_hostname(envelope.mx)
                                            .with_receiving_ip(remote_ip)
                                            .with_failure_reason_code(
                                                response
                                                    .as_ref()
                                                    .map(|r| r.to_string())
                                                    .unwrap_or_else(|| {
                                                        "STARTTLS was not advertised by host"
                                                            .to_string()
                                                    }),
                                            )
                                            .into(),
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                    }

                                    if tls_strategy.is_tls_required()
                                        || (self.message.flags & MAIL_REQUIRETLS) != 0
                                        || mta_sts_policy.is_some()
                                        || dane_policy.is_some()
                                    {
                                        last_status =
                                            Status::from_starttls_error(envelope.mx, response);
                                        continue 'next_host;
                                    } else {
                                        // TLS is not required, proceed in plain-text
                                        self.message
                                            .deliver(
                                                smtp_client,
                                                recipients
                                                    .iter_mut()
                                                    .filter(|r| r.domain_idx == domain_idx),
                                                params,
                                            )
                                            .await
                                    }
                                }
                                StartTlsResult::Error { error } => {
                                    // Report TLS failure
                                    if let (Some(tls_report), mail_send::Error::Tls(error)) =
                                        (&tls_report, &error)
                                    {
                                        core.schedule_report(TlsEvent {
                                            policy: (&mta_sts_policy, &dane_policy).into(),
                                            domain: envelope.domain.to_string(),
                                            failure: FailureDetails::new(
                                                ResultType::CertificateNotTrusted,
                                            )
                                            .with_receiving_mx_hostname(envelope.mx)
                                            .with_receiving_ip(remote_ip)
                                            .with_failure_reason_code(error.to_string())
                                            .into(),
                                            tls_record: tls_report.record.clone(),
                                            interval: tls_report.interval,
                                        })
                                        .await;
                                    }
                                    last_status = Status::from_tls_error(envelope.mx, error);
                                    continue 'next_host;
                                }
                            }
                        } else {
                            // Start TLS
                            smtp_client.timeout = *queue_config.timeout.tls.eval(&envelope).await;
                            let mut smtp_client =
                                match smtp_client.into_tls(tls_connector, envelope.mx).await {
                                    Ok(smtp_client) => smtp_client,
                                    Err(error) => {
                                        last_status = Status::from_tls_error(envelope.mx, error);
                                        continue 'next_host;
                                    }
                                };

                            // Read greeting
                            smtp_client.timeout =
                                *queue_config.timeout.greeting.eval(&envelope).await;
                            if let Err(status) = read_greeting(&mut smtp_client, envelope.mx).await
                            {
                                last_status = status;
                                continue 'next_host;
                            }

                            // Deliver message
                            self.message
                                .deliver(
                                    smtp_client,
                                    recipients.iter_mut().filter(|r| r.domain_idx == domain_idx),
                                    params,
                                )
                                .await
                        };

                        // Update status for the current domain and continue with the next one
                        domain
                            .set_status(delivery_result, queue_config.retry.eval(&envelope).await);
                        continue 'next_domain;
                    }
                }

                // Update status
                domain.set_status(last_status, queue_config.retry.eval(&envelope).await);
            }
            self.message.domains = domains;
            self.message.recipients = recipients;

            // Send Delivery Status Notifications
            core.queue.send_dsn(&mut self.message).await;

            // Notify queue manager
            let span = self.span;
            let result = if !on_hold.is_empty() {
                // Release quota for completed deliveries
                self.message.release_quota();

                // Save changes to disk
                self.message.save_changes().await;

                WorkerResult::OnHold(OnHold {
                    next_due: self.message.next_event_after(Instant::now()),
                    limiters: on_hold,
                    message: self.message,
                })
            } else if let Some(due) = self.message.next_event() {
                // Release quota for completed deliveries
                self.message.release_quota();

                // Save changes to disk
                self.message.save_changes().await;

                WorkerResult::Retry(Schedule {
                    due,
                    inner: self.message,
                })
            } else {
                // Delete message from queue
                self.message.remove().await;

                WorkerResult::Done
            };
            if core.queue.tx.send(Event::Done(result)).await.is_err() {
                tracing::warn!(
                    parent: &span,
                    "Channel closed while trying to notify queue manager."
                );
            }
        });
    }
}

impl Message {
    /// Marks as failed all domains that reached their expiration time
    pub fn has_pending_delivery(&mut self) -> bool {
        let now = Instant::now();
        let mut has_pending_delivery = false;

        for domain in &mut self.domains {
            match &domain.status {
                Status::TemporaryFailure(_) if domain.expires <= now => {
                    domain.status =
                        match std::mem::replace(&mut domain.status, Status::Completed(())) {
                            Status::TemporaryFailure(err) => Status::PermanentFailure(err),
                            _ => unreachable!(),
                        };
                    domain.changed = true;
                }
                Status::Scheduled if domain.expires <= now => {
                    domain.status = Status::PermanentFailure(Error::Io(
                        "Queue rate limit exceeded.".to_string(),
                    ));
                    domain.changed = true;
                }
                Status::Completed(_) | Status::PermanentFailure(_) => (),
                _ => {
                    has_pending_delivery = true;
                }
            }
        }

        has_pending_delivery
    }
}

enum RemoteHost<'x> {
    Relay(&'x RelayHost),
    MX(&'x str),
}

impl<'x> RemoteHost<'x> {
    fn hostname(&self) -> &str {
        match self {
            RemoteHost::MX(host) => host,
            RemoteHost::Relay(host) => host.address.as_str(),
        }
    }

    fn fqdn_hostname(&self) -> Cow<'_, str> {
        match self {
            RemoteHost::MX(host) => {
                if !host.ends_with('.') {
                    format!("{}.", host).into()
                } else {
                    (*host).into()
                }
            }
            RemoteHost::Relay(host) => host.address.as_str().into(),
        }
    }

    fn port(&self) -> u16 {
        match self {
            RemoteHost::MX(_) => 25,
            RemoteHost::Relay(host) => host.port,
        }
    }

    fn credentials(&self) -> Option<&Credentials<String>> {
        match self {
            RemoteHost::MX(_) => None,
            RemoteHost::Relay(host) => host.auth.as_ref(),
        }
    }

    fn allow_invalid_certs(&self) -> bool {
        match self {
            RemoteHost::MX(_) => false,
            RemoteHost::Relay(host) => host.tls_allow_invalid_certs,
        }
    }

    fn implicit_tls(&self) -> bool {
        match self {
            RemoteHost::MX(_) => false,
            RemoteHost::Relay(host) => host.tls_implicit,
        }
    }

    fn is_smtp(&self) -> bool {
        match self {
            RemoteHost::MX(_) => true,
            RemoteHost::Relay(host) => host.protocol == ServerProtocol::Smtp,
        }
    }
}

impl Core {
    async fn resolve_host(
        &self,
        remote_host: &RemoteHost<'_>,
        envelope: &QueueEnvelope<'_>,
        max_multihomed: usize,
    ) -> Result<(Option<IpAddr>, Vec<IpAddr>), Status<(), Error>> {
        let mut remote_ips = Vec::new();
        let mut source_ip = None;

        for (pos, remote_ip) in self
            .resolvers
            .dns
            .ip_lookup(remote_host.fqdn_hostname().as_ref())
            .await?
            .take(max_multihomed)
            .enumerate()
        {
            if pos == 0 {
                if remote_ip.is_ipv4() {
                    let source_ips = self.queue.config.source_ip.ipv4.eval(envelope).await;
                    match source_ips.len().cmp(&1) {
                        std::cmp::Ordering::Equal => {
                            source_ip = IpAddr::from(*source_ips.first().unwrap()).into();
                        }
                        std::cmp::Ordering::Greater => {
                            source_ip = IpAddr::from(
                                source_ips[rand::thread_rng().gen_range(0..source_ips.len())],
                            )
                            .into();
                        }
                        std::cmp::Ordering::Less => (),
                    }
                } else {
                    let source_ips = self.queue.config.source_ip.ipv6.eval(envelope).await;
                    match source_ips.len().cmp(&1) {
                        std::cmp::Ordering::Equal => {
                            source_ip = IpAddr::from(*source_ips.first().unwrap()).into();
                        }
                        std::cmp::Ordering::Greater => {
                            source_ip = IpAddr::from(
                                source_ips[rand::thread_rng().gen_range(0..source_ips.len())],
                            )
                            .into();
                        }
                        std::cmp::Ordering::Less => (),
                    }
                }
            }
            remote_ips.push(remote_ip);
        }

        // Make sure there is at least one IP address
        if !remote_ips.is_empty() {
            Ok((source_ip, remote_ips))
        } else {
            Err(Status::TemporaryFailure(Error::DnsError(format!(
                "No IP addresses found for {:?}.",
                envelope.mx
            ))))
        }
    }
}

impl Domain {
    pub fn set_status(&mut self, status: impl Into<Status<(), Error>>, schedule: &[Duration]) {
        self.status = status.into();
        self.changed = true;
        if matches!(&self.status, Status::TemporaryFailure(_)) {
            self.retry(schedule);
        }
    }

    pub fn retry(&mut self, schedule: &[Duration]) {
        self.retry.due =
            Instant::now() + schedule[std::cmp::min(self.retry.inner as usize, schedule.len() - 1)];
        self.retry.inner += 1;
    }
}
