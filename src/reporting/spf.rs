use std::time::SystemTime;

use mail_auth::{
    report::{AuthFailureType, DeliveryResult, Feedback, FeedbackType},
    AuthenticationResults, SpfOutput,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{config::Rate, core::Session, USER_AGENT};

use super::sign_local_message;

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn send_spf_report(
        &self,
        rcpt: &str,
        rate: &Rate,
        rejected: bool,
        output: &SpfOutput,
    ) {
        if !self.throttle_rcpt(rcpt, rate, "spf") {
            return;
        }
        let config = &self.core.report.spf;
        let from_addr = config.address.eval(self).await;
        let mut feedback = Vec::with_capacity(128);
        Feedback::new(FeedbackType::AuthFailure)
            .with_auth_failure(AuthFailureType::Spf)
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
            .with_authentication_results(
                if let Some(mail_from) = &self.data.mail_from {
                    AuthenticationResults::new(&self.instance.hostname).with_spf_mailfrom_result(
                        output,
                        self.data.remote_ip,
                        &mail_from.address,
                        &self.data.helo_domain,
                    )
                } else {
                    AuthenticationResults::new(&self.instance.hostname).with_spf_ehlo_result(
                        output,
                        self.data.remote_ip,
                        &self.data.helo_domain,
                    )
                }
                .to_string(),
            )
            .with_spf_dns(format!("txt : {} : v=SPF1", output.domain())) // TODO use DNS record
            .write_rfc5322(
                config.name.eval(self).await,
                from_addr,
                rcpt,
                config.subject.eval(self).await,
                &mut feedback,
            )
            .ok();

        let from_addr_lcase = from_addr.to_lowercase();
        let from_addr_domain = from_addr_lcase
            .rsplit_once('@')
            .map(|(_, d)| d.to_string())
            .unwrap_or_default();
        let rcpt_lcase = rcpt.to_lowercase();
        let rcpt_domain = rcpt_lcase
            .rsplit_once('@')
            .map(|(_, d)| d.to_string())
            .unwrap_or_default();
        let mut message = self
            .core
            .queue
            .new_message(
                from_addr,
                from_addr_lcase,
                from_addr_domain,
                rcpt_domain,
                rcpt,
                rcpt_lcase,
            )
            .await;

        // Sign message
        let message_bytes = message.sign(&config.sign, feedback).await;

        // Queue message
        self.core.queue.queue_message(message, message_bytes).await;
    }
}
