use mail_auth::{report::AuthFailureType, AuthenticationResults, SpfOutput};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{config::Rate, core::Session};

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn send_spf_report(
        &self,
        rcpt: &str,
        rate: &Rate,
        rejected: bool,
        output: &SpfOutput,
    ) {
        // Throttle recipient
        if !self.throttle_rcpt(rcpt, rate, "spf") {
            return;
        }

        // Generate report
        let config = &self.core.report.config.spf;
        let from_addr = config.address.eval(self).await;
        let mut report = Vec::with_capacity(128);
        self.new_auth_failure(AuthFailureType::Spf, rejected)
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
                (config.name.eval(self).await.as_str(), from_addr.as_str()),
                rcpt,
                config.subject.eval(self).await,
                &mut report,
            )
            .ok();

        // Send report
        self.core
            .send_report(from_addr, [rcpt].into_iter(), report, &config.sign)
            .await;
    }
}
