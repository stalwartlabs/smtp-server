use mail_auth::{
    common::verify::VerifySignature, AuthenticatedMessage, AuthenticationResults, DkimOutput,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{config::Rate, core::Session};

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn send_dkim_report(
        &self,
        rcpt: &str,
        message: &AuthenticatedMessage<'_>,
        rate: &Rate,
        rejected: bool,
        output: &DkimOutput<'_>,
    ) {
        // Generate report
        let signature = if let Some(signature) = output.signature() {
            signature
        } else {
            return;
        };

        // Throttle recipient
        if !self.throttle_rcpt(rcpt, rate, "dkim") {
            tracing::debug!(
                parent: &self.span,
                context = "report",
                report = "dkim",
                event = "throttle",
                rcpt = rcpt,
            );
            return;
        }

        let config = &self.core.report.config.dkim;
        let from_addr = config.address.eval(self).await;
        let mut report = Vec::with_capacity(128);
        self.new_auth_failure(output.result().into(), rejected)
            .with_authentication_results(
                AuthenticationResults::new(&self.instance.hostname)
                    .with_dkim_result(output, message.from())
                    .to_string(),
            )
            .with_dkim_domain(signature.domain())
            .with_dkim_selector(signature.selector())
            .with_dkim_identity(signature.identity())
            .with_headers(message.raw_headers())
            .write_rfc5322(
                (config.name.eval(self).await.as_str(), from_addr.as_str()),
                rcpt,
                config.subject.eval(self).await,
                &mut report,
            )
            .ok();

        tracing::info!(
            parent: &self.span,
            context = "report",
            report = "dkim",
            event = "queue",
            rcpt = rcpt,
            "Queueing DKIM authentication failure report."
        );

        // Send report
        self.core
            .send_report(
                from_addr,
                [rcpt].into_iter(),
                report,
                &config.sign,
                &self.span,
            )
            .await;
    }
}
