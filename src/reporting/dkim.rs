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
        // Throttle recipient
        if !self.throttle_rcpt(rcpt, rate, "dkim") {
            return;
        }

        // Generate report
        let signature = if let Some(signature) = output.signature() {
            signature
        } else {
            return;
        };
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
                config.name.eval(self).await,
                from_addr,
                rcpt,
                config.subject.eval(self).await,
                &mut report,
            )
            .ok();

        // Send report
        self.send_report(from_addr, [rcpt].into_iter(), report, &config.sign)
            .await;
    }
}
