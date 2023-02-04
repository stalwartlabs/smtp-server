use tokio::io::{AsyncRead, AsyncWrite};

use super::Session;

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn eval_session_params(&mut self) {
        let c = &self.core.session.config;
        self.data.bytes_left = *c.transfer_limit.eval(self).await;
        self.data.valid_until += *c.duration.eval(self).await;

        self.params.timeout = *c.timeout.eval(self).await;
        self.params.spf_ehlo = *self.core.mail_auth.spf.verify_ehlo.eval(self).await;
        self.params.spf_mail_from = *self.core.mail_auth.spf.verify_mail_from.eval(self).await;
        self.params.iprev = *self.core.mail_auth.iprev.verify.eval(self).await;
        self.params.dnsbl_policy = *self.core.mail_auth.dnsbl.verify.eval(self).await;

        // Ehlo parameters
        let ec = &self.core.session.config.ehlo;
        self.params.ehlo_require = *ec.require.eval(self).await;
        self.params.ehlo_reject_non_fqdn = *ec.reject_non_fqdn.eval(self).await;

        // Auth parameters
        let ac = &self.core.session.config.auth;
        self.params.auth_lookup = ac.lookup.eval(self).await.clone();
        self.params.auth_require = *ac.require.eval(self).await;
        self.params.auth_errors_max = *ac.errors_max.eval(self).await;
        self.params.auth_errors_wait = *ac.errors_wait.eval(self).await;

        // VRFY/EXPN parameters
        let rc = &self.core.session.config.rcpt;
        self.params.rcpt_lookup_expn = rc.lookup_expn.eval(self).await.clone();
        self.params.rcpt_lookup_vrfy = rc.lookup_vrfy.eval(self).await.clone();
    }

    pub async fn eval_post_auth_params(&mut self) {
        // Refresh VRFY/EXPN parameters
        let rc = &self.core.session.config.rcpt;
        self.params.rcpt_lookup_expn = rc.lookup_expn.eval(self).await.clone();
        self.params.rcpt_lookup_vrfy = rc.lookup_vrfy.eval(self).await.clone();
    }

    pub async fn eval_rcpt_params(&mut self) {
        let rc = &self.core.session.config.rcpt;
        self.params.rcpt_script = rc.script.eval(self).await.clone();
        self.params.rcpt_relay = *rc.relay.eval(self).await;
        self.params.rcpt_errors_max = *rc.errors_max.eval(self).await;
        self.params.rcpt_errors_wait = *rc.errors_wait.eval(self).await;
        self.params.rcpt_max = *rc.max_recipients.eval(self).await;
        self.params.rcpt_lookup_domain = rc.lookup_domains.eval(self).await.clone();
        self.params.rcpt_lookup_addresses = rc.lookup_addresses.eval(self).await.clone();
        self.params.rcpt_dsn = *self.core.session.config.extensions.dsn.eval(self).await;

        self.params.max_message_size = *self
            .core
            .session
            .config
            .data
            .max_message_size
            .eval(self)
            .await;
    }
}
