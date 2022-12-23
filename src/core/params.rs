use tokio::io::{AsyncRead, AsyncWrite};

use super::{Session, SessionParameters};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub async fn eval_ehlo_params(&mut self) {
        self.data.valid_until += *self.core.config.duration.eval(self).await;

        // Ehlo parameter
        self.params.ehlo_script = self.core.config.ehlo.script.eval(self).await.clone();
        self.params.ehlo_require = *self.core.config.ehlo.require.eval(self).await;
        self.params.ehlo_multiple = *self.core.config.ehlo.multiple.eval(self).await;

        // Capabilities
        self.params.pipelining = *self.core.config.ehlo.pipelining.eval(self).await;
        self.params.chunking = *self.core.config.ehlo.chunking.eval(self).await;
        self.params.requiretls = *self.core.config.ehlo.requiretls.eval(self).await;
        self.params.no_soliciting = self.core.config.ehlo.no_soliciting.eval(self).await.clone();
        self.params.future_release = *self.core.config.ehlo.future_release.eval(self).await;
        self.params.deliver_by = *self.core.config.ehlo.deliver_by.eval(self).await;
        self.params.mt_priority = *self.core.config.ehlo.mt_priority.eval(self).await;
        self.params.size = *self.core.config.ehlo.size.eval(self).await;
    }

    pub async fn eval_auth_params(&mut self) {
        // Auth parameters
        self.params.auth_script = self.core.config.auth.script.eval(self).await.clone();
        self.params.auth_require = *self.core.config.auth.require.eval(self).await;
        self.params.auth_lookup = self.core.config.auth.lookup.eval(self).await.clone();
        self.params.auth_mechanisms = *self.core.config.auth.mechanisms.eval(self).await;
        self.params.auth_errors_max = *self.core.config.auth.errors_max.eval(self).await;
        self.params.auth_errors_wait = *self.core.config.auth.errors_wait.eval(self).await;
    }

    pub async fn eval_mail_params(&mut self) {
        self.params.mail_script = self.core.config.mail.script.eval(self).await.clone();
    }

    pub async fn eval_rcpt_params(&mut self) {
        self.params.rcpt_script = self.core.config.rcpt.script.eval(self).await.clone();
        self.params.rcpt_relay = *self.core.config.rcpt.relay.eval(self).await;
        self.params.rcpt_errors_max = *self.core.config.rcpt.errors_max.eval(self).await;
        self.params.rcpt_errors_wait = *self.core.config.rcpt.errors_wait.eval(self).await;
        self.params.rcpt_max = *self.core.config.rcpt.max_recipients.eval(self).await;
    }

    pub async fn eval_data_params(&mut self) {
        self.params.data_script = self.core.config.data.script.eval(self).await.clone();
        self.params.data_max_messages = *self.core.config.data.max_messages.eval(self).await;
        self.params.data_max_message_size =
            *self.core.config.data.max_message_size.eval(self).await;
        self.params.data_max_received_headers =
            *self.core.config.data.max_received_headers.eval(self).await;
        self.params.data_max_mime_parts = *self.core.config.data.max_mime_parts.eval(self).await;
        self.params.data_max_nested_messages =
            *self.core.config.data.max_nested_messages.eval(self).await;
        self.params.data_add_received = *self.core.config.data.add_received.eval(self).await;
        self.params.data_add_received_spf =
            *self.core.config.data.add_received_spf.eval(self).await;
        self.params.data_add_return_path = *self.core.config.data.add_return_path.eval(self).await;
        self.params.data_add_auth_results =
            *self.core.config.data.add_auth_results.eval(self).await;
        self.params.data_add_message_id = *self.core.config.data.add_message_id.eval(self).await;
        self.params.data_add_date = *self.core.config.data.add_date.eval(self).await;
    }
}

impl SessionParameters {
    pub fn can_starttls(mut self, can_tls: bool) -> Self {
        self.starttls = can_tls;
        self
    }
}
