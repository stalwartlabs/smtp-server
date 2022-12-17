use tokio::io::{AsyncRead, AsyncWrite};

use super::{Session, SessionParameters};

impl<T: AsyncRead + AsyncWrite> Session<T> {
    pub fn eval_connect_params(&mut self) {
        self.data.valid_until += *self.core.stage.connect.max_duration.eval(self);

        // Ehlo parameter
        self.params.ehlo_script = self.core.stage.ehlo.script.eval(self).clone();
        self.params.ehlo_require = *self.core.stage.ehlo.require.eval(self);
        self.params.ehlo_multiple = *self.core.stage.ehlo.multiple.eval(self);

        // Capabilities
        self.params.pipelining = *self.core.stage.ehlo.pipelining.eval(self);
        self.params.chunking = *self.core.stage.ehlo.chunking.eval(self);
        self.params.requiretls = *self.core.stage.ehlo.requiretls.eval(self);
        self.params.no_soliciting = self.core.stage.ehlo.no_soliciting.eval(self).clone();
        self.params.future_release = *self.core.stage.ehlo.future_release.eval(self);
        self.params.deliver_by = *self.core.stage.ehlo.deliver_by.eval(self);
        self.params.mt_priority = *self.core.stage.ehlo.mt_priority.eval(self);
        self.params.size = *self.core.stage.ehlo.size.eval(self);
        self.params.expn = *self.core.stage.ehlo.expn.eval(self);

        // Auth parameters
        self.params.auth_script = self.core.stage.auth.script.eval(self).clone();
        self.params.auth_require = *self.core.stage.auth.require.eval(self);
        self.params.auth_host = self.core.stage.auth.auth_host.eval(self).clone();
        self.params.auth_mechanisms = *self.core.stage.auth.mechanisms.eval(self);
        self.params.auth_errors_max = *self.core.stage.auth.errors_max.eval(self);
        self.params.auth_errors_wait = *self.core.stage.auth.errors_wait.eval(self);
    }
}

impl SessionParameters {
    pub fn can_starttls(mut self, can_tls: bool) -> Self {
        self.starttls = can_tls;
        self
    }
}
