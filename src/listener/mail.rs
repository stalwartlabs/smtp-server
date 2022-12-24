use smtp_proto::Parameter;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Session, SessionAddress};

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn handle_mail_from(
        &mut self,
        from: String,
        parameters: Vec<Parameter<String>>,
    ) -> Result<(), ()> {
        if self.data.helo_domain.is_empty() && self.params.ehlo_require {
            return self
                .write(b"503 5.5.1 Polite people say EHLO first.\r\n")
                .await;
        } else if self.data.mail_from.is_some() {
            return self
                .write(b"503 5.5.1 Multiple MAIL commands not allowed.\r\n")
                .await;
        } else if self.params.auth_require && self.data.authenticated_as.is_empty() {
            return self.write(b"530 5.7.0 Authentication required.\r\n").await;
        }

        self.data.mail_from = if !from.is_empty() {
            let address_lcase = from.to_lowercase();
            SessionAddress {
                address: from,
                domain: address_lcase
                    .rsplit_once('@')
                    .map(|(_, d)| d)
                    .unwrap_or_default()
                    .to_string(),
                address_lcase,
            }
        } else {
            SessionAddress {
                address: String::new(),
                address_lcase: String::new(),
                domain: String::new(),
            }
        }
        .into();

        if self
            .is_allowed(&self.core.clone().config.mail.throttle)
            .await
        {
            self.eval_rcpt_params().await;
            self.write(b"250 2.1.0 OK\r\n").await
        } else {
            self.data.mail_from = None;
            self.write(b"451 4.4.5 Rate limit exceeded, try again later.\r\n")
                .await
        }
    }
}
