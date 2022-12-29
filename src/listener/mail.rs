use smtp_proto::MailFrom;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Session, SessionAddress};

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn handle_mail_from(&mut self, from: MailFrom<String>) -> Result<(), ()> {
        if self.data.helo_domain.is_empty() && self.params.ehlo_require {
            return self
                .write(b"503 5.5.1 Polite people say EHLO first.\r\n")
                .await;
        } else if self.data.mail_from.is_some() {
            return self
                .write(b"503 5.5.1 Multiple MAIL commands not allowed.\r\n")
                .await;
        }

        self.data.mail_from = if !from.address.is_empty() {
            let address_lcase = from.address.to_lowercase();
            SessionAddress {
                address: from.address,
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

        if self.is_allowed().await {
            self.eval_rcpt_params().await;
            self.write(b"250 2.1.0 OK\r\n").await
        } else {
            self.data.mail_from = None;
            self.write(b"451 4.4.5 Rate limit exceeded, try again later.\r\n")
                .await
        }
    }
}
