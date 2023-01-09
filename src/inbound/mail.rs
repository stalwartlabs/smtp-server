use mail_auth::{IprevOutput, IprevResult, SpfResult};
use smtp_proto::MailFrom;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::{Session, SessionAddress};

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn handle_mail_from(&mut self, from: MailFrom<String>) -> Result<(), ()> {
        if self.data.helo_domain.is_empty()
            && (self.params.ehlo_require
                || self.params.spf_ehlo.verify()
                || self.params.spf_mail_from.verify())
        {
            return self
                .write(b"503 5.5.1 Polite people say EHLO first.\r\n")
                .await;
        } else if self.data.mail_from.is_some() {
            return self
                .write(b"503 5.5.1 Multiple MAIL commands not allowed.\r\n")
                .await;
        } else if self.data.iprev.is_none() && self.params.iprev.verify() {
            self.data.iprev = self
                .core
                .resolvers
                .dns
                .verify_iprev(self.data.remote_ip)
                .await
                .into();
        }

        // In strict mode reject messages from hosts that fail the reverse DNS lookup check
        if self.params.iprev.is_strict()
            && !matches!(
                &self.data.iprev,
                Some(IprevOutput {
                    result: IprevResult::Pass,
                    ..
                })
            )
        {
            let message = if matches!(
                &self.data.iprev,
                Some(IprevOutput {
                    result: IprevResult::TempError(_),
                    ..
                })
            ) {
                &b"451 4.7.25 Temporary error validating reverse DNS.\r\n"[..]
            } else {
                &b"550 5.7.25 Reverse DNS validation failed.\r\n"[..]
            };

            return self.write(message).await;
        }

        let (address, address_lcase, domain) = if !from.address.is_empty() {
            let address_lcase = from.address.to_lowercase();
            let domain = address_lcase
                .rsplit_once('@')
                .map(|(_, d)| d)
                .unwrap_or_default()
                .to_string();
            (from.address, address_lcase, domain)
        } else {
            (String::new(), String::new(), String::new())
        };

        self.data.mail_from = SessionAddress {
            address,
            address_lcase,
            domain,
            flags: from.flags,
            dsn_info: from.env_id,
        }
        .into();

        if self.is_allowed().await {
            // Verify SPF
            if self.params.spf_mail_from.verify() {
                let mail_from = self.data.mail_from.as_ref().unwrap();
                let spf_result = if !mail_from.address.is_empty() {
                    self.core
                        .resolvers
                        .dns
                        .check_host(
                            self.data.remote_ip,
                            &mail_from.domain,
                            &self.data.helo_domain,
                            &self.instance.hostname,
                            &mail_from.address_lcase,
                        )
                        .await
                } else {
                    self.core
                        .resolvers
                        .dns
                        .check_host(
                            self.data.remote_ip,
                            &self.data.helo_domain,
                            &self.data.helo_domain,
                            &self.instance.hostname,
                            &format!("postmaster@{}", self.data.helo_domain),
                        )
                        .await
                };

                // Reject EHLO when SPF fails in strict mode
                match spf_result.result() {
                    SpfResult::Pass => (),
                    SpfResult::TempError if self.params.spf_mail_from.is_strict() => {
                        self.data.mail_from = None;
                        return self
                            .write(b"451 4.7.24 Temporary SPF validation error.\r\n")
                            .await;
                    }
                    result => {
                        if self.params.spf_ehlo.is_strict() {
                            self.data.mail_from = None;
                            return self
                                .write(
                                    format!(
                                        "550 5.7.23 SPF validation failed, status: {}.\r\n",
                                        result
                                    )
                                    .as_bytes(),
                                )
                                .await;
                        }
                    }
                }

                self.data.spf_mail_from = spf_result.into();
            }

            self.eval_rcpt_params().await;
            self.write(b"250 2.1.0 OK\r\n").await
        } else {
            self.data.mail_from = None;
            self.write(b"451 4.4.5 Rate limit exceeded, try again later.\r\n")
                .await
        }
    }
}
