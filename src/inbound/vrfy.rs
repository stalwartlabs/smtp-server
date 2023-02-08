use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    core::Session,
    lookup::{Item, LookupResult},
};
use std::fmt::Write;

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn handle_vrfy(&mut self, address: String) -> Result<(), ()> {
        if let Some(address_lookup) = &self.params.rcpt_lookup_vrfy {
            if let Some(result) = address_lookup
                .lookup(Item::Verify(address.to_lowercase()))
                .await
            {
                if let LookupResult::Values(values) = result {
                    let mut result = String::with_capacity(32);
                    for (pos, value) in values.iter().enumerate() {
                        let _ = write!(
                            result,
                            "250{}{}\r\n",
                            if pos == values.len() - 1 { " " } else { "-" },
                            value
                        );
                    }

                    tracing::debug!(parent: &self.span,
                        event = "success",
                        context = "vrfy",
                        address = &address);

                    self.write(result.as_bytes()).await
                } else {
                    tracing::debug!(parent: &self.span,
                        event = "not-found",
                        context = "vrfy",
                        address = &address);

                    self.write(b"550 5.1.2 Address not found.\r\n").await
                }
            } else {
                tracing::debug!(parent: &self.span,
                    event = "temp-fail",
                    context = "vrfy",
                    address = &address);

                self.write(b"252 2.4.3 Unable to verify address at this time.\r\n")
                    .await
            }
        } else {
            tracing::debug!(parent: &self.span,
                event = "forbidden",
                context = "vrfy",
                address = &address);

            self.write(b"252 2.5.1 VRFY is disabled.\r\n").await
        }
    }

    pub async fn handle_expn(&mut self, address: String) -> Result<(), ()> {
        if let Some(address_lookup) = &self.params.rcpt_lookup_expn {
            if let Some(result) = address_lookup
                .lookup(Item::Expand(address.to_lowercase()))
                .await
            {
                if let LookupResult::Values(values) = result {
                    let mut result = String::with_capacity(32);
                    for (pos, value) in values.iter().enumerate() {
                        let _ = write!(
                            result,
                            "250{}{}\r\n",
                            if pos == values.len() - 1 { " " } else { "-" },
                            value
                        );
                    }
                    tracing::debug!(parent: &self.span,
                        event = "success",
                        context = "expn",
                        address = &address);
                    self.write(result.as_bytes()).await
                } else {
                    tracing::debug!(parent: &self.span,
                        event = "not-found",
                        context = "expn",
                        address = &address);

                    self.write(b"550 5.1.2 Mailing list not found.\r\n").await
                }
            } else {
                tracing::debug!(parent: &self.span,
                    event = "temp-fail",
                    context = "expn",
                    address = &address);

                self.write(b"252 2.4.3 Unable to expand mailing list at this time.\r\n")
                    .await
            }
        } else {
            tracing::debug!(parent: &self.span,
                event = "forbidden",
                context = "expn",
                address = &address);

            self.write(b"252 2.5.1 EXPN is disabled.\r\n").await
        }
    }
}
