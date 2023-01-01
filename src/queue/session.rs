use std::net::{IpAddr, SocketAddr};

use mail_send::{smtp::AssertReply, SmtpClient};
use smtp_proto::Response;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::{
    config::TlsStrategy,
    core::{Core, QueueCore},
};

use super::{Message, Recipient, Status};

impl Message {
    pub async fn deliver<T: AsyncRead + AsyncWrite + Unpin>(
        &self,
        smtp_client: SmtpClient<T>,
        recipients: impl Iterator<Item = &mut Recipient>,
        queue: &QueueCore,
    ) -> Status {
        todo!()
    }
}

pub async fn into_tls(
    smtp_client: SmtpClient<TcpStream>,
    tls_connector: &TlsConnector,
    hostname: &str,
) -> Result<SmtpClient<TlsStream<TcpStream>>, Status> {
    smtp_client
        .into_tls(tls_connector, hostname)
        .await
        .map_err(|err| Status::from(("TLS handshake failed with", hostname, err)))
}

pub enum StartTlsResult {
    Success {
        smtp_client: SmtpClient<TlsStream<TcpStream>>,
    },
    Unavailable {
        response: Response<String>,
        smtp_client: SmtpClient<TcpStream>,
    },
}

pub async fn try_start_tls(
    mut smtp_client: SmtpClient<TcpStream>,
    tls_connector: &TlsConnector,
    hostname: &str,
) -> Result<StartTlsResult, Status> {
    let response = smtp_client
        .cmd("STARTTLS\r\n")
        .await
        .map_err(|err| Status::from(("Failed to write to", hostname, err)))?;
    if response.code() == 220 {
        into_tls(smtp_client, tls_connector, hostname)
            .await
            .map(|smtp_client| StartTlsResult::Success { smtp_client })
    } else {
        Ok(StartTlsResult::Unavailable {
            response,
            smtp_client,
        })
    }
}

pub async fn read_greeting<T: AsyncRead + AsyncWrite + Unpin>(
    smtp_client: &mut SmtpClient<T>,
    hostname: &str,
) -> Result<(), Status> {
    tokio::time::timeout(smtp_client.timeout, smtp_client.read())
        .await
        .map_err(|_| {
            Status::from((
                "Timeout reading greeting from",
                hostname,
                mail_send::Error::Timeout,
            ))
        })?
        .and_then(|r| r.assert_code(220))
        .map_err(|err| Status::from(("Invalid SMTP greeting from", hostname, err)))
}

impl TlsStrategy {
    pub fn is_dane(&self) -> bool {
        matches!(
            self,
            TlsStrategy::Dane | TlsStrategy::DaneOrOptional | TlsStrategy::DaneOrTls
        )
    }

    pub fn is_dane_required(&self) -> bool {
        matches!(self, TlsStrategy::Dane)
    }

    pub fn is_tls_required(&self) -> bool {
        matches!(self, TlsStrategy::Dane | TlsStrategy::DaneOrTls)
    }
}
