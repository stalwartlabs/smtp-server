use std::time::Duration;

use mail_send::Credentials;
use rustls::ServerName;
use smtp_proto::{
    request::{parser::Rfc5321Parser, AUTH},
    response::generate::BitToString,
    IntoString, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrs},
};
use tokio_rustls::{client::TlsStream, TlsConnector};

pub struct ImapAuthClient<T: AsyncRead + AsyncWrite> {
    stream: T,
    timeout: Duration,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Timeout,
    InvalidResponse(String),
    InvalidChallenge(String),
    TLSInvalidName,
    Disconnected,
}

impl ImapAuthClient<TcpStream> {
    async fn start_tls(
        mut self,
        tls_connector: &TlsConnector,
        tls_hostname: &str,
    ) -> Result<ImapAuthClient<TlsStream<TcpStream>>, Error> {
        let line = tokio::time::timeout(self.timeout, async {
            self.stream.write_all(b"C7 STARTTLS\r\n").await?;
            self.read_line().await
        })
        .await
        .map_err(|_| Error::Timeout)??;

        if matches!(line.get(..5), Some(b"C7 OK")) {
            self.into_tls(tls_connector, tls_hostname).await
        } else {
            Err(Error::InvalidResponse(line.into_string()))
        }
    }

    async fn into_tls(
        self,
        tls_connector: &TlsConnector,
        tls_hostname: &str,
    ) -> Result<ImapAuthClient<TlsStream<TcpStream>>, Error> {
        tokio::time::timeout(self.timeout, async {
            Ok(ImapAuthClient {
                stream: tls_connector
                    .connect(
                        ServerName::try_from(tls_hostname).map_err(|_| Error::TLSInvalidName)?,
                        self.stream,
                    )
                    .await?,
                timeout: self.timeout,
            })
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}

impl ImapAuthClient<TlsStream<TcpStream>> {
    pub async fn connect(
        addr: impl ToSocketAddrs,
        timeout: Duration,
        tls_connector: &TlsConnector,
        tls_hostname: &str,
        tls_implicit: bool,
    ) -> Result<Self, Error> {
        let mut client: ImapAuthClient<TcpStream> = tokio::time::timeout(timeout, async {
            match TcpStream::connect(addr).await {
                Ok(stream) => Ok(ImapAuthClient { stream, timeout }),
                Err(err) => Err(Error::Io(err)),
            }
        })
        .await
        .map_err(|_| Error::Timeout)??;

        if tls_implicit {
            let mut client = client.into_tls(tls_connector, tls_hostname).await?;
            client.expect_greeting().await?;
            Ok(client)
        } else {
            client.expect_greeting().await?;
            client.start_tls(tls_connector, tls_hostname).await
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> ImapAuthClient<T> {
    pub async fn authenticate(
        &mut self,
        mechanism: u64,
        credentials: &Credentials<String>,
    ) -> Result<(), Error> {
        if (mechanism & (AUTH_PLAIN | AUTH_XOAUTH2 | AUTH_OAUTHBEARER)) != 0 {
            self.stream
                .write_all(
                    format!(
                        "C3 AUTHENTICATE {} {}\r\n",
                        mechanism.to_mechanism(),
                        credentials
                            .encode(mechanism, "")
                            .map_err(|err| Error::InvalidChallenge(err.to_string()))?
                    )
                    .as_bytes(),
                )
                .await?;
        } else {
            self.stream
                .write_all(format!("C3 AUTHENTICATE {}\r\n", mechanism.to_mechanism()).as_bytes())
                .await?;
        }
        let mut line = self.read_line().await?;

        for _ in 0..3 {
            if matches!(line.first(), Some(b'+')) {
                self.stream
                    .write_all(
                        format!(
                            "{}\r\n",
                            credentials
                                .encode(
                                    mechanism,
                                    std::str::from_utf8(line.get(2..).unwrap_or_default())
                                        .unwrap_or_default()
                                )
                                .map_err(|err| Error::InvalidChallenge(err.to_string()))?
                        )
                        .as_bytes(),
                    )
                    .await?;
                line = self.read_line().await?;
            } else if matches!(line.get(..5), Some(b"C3 OK")) {
                return Ok(());
            } else {
                return Err(Error::InvalidResponse(line.into_string()));
            }
        }

        Err(Error::InvalidResponse(line.into_string()))
    }

    pub async fn authentication_mechanisms(&mut self) -> Result<u64, Error> {
        tokio::time::timeout(self.timeout, async {
            self.stream.write_all(b"C0 CAPABILITY\r\n").await?;

            let line = self.read_line().await?;
            if !matches!(line.get(..12), Some(b"* CAPABILITY")) {
                return Err(Error::InvalidResponse(line.into_string()));
            }

            let mut line_iter = line.iter();
            let mut parser = Rfc5321Parser::new(&mut line_iter);
            let mut mechanisms = 0;

            'outer: while let Ok(ch) = parser.read_char() {
                if ch == b' ' {
                    loop {
                        if parser.hashed_value().unwrap_or(0) == AUTH && parser.stop_char == b'=' {
                            if let Ok(Some(mechanism)) = parser.mechanism() {
                                mechanisms |= mechanism;
                            }
                            match parser.stop_char {
                                b' ' => (),
                                b'\n' => break 'outer,
                                _ => break,
                            }
                        }
                    }
                } else if ch == b'\n' {
                    break;
                }
            }

            Ok(mechanisms)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn noop(&mut self) -> Result<(), Error> {
        tokio::time::timeout(self.timeout, async {
            self.stream.write_all(b"C8 NOOP\r\n").await?;
            self.read_line().await?;
            Ok(())
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn logout(&mut self) -> Result<(), Error> {
        tokio::time::timeout(self.timeout, async {
            self.stream.write_all(b"C9 LOGOUT\r\n").await?;
            Ok(())
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn expect_greeting(&mut self) -> Result<(), Error> {
        tokio::time::timeout(self.timeout, async {
            let line = self.read_line().await?;
            return if matches!(line.get(..4), Some(b"* OK")) {
                Ok(())
            } else {
                Err(Error::InvalidResponse(line.into_string()))
            };
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub async fn read_line(&mut self) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; 1024];
        let mut buf_extended = Vec::with_capacity(0);

        loop {
            let br = self.stream.read(&mut buf).await?;

            if br > 0 {
                if matches!(buf.get(br - 1), Some(b'\n')) {
                    //println!("{:?}", std::str::from_utf8(&buf[..br]).unwrap());
                    return Ok(if buf_extended.is_empty() {
                        buf.truncate(br);
                        buf
                    } else {
                        buf_extended.extend_from_slice(&buf[..br]);
                        buf_extended
                    });
                } else if buf_extended.is_empty() {
                    buf_extended = buf[..br].to_vec();
                } else {
                    buf_extended.extend_from_slice(&buf[..br]);
                }
            } else {
                return Err(Error::Disconnected);
            }
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

#[cfg(test)]
mod test {
    use crate::remote::imap::ImapAuthClient;
    use mail_send::smtp::tls::build_tls_connector;
    use smtp_proto::{AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH, AUTH_XOAUTH2};
    use std::time::Duration;

    #[ignore]
    #[tokio::test]
    async fn imap_auth() {
        let connector = build_tls_connector(false);

        let mut client = ImapAuthClient::connect(
            "imap.gmail.com:993",
            Duration::from_secs(5),
            &connector,
            "imap.gmail.com",
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            AUTH_PLAIN | AUTH_XOAUTH | AUTH_XOAUTH2 | AUTH_OAUTHBEARER,
            client.authentication_mechanisms().await.unwrap()
        );
        client.logout().await.unwrap();
    }
}
