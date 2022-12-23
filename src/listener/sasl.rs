use mail_parser::decoders::base64::base64_decode;
use mail_send::Credentials;
use smtp_proto::{IntoString, AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::Session;

pub struct SaslToken {
    mechanism: u64,
    credentials: Credentials<String>,
}

impl SaslToken {
    pub fn from_mechanism(mechanism: u64) -> Option<SaslToken> {
        match mechanism {
            AUTH_PLAIN | AUTH_LOGIN => SaslToken {
                mechanism,
                credentials: Credentials::Plain {
                    username: String::new(),
                    secret: String::new(),
                },
            }
            .into(),
            AUTH_OAUTHBEARER => SaslToken {
                mechanism,
                credentials: Credentials::OAuthBearer {
                    token: String::new(),
                },
            }
            .into(),
            AUTH_XOAUTH2 => SaslToken {
                mechanism,
                credentials: Credentials::XOauth2 {
                    username: String::new(),
                    secret: String::new(),
                },
            }
            .into(),
            _ => None,
        }
    }
}

impl<T: AsyncWrite + AsyncRead + Unpin> Session<T> {
    pub async fn handle_sasl_response(
        &mut self,
        token: &mut SaslToken,
        response: &[u8],
    ) -> Result<bool, ()> {
        if response.is_empty() {
            match (token.mechanism, &token.credentials) {
                (AUTH_PLAIN | AUTH_XOAUTH2 | AUTH_OAUTHBEARER, _) => {
                    self.write(b"334 Go ahead.\r\n").await?;
                    return Ok(true);
                }
                (AUTH_LOGIN, Credentials::Plain { username, secret }) => {
                    if username.is_empty() && secret.is_empty() {
                        self.write(b"334 VXNlciBOYW1lAA==\r\n").await?;
                        return Ok(true);
                    }
                }
                _ => (),
            }
        } else if let Some(response) = base64_decode(response) {
            match (token.mechanism, &mut token.credentials) {
                (AUTH_PLAIN, Credentials::Plain { username, secret }) => {
                    let mut b_username = Vec::new();
                    let mut b_secret = Vec::new();
                    let mut arg_num = 0;
                    for ch in response {
                        if ch != 0 {
                            if arg_num == 1 {
                                b_username.push(ch);
                            } else if arg_num == 2 {
                                b_secret.push(ch);
                            }
                        } else {
                            arg_num += 1;
                        }
                    }
                    match (String::from_utf8(b_username), String::from_utf8(b_secret)) {
                        (Ok(s_username), Ok(s_secret)) if !s_username.is_empty() => {
                            *username = s_username;
                            *secret = s_secret;
                            self.authenticate(std::mem::take(&mut token.credentials))
                                .await?;
                            return Ok(false);
                        }
                        _ => (),
                    }
                }
                (AUTH_LOGIN, Credentials::Plain { username, secret }) => {
                    return if username.is_empty() {
                        *username = response.into_string();
                        self.write(b"334 UGFzc3dvcmQA\r\n").await?;
                        Ok(true)
                    } else {
                        *secret = response.into_string();
                        self.authenticate(std::mem::take(&mut token.credentials))
                            .await?;
                        Ok(false)
                    };
                }
                (AUTH_OAUTHBEARER, Credentials::OAuthBearer { token: token_ }) => {
                    let response = response.into_string();
                    if response.contains("auth=") {
                        *token_ = response;
                        self.authenticate(std::mem::take(&mut token.credentials))
                            .await?;
                        return Ok(false);
                    }
                }
                (AUTH_XOAUTH2, Credentials::XOauth2 { username, secret }) => {
                    let mut b_username = Vec::new();
                    let mut b_secret = Vec::new();
                    let mut arg_num = 0;
                    let mut in_arg = false;

                    for ch in response {
                        if in_arg {
                            if ch != 1 {
                                if arg_num == 1 {
                                    b_username.push(ch);
                                } else if arg_num == 2 {
                                    b_secret.push(ch);
                                }
                            } else {
                                in_arg = false;
                            }
                        } else if ch == b'=' {
                            arg_num += 1;
                            in_arg = true;
                        }
                    }
                    match (String::from_utf8(b_username), String::from_utf8(b_secret)) {
                        (Ok(s_username), Ok(s_secret)) if !s_username.is_empty() => {
                            *username = s_username;
                            *secret = s_secret;
                            self.authenticate(std::mem::take(&mut token.credentials))
                                .await?;
                            return Ok(false);
                        }
                        _ => (),
                    }
                }

                _ => (),
            }
        }
        tokio::time::sleep(self.params.auth_errors_wait).await;
        self.write(b"500 5.5.6 Invalid challenge.\r\n").await?;
        if self.data.auth_errors < self.params.auth_errors_max {
            self.data.auth_errors += 1;
            Ok(false)
        } else {
            Err(())
        }
    }

    pub async fn authenticate(&mut self, credentials: Credentials<String>) -> Result<(), ()> {
        Ok(())
    }
}
