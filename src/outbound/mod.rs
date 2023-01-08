use smtp_proto::{Response, Severity};

use crate::queue::{DeliveryAttempt, Error, ErrorDetails, HostResponse, Message, Status};

pub mod dane;
pub mod delivery;
pub mod mta_sts;
pub mod session;

impl Status<(), Error> {
    pub fn from_smtp_error(hostname: &str, command: &str, err: mail_send::Error) -> Self {
        match err {
            mail_send::Error::Io(_)
            | mail_send::Error::Base64(_)
            | mail_send::Error::UnparseableReply
            | mail_send::Error::AuthenticationFailed(_)
            | mail_send::Error::MissingCredentials
            | mail_send::Error::MissingMailFrom
            | mail_send::Error::MissingRcptTo
            | mail_send::Error::Timeout => {
                Status::TemporaryFailure(Error::ConnectionError(ErrorDetails {
                    entity: hostname.to_string(),
                    details: err.to_string(),
                }))
            }

            mail_send::Error::UnexpectedReply(reply) => {
                let details = ErrorDetails {
                    entity: hostname.to_string(),
                    details: command.trim().to_string(),
                };
                if reply.severity() == Severity::PermanentNegativeCompletion {
                    Status::PermanentFailure(Error::UnexpectedResponse(HostResponse {
                        hostname: details,
                        response: reply,
                    }))
                } else {
                    Status::TemporaryFailure(Error::UnexpectedResponse(HostResponse {
                        hostname: details,
                        response: reply,
                    }))
                }
            }

            mail_send::Error::Auth(_)
            | mail_send::Error::UnsupportedAuthMechanism
            | mail_send::Error::InvalidTLSName
            | mail_send::Error::MissingStartTls => {
                Status::PermanentFailure(Error::ConnectionError(ErrorDetails {
                    entity: hostname.to_string(),
                    details: err.to_string(),
                }))
            }
        }
    }

    pub fn from_tls_error(hostname: &str, response: Option<Response<String>>) -> Self {
        let entity = hostname.to_string();
        if let Some(response) = response {
            let hostname = ErrorDetails {
                entity,
                details: "STARTTLS".to_string(),
            };

            if response.severity() == Severity::PermanentNegativeCompletion {
                Status::PermanentFailure(Error::UnexpectedResponse(HostResponse {
                    hostname,
                    response,
                }))
            } else {
                Status::TemporaryFailure(Error::UnexpectedResponse(HostResponse {
                    hostname,
                    response,
                }))
            }
        } else {
            Status::PermanentFailure(Error::TlsError(ErrorDetails {
                entity,
                details: "STARTTLS not advertised by host.".to_string(),
            }))
        }
    }

    pub fn timeout(hostname: &str, stage: &str) -> Self {
        Status::TemporaryFailure(Error::ConnectionError(ErrorDetails {
            entity: hostname.to_string(),
            details: format!("Timeout while {}", stage),
        }))
    }
}

impl From<mail_auth::Error> for Status<(), Error> {
    fn from(err: mail_auth::Error) -> Self {
        match &err {
            mail_auth::Error::DnsRecordNotFound(code) => {
                Status::PermanentFailure(Error::DnsError(format!("Domain not found: {:?}", code)))
            }
            _ => Status::TemporaryFailure(Error::DnsError(err.to_string())),
        }
    }
}

impl From<mta_sts::Error> for Status<(), Error> {
    fn from(err: mta_sts::Error) -> Self {
        match &err {
            mta_sts::Error::Dns(err) => match err {
                mail_auth::Error::DnsRecordNotFound(code) => Status::PermanentFailure(
                    Error::MtaStsError(format!("Record not found: {:?}", code)),
                ),
                mail_auth::Error::InvalidRecordType => Status::PermanentFailure(
                    Error::MtaStsError("Failed to parse MTA-STS DNS record.".to_string()),
                ),
                _ => Status::TemporaryFailure(Error::MtaStsError(format!(
                    "DNS lookup error: {}",
                    err
                ))),
            },
            mta_sts::Error::Http(err) => {
                if err.is_timeout() {
                    Status::TemporaryFailure(Error::MtaStsError(
                        "Timeout fetching policy.".to_string(),
                    ))
                } else if err.is_connect() {
                    Status::TemporaryFailure(Error::MtaStsError(
                        "Could not reach policy host.".to_string(),
                    ))
                } else if err.is_status()
                    & err
                        .status()
                        .map_or(false, |s| s == reqwest::StatusCode::NOT_FOUND)
                {
                    Status::PermanentFailure(Error::MtaStsError("Policy not found.".to_string()))
                } else {
                    Status::TemporaryFailure(Error::MtaStsError(
                        "Failed to fetch policy.".to_string(),
                    ))
                }
            }
            mta_sts::Error::InvalidPolicy(err) => Status::PermanentFailure(Error::MtaStsError(
                format!("Failed to parse policy: {}", err),
            )),
        }
    }
}

impl From<Box<Message>> for DeliveryAttempt {
    fn from(message: Box<Message>) -> Self {
        DeliveryAttempt {
            span: tracing::info_span!(
                "delivery",
                "queue-id" = message.id,
                "from" = message.return_path_lcase,
                "size" = message.size,
                "nrcpt" = message.recipients.len()
            ),
            in_flight: Vec::new(),
            message,
        }
    }
}
