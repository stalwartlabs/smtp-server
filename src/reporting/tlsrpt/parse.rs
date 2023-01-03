use mail_auth::common::parse::{TagParser, TxtRecordParser};

use super::{ReportUri, TlsRpt};

const V: u64 = b'v' as u64;
const RUA: u64 = (b'r' as u64) | (b'u' as u64) << 8 | (b'a' as u64) << 16;

const MAILTO: u64 = (b'm' as u64)
    | (b'a' as u64) << 8
    | (b'i' as u64) << 16
    | (b'l' as u64) << 24
    | (b't' as u64) << 32
    | (b'o' as u64) << 40;
const HTTPS: u64 = (b'h' as u64)
    | (b't' as u64) << 8
    | (b't' as u64) << 16
    | (b'p' as u64) << 24
    | (b's' as u64) << 32;

impl TxtRecordParser for TlsRpt {
    #[allow(clippy::while_let_on_iterator)]
    fn parse(record: &[u8]) -> mail_auth::Result<Self> {
        let mut record = record.iter();

        if record.key().unwrap_or(0) != V
            || !record.match_bytes(b"TLSRPTv1")
            || !record.seek_tag_end()
        {
            return Err(mail_auth::Error::InvalidRecordType);
        }

        let mut rua = Vec::new();

        while let Some(key) = record.key() {
            match key {
                RUA => loop {
                    match record.flag_value() {
                        (MAILTO, b':') => {
                            let mail_to = record.text_qp(Vec::with_capacity(20), false, true);
                            if !mail_to.is_empty() {
                                rua.push(ReportUri::Mail(mail_to));
                            }
                        }
                        (HTTPS, b':') => {
                            let mut url = Vec::with_capacity(20);
                            url.extend_from_slice(b"https:");
                            let url = record.text_qp(url, false, true);
                            if !url.is_empty() {
                                rua.push(ReportUri::Http(url));
                            }
                        }
                        _ => {
                            record.ignore();
                            break;
                        }
                    }
                },
                _ => {
                    record.ignore();
                }
            }
        }

        if !rua.is_empty() {
            Ok(TlsRpt { rua })
        } else {
            Err(mail_auth::Error::InvalidRecordType)
        }
    }
}

#[cfg(test)]
mod tests {
    use mail_auth::common::parse::TxtRecordParser;

    use crate::reporting::tlsrpt::{ReportUri, TlsRpt};

    #[test]
    fn parse_tls_rpt() {
        for (tls_rpt, expected_tls_rpt) in [
            (
                "v=TLSRPTv1;rua=mailto:reports@example.com",
                TlsRpt {
                    rua: vec![ReportUri::Mail("reports@example.com".to_string())],
                },
            ),
            (
                "v=TLSRPTv1; rua=https://reporting.example.com/v1/tlsrpt",
                TlsRpt {
                    rua: vec![ReportUri::Http(
                        "https://reporting.example.com/v1/tlsrpt".to_string(),
                    )],
                },
            ),
            (
                "v=TLSRPTv1; rua=mailto:tlsrpt@mydomain.com,https://tlsrpt.mydomain.com/v1",
                TlsRpt {
                    rua: vec![
                        ReportUri::Mail("tlsrpt@mydomain.com".to_string()),
                        ReportUri::Http("https://tlsrpt.mydomain.com/v1".to_string()),
                    ],
                },
            ),
        ] {
            assert_eq!(TlsRpt::parse(tls_rpt.as_bytes()).unwrap(), expected_tls_rpt);
        }
    }
}
