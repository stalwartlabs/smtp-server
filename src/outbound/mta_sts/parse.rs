use std::time::{Duration, Instant};

use mail_auth::common::parse::{TagParser, TxtRecordParser};

use super::{Mode, MtaSts, MxPattern, Policy};

const ID: u64 = (b'i' as u64) | ((b'd' as u64) << 8);
const V: u64 = b'v' as u64;

impl TxtRecordParser for MtaSts {
    #[allow(clippy::while_let_on_iterator)]
    fn parse(record: &[u8]) -> mail_auth::Result<Self> {
        let mut record = record.iter();
        let mut id = None;
        let mut has_version = false;

        while let Some(key) = record.key() {
            match key {
                V => {
                    if !record.match_bytes(b"STSv1") || !record.seek_tag_end() {
                        return Err(mail_auth::Error::InvalidRecordType);
                    }
                    has_version = true;
                }
                ID => {
                    id = record.text(false).into();
                }
                _ => {
                    record.ignore();
                }
            }
        }

        if let Some(id) = id {
            if has_version {
                return Ok(MtaSts { id });
            }
        }
        Err(mail_auth::Error::InvalidRecordType)
    }
}

impl Policy {
    pub fn parse(mut data: &str, id: String) -> Result<(Policy, Instant), String> {
        let mut mode = Mode::None;
        let mut expires_in: u64 = 86400;
        let mut mx = Vec::new();

        while !data.is_empty() {
            if let Some((key, next_data)) = data.split_once(':') {
                let value = if let Some((value, next_data)) = next_data.split_once('\n') {
                    data = next_data;
                    value.trim()
                } else {
                    data = "";
                    next_data.trim()
                };
                match key.trim() {
                    "mx" => {
                        if let Some(suffix) = value.strip_prefix('*') {
                            if !suffix.is_empty() {
                                mx.push(MxPattern::StartsWith(suffix.to_lowercase()));
                            }
                        } else if !value.is_empty() {
                            mx.push(MxPattern::Equals(value.to_lowercase()));
                        }
                    }
                    "max_age" => {
                        if let Ok(value) = value.parse() {
                            if (3600..31557600).contains(&value) {
                                expires_in = value;
                            }
                        }
                    }
                    "mode" => {
                        mode = match value {
                            "enforce" => Mode::Enforce,
                            "testing" => Mode::Testing,
                            "none" => Mode::Testing,
                            _ => return Err(format!("Unsupported mode {:?}.", value)),
                        };
                    }
                    "version" => {
                        if !value.eq_ignore_ascii_case("STSv1") {
                            return Err(format!("Unsupported version {:?}.", value));
                        }
                    }
                    _ => (),
                }
            } else {
                break;
            }
        }

        if !mx.is_empty() {
            Ok((
                Policy { id, mode, mx },
                Instant::now() + Duration::from_secs(expires_in),
            ))
        } else {
            Err("No 'mx' entries found.".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use mail_auth::common::parse::TxtRecordParser;

    use crate::outbound::mta_sts::{Mode, MtaSts, MxPattern, Policy};

    #[test]
    fn parse_mta_sts() {
        for (mta_sts, expected_mta_sts) in [
            (
                "v=STSv1; id=20160831085700Z;",
                MtaSts {
                    id: "20160831085700Z".to_string(),
                },
            ),
            (
                "v=STSv1; id=20190429T010101",
                MtaSts {
                    id: "20190429T010101".to_string(),
                },
            ),
        ] {
            assert_eq!(MtaSts::parse(mta_sts.as_bytes()).unwrap(), expected_mta_sts);
        }
    }

    #[test]
    fn parse_policy() {
        for (policy, expected_policy, max_age) in [
            (
                r"version: STSv1
mode: enforce
mx: mail.example.com
mx: *.example.net
mx: backupmx.example.com
max_age: 604800",
                Policy {
                    id: "abc".to_string(),
                    mode: Mode::Enforce,
                    mx: vec![
                        MxPattern::Equals("mail.example.com".to_string()),
                        MxPattern::StartsWith(".example.net".to_string()),
                        MxPattern::Equals("backupmx.example.com".to_string()),
                    ],
                },
                604800,
            ),
            (
                r"version: STSv1
mode: testing
mx: gmail-smtp-in.l.google.com
mx: *.gmail-smtp-in.l.google.com
max_age: 86400
",
                Policy {
                    id: "abc".to_string(),
                    mode: Mode::Testing,
                    mx: vec![
                        MxPattern::Equals("gmail-smtp-in.l.google.com".to_string()),
                        MxPattern::StartsWith(".gmail-smtp-in.l.google.com".to_string()),
                    ],
                },
                86400,
            ),
        ] {
            let (policy, expires_in) =
                Policy::parse(policy, expected_policy.id.to_string()).unwrap();
            assert_eq!(
                expires_in.duration_since(Instant::now()).as_secs() + 1,
                max_age
            );
            assert_eq!(policy, expected_policy);
        }
    }
}
