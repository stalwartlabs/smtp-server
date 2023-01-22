use super::{Mode, MxPattern, Policy};

impl Policy {
    pub fn parse(mut data: &str, id: String) -> Result<Policy, String> {
        let mut mode = Mode::None;
        let mut max_age: u64 = 86400;
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
                        if let Some(suffix) = value.strip_prefix("*.") {
                            if !suffix.is_empty() {
                                mx.push(MxPattern::StartsWith(suffix.to_lowercase()));
                            }
                        } else if !value.is_empty() {
                            mx.push(MxPattern::Equals(value.to_lowercase()));
                        }
                    }
                    "max_age" => {
                        if let Ok(value) = value.parse() {
                            max_age = value;
                        }
                    }
                    "mode" => {
                        mode = match value {
                            "enforce" => Mode::Enforce,
                            "testing" => Mode::Testing,
                            "none" => Mode::None,
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
            Ok(Policy {
                id,
                mode,
                mx,
                max_age,
            })
        } else {
            Err("No 'mx' entries found.".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::outbound::mta_sts::{Mode, MxPattern, Policy};

    #[test]
    fn parse_policy() {
        for (policy, expected_policy) in [
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
                        MxPattern::StartsWith("example.net".to_string()),
                        MxPattern::Equals("backupmx.example.com".to_string()),
                    ],
                    max_age: 604800,
                },
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
                        MxPattern::StartsWith("gmail-smtp-in.l.google.com".to_string()),
                    ],
                    max_age: 86400,
                },
            ),
        ] {
            assert_eq!(
                Policy::parse(policy, expected_policy.id.to_string()).unwrap(),
                expected_policy
            );
        }
    }
}
