use super::{Mode, MxPattern, Policy};

impl Policy {
    pub fn verify(&self, mx_host: &str) -> bool {
        if self.mode != Mode::None {
            for mx_pattern in &self.mx {
                match mx_pattern {
                    MxPattern::Equals(host) => {
                        if host == mx_host {
                            return true;
                        }
                    }
                    MxPattern::StartsWith(domain) => {
                        if let Some((_, suffix)) = mx_host.split_once('.') {
                            if suffix == domain {
                                return true;
                            }
                        }
                    }
                }
            }

            false
        } else {
            true
        }
    }

    pub fn enforce(&self) -> bool {
        self.mode == Mode::Enforce
    }
}
