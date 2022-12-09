use std::str::FromStr;

use super::{
    utils::{AsKey, ParseKey},
    Config, Throttle, ThrottleKey,
};

impl Config {
    pub fn parse_throttle(&self, prefix: impl AsKey) -> super::Result<Vec<Throttle>> {
        let mut throttles = Vec::new();
        let key = prefix.as_key();

        for array_pos in self.sub_keys(prefix) {
            let mut throttle = Throttle {
                key: Vec::new(),
                concurrency: 0,
                rate_requests: 0,
                rate_period: 0,
            };

            // Parse keys
            for (_, throttle_key) in
                self.properties::<ThrottleKey>((key.as_str(), array_pos, "key"))
            {
                throttle.key.push(throttle_key?);
            }

            // Parse concurrency
            if let Some(concurrency) =
                self.property::<u64>((key.as_str(), array_pos, "concurrency"))?
            {
                throttle.concurrency = concurrency;
            }

            // Parse rate
            if let Some(rate) = self.value((key.as_str(), array_pos, "rate")) {
                if let Some((requests, period)) = rate.split_once('/') {
                    throttle.rate_requests = requests
                        .trim()
                        .parse::<u64>()
                        .ok()
                        .and_then(|r| if r > 0 { Some(r) } else { None })
                        .ok_or_else(|| {
                            format!(
                                "Invalid rate value {:?} for key {:?}.",
                                rate,
                                (key.as_str(), array_pos, "rate").as_key()
                            )
                        })?;
                    throttle.rate_period =
                        period.parse_duration((key.as_str(), array_pos, "rate"))?;
                } else {
                    return Err(format!(
                        "Invalid rate value {:?} for key {:?}.",
                        rate,
                        (key.as_str(), array_pos, "rate").as_key()
                    ));
                }
            }

            // Validate
            if throttle.key.is_empty() {
                return Err(format!(
                    "No throttle keys found in {:?}",
                    (key.as_str(), array_pos, "key").as_key()
                ));
            } else if throttle.rate_requests == 0 && throttle.concurrency == 0 {
                return Err(format!(
                    concat!(
                        "Throttle {:?} needs to define a ",
                        "valid 'rate' or 'concurrency' property."
                    ),
                    (key.as_str(), array_pos).as_key()
                ));
            }

            throttles.push(throttle);
        }

        Ok(throttles)
    }
}

impl FromStr for ThrottleKey {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "rcpt-domain" => ThrottleKey::RecipientDomain,
            "sender-domain" => ThrottleKey::SenderDomain,
            "listener" => ThrottleKey::Listener,
            "mx" => ThrottleKey::Mx,
            "remote-ip" => ThrottleKey::RemoteIp,
            "local-ip" => ThrottleKey::LocalIp,
            _ => return Err(()),
        })
    }
}
