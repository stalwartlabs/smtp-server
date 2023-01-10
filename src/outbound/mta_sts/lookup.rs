use std::{sync::Arc, time::Duration};

use mail_auth::{common::lru::DnsCache, mta_sts::MtaSts};
use reqwest::redirect;

use crate::{core::Resolvers, USER_AGENT};

use super::{Error, Policy};

impl Resolvers {
    pub async fn lookup_mta_sts_policy<'x>(
        &self,
        domain: &str,
        timeout: Duration,
    ) -> Result<Arc<Policy>, Error> {
        // Lookup MTA-STS TXT record
        let record = match self
            .dns
            .txt_lookup::<MtaSts>(format!("_mta-sts.{}.", domain))
            .await
        {
            Ok(record) => record,
            Err(err) => {
                // Return the cached policy in case of failure
                return if let Some(value) = self.cache.mta_sts.get(domain) {
                    Ok(value)
                } else {
                    Err(err.into())
                };
            }
        };

        // Check if the policy has been cached
        if let Some(value) = self.cache.mta_sts.get(domain) {
            if value.id == record.id {
                return Ok(value);
            }
        }

        // Fetch policy
        let bytes = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(timeout)
            .redirect(redirect::Policy::none())
            .build()?
            .get(&format!(
                "https://mta-sts.{}/.well-known/mta-sts.txt",
                domain
            ))
            .send()
            .await?
            .bytes()
            .await?;

        // Parse policy
        let (policy, valid_until) = Policy::parse(
            std::str::from_utf8(&bytes).map_err(|err| Error::InvalidPolicy(err.to_string()))?,
            record.id.clone(),
        )?;

        Ok(self
            .cache
            .mta_sts
            .insert(domain.to_string(), Arc::new(policy), valid_until))
    }

    #[cfg(test)]
    pub(crate) fn policy_add<'x>(
        &self,
        key: impl mail_auth::common::resolver::IntoFqdn<'x>,
        value: Policy,
        valid_until: std::time::Instant,
    ) {
        self.cache
            .mta_sts
            .insert(key.into_fqdn().into_owned(), Arc::new(value), valid_until);
    }
}

impl From<mail_auth::Error> for Error {
    fn from(value: mail_auth::Error) -> Self {
        Error::Dns(value)
    }
}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        Error::Http(value)
    }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Error::InvalidPolicy(value)
    }
}
