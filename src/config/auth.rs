use std::{sync::Arc, time::Duration};

use ahash::AHashMap;
use mail_auth::{
    common::crypto::{Algorithm, Ed25519Key, HashAlgorithm, RsaKey, Sha256, SigningKey},
    dkim::{Canonicalization, Done},
};
use mail_parser::decoders::base64::base64_decode;

use super::{
    utils::{AsKey, ParseValue},
    ArcAuthConfig, ArcSealer, Config, ConfigContext, DkimAuthConfig, DkimCanonicalization,
    DkimSigner, DmarcAuthConfig, EnvelopeKey, IfBlock, IpRevAuthConfig, MailAuthConfig,
    SpfAuthConfig, TlsAuthConfig, VerifyStrategy,
};

impl Config {
    pub fn parse_mail_auth(&self, ctx: &ConfigContext) -> super::Result<MailAuthConfig> {
        let envelope_sender_keys = [
            EnvelopeKey::Sender,
            EnvelopeKey::SenderDomain,
            EnvelopeKey::Priority,
            EnvelopeKey::AuthenticatedAs,
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
        ];
        let envelope_conn_keys = [
            EnvelopeKey::Listener,
            EnvelopeKey::RemoteIp,
            EnvelopeKey::LocalIp,
        ];

        let (signers, sealers) = self.parse_signatures()?;

        Ok(MailAuthConfig {
            dkim: DkimAuthConfig {
                verify: self
                    .parse_if_block("auth.dkim.verify", ctx, &envelope_sender_keys)?
                    .unwrap_or_else(|| IfBlock::new(VerifyStrategy::Relaxed)),
                sign: self
                    .parse_if_block::<Vec<String>>("auth.dkim.sign", ctx, &envelope_sender_keys)?
                    .unwrap_or_default()
                    .map_if_block(&signers, "auth.dkim.sign", "signature")?,
                report_send: self
                    .parse_if_block("auth.dkim.reporting.send-rate", ctx, &envelope_sender_keys)?
                    .unwrap_or_default(),
                report_analyze: self
                    .parse_if_block("auth.dkim.reporting.analyze", ctx, &envelope_sender_keys)?
                    .unwrap_or_else(|| IfBlock::new(true)),
            },
            arc: ArcAuthConfig {
                verify: self
                    .parse_if_block("auth.arc.verify", ctx, &envelope_sender_keys)?
                    .unwrap_or_else(|| IfBlock::new(VerifyStrategy::Relaxed)),
                seal: self
                    .parse_if_block::<Option<String>>("auth.arc.seal", ctx, &envelope_sender_keys)?
                    .unwrap_or_default()
                    .map_if_block(&sealers, "auth.arc.seal", "signature")?,
            },
            spf: SpfAuthConfig {
                verify_ehlo: self
                    .parse_if_block("auth.spf.verify.ehlo", ctx, &envelope_conn_keys)?
                    .unwrap_or_else(|| IfBlock::new(VerifyStrategy::Relaxed)),
                verify_mail_from: self
                    .parse_if_block("auth.spf.verify.mail-from", ctx, &envelope_conn_keys)?
                    .unwrap_or_else(|| IfBlock::new(VerifyStrategy::Relaxed)),
                report_send: self
                    .parse_if_block("auth.spf.reporting.send-rate", ctx, &envelope_conn_keys)?
                    .unwrap_or_default(),
                report_analyze: self
                    .parse_if_block("auth.spf.reporting.analyze", ctx, &envelope_sender_keys)?
                    .unwrap_or_else(|| IfBlock::new(true)),
            },
            dmarc: DmarcAuthConfig {
                verify: self
                    .parse_if_block("auth.dmarc.verify", ctx, &envelope_sender_keys)?
                    .unwrap_or_else(|| IfBlock::new(VerifyStrategy::Relaxed)),
                report_aggregate: self
                    .parse_if_block(
                        "auth.dmarc.reporting.aggregate-frequency",
                        ctx,
                        &envelope_sender_keys,
                    )?
                    .unwrap_or_default(),
                report_send: self
                    .parse_if_block("auth.dmarc.reporting.send-rate", ctx, &envelope_sender_keys)?
                    .unwrap_or_default(),
                report_analyze: self
                    .parse_if_block("auth.dmarc.reporting.analyze", ctx, &envelope_sender_keys)?
                    .unwrap_or_else(|| IfBlock::new(true)),
            },
            tls: TlsAuthConfig {
                report_send: self
                    .parse_if_block("auth.tls.reporting.send-rate", ctx, &envelope_conn_keys)?
                    .unwrap_or_default(),
                report_analyze: self
                    .parse_if_block("auth.tls.reporting.analyze", ctx, &envelope_sender_keys)?
                    .unwrap_or_else(|| IfBlock::new(true)),
            },
            iprev: IpRevAuthConfig {
                verify: self
                    .parse_if_block("auth.iprev.verify", ctx, &envelope_conn_keys)?
                    .unwrap_or_else(|| IfBlock::new(VerifyStrategy::Relaxed)),
            },
        })
    }

    #[allow(clippy::type_complexity)]
    fn parse_signatures(
        &self,
    ) -> super::Result<(
        AHashMap<String, Arc<DkimSigner>>,
        AHashMap<String, Arc<ArcSealer>>,
    )> {
        let mut signers = AHashMap::new();
        let mut sealers = AHashMap::new();

        for id in self.sub_keys("auth.signature") {
            let (signer, sealer) =
                match self.property_require::<Algorithm>(("auth.signature", id, "algorithm"))? {
                    Algorithm::RsaSha256 => {
                        let key = RsaKey::<Sha256>::from_pkcs1_pem(
                            &String::from_utf8(self.file_contents((
                                "auth.signature",
                                id,
                                "public-key",
                            ))?)
                            .unwrap_or_default(),
                        )
                        .map_err(|err| {
                            format!(
                                "Failed to build RSA key for {}: {}",
                                ("auth.signature", id, "public-key",).as_key(),
                                err
                            )
                        })?;
                        let (signer, sealer) = self.parse_signature(id, key.clone(), key)?;
                        (DkimSigner::RsaSha256(signer), ArcSealer::RsaSha256(sealer))
                    }
                    Algorithm::Ed25519Sha256 => {
                        let cert = base64_decode(&self.file_contents((
                            "auth.signature",
                            id,
                            "public-key",
                        ))?)
                        .ok_or_else(|| {
                            format!(
                                "Failed to base64 decode public key for {}.",
                                ("auth.signature", id, "public-key",).as_key(),
                            )
                        })?;
                        let pk = base64_decode(&self.file_contents((
                            "auth.signature",
                            id,
                            "private-key",
                        ))?)
                        .ok_or_else(|| {
                            format!(
                                "Failed to base64 decode private key for {}.",
                                ("auth.signature", id, "private-key",).as_key(),
                            )
                        })?;
                        let key = Ed25519Key::from_bytes(&cert, &pk).map_err(|err| {
                            format!(
                                "Failed to build ED25519 key for signature {:?}: {}",
                                id, err
                            )
                        })?;
                        let key_clone = Ed25519Key::from_bytes(&cert, &pk).map_err(|err| {
                            format!(
                                "Failed to build ED25519 key for signature {:?}: {}",
                                id, err
                            )
                        })?;

                        let (signer, sealer) = self.parse_signature(id, key_clone, key)?;
                        (
                            DkimSigner::Ed25519Sha256(signer),
                            ArcSealer::Ed25519Sha256(sealer),
                        )
                    }
                    Algorithm::RsaSha1 => {
                        return Err(format!(
                            "Could not build signature {:?}: SHA1 signatures are deprecated.",
                            id
                        ))
                    }
                };
            signers.insert(id.to_string(), Arc::new(signer));
            sealers.insert(id.to_string(), Arc::new(sealer));
        }

        Ok((signers, sealers))
    }

    fn parse_signature<T: SigningKey, U: SigningKey<Hasher = Sha256>>(
        &self,
        id: &str,
        key_dkim: T,
        key_arc: U,
    ) -> super::Result<(
        mail_auth::dkim::DkimSigner<T, Done>,
        mail_auth::arc::ArcSealer<U, Done>,
    )> {
        let domain = self.value_require(("auth.signature", id, "domain"))?;
        let selector = self.value_require(("auth.signature", id, "selector"))?;
        let mut headers = self
            .values(("auth.signature", id, "headers"))
            .filter_map(|(_, v)| {
                if !v.is_empty() {
                    v.to_string().into()
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if headers.is_empty() {
            headers = vec![
                "From".to_string(),
                "To".to_string(),
                "Date".to_string(),
                "Subject".to_string(),
                "Message-ID".to_string(),
            ];
        }

        let mut signer = mail_auth::dkim::DkimSigner::from_key(key_dkim)
            .domain(domain)
            .selector(selector)
            .headers(headers.clone());
        if !headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case("DKIM-Signature"))
        {
            headers.push("DKIM-Signature".to_string());
        }
        let mut sealer = mail_auth::arc::ArcSealer::from_key(key_arc)
            .domain(domain)
            .selector(selector)
            .headers(headers);

        if let Some(c) =
            self.property::<DkimCanonicalization>(("auth.signature", id, "canonicalization"))?
        {
            signer = signer
                .body_canonicalization(c.body)
                .header_canonicalization(c.headers);
            sealer = sealer
                .body_canonicalization(c.body)
                .header_canonicalization(c.headers);
        }

        if let Some(c) = self.property::<Duration>(("auth.signature", id, "expire"))? {
            signer = signer.expiration(c.as_secs());
            sealer = sealer.expiration(c.as_secs());
        }

        if let Some(true) = self.property::<bool>(("auth.signature", id, "set-body-length"))? {
            signer = signer.body_length(true);
            sealer = sealer.body_length(true);
        }

        if let Some(true) = self.property::<bool>(("auth.signature", id, "report"))? {
            signer = signer.reporting(true);
        }

        if let Some(auid) = self.property::<String>(("auth.signature", id, "auid"))? {
            signer = signer.agent_user_identifier(auid);
        }

        if let Some(atps) = self.property::<String>(("auth.signature", id, "third-party"))? {
            signer = signer.atps(atps);
        }

        if let Some(atpsh) =
            self.property::<HashAlgorithm>(("auth.signature", id, "third-party-algo"))?
        {
            signer = signer.atpsh(atpsh);
        }

        Ok((signer, sealer))
    }
}

impl ParseValue for VerifyStrategy {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        match value {
            "relaxed" => Ok(VerifyStrategy::Relaxed),
            "strict" => Ok(VerifyStrategy::Strict),
            "disable" | "disabled" | "never" | "none" => Ok(VerifyStrategy::Disable),
            _ => Err(format!(
                "Invalid value {:?} for key {:?}.",
                value,
                key.as_key()
            )),
        }
    }
}

impl ParseValue for DkimCanonicalization {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        if let Some((headers, body)) = value.split_once('/') {
            Ok(DkimCanonicalization {
                headers: Canonicalization::parse_value(key.clone(), headers.trim())?,
                body: Canonicalization::parse_value(key, body.trim())?,
            })
        } else {
            let c = Canonicalization::parse_value(key, value)?;
            Ok(DkimCanonicalization {
                headers: c,
                body: c,
            })
        }
    }
}

impl ParseValue for Canonicalization {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        match value {
            "relaxed" => Ok(Canonicalization::Relaxed),
            "simple" => Ok(Canonicalization::Simple),
            _ => Err(format!(
                "Invalid canonicalization value {:?} for key {:?}.",
                value,
                key.as_key()
            )),
        }
    }
}

impl Default for DkimCanonicalization {
    fn default() -> Self {
        Self {
            headers: Canonicalization::Relaxed,
            body: Canonicalization::Relaxed,
        }
    }
}

impl ParseValue for Algorithm {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        match value {
            "ed25519-sha256" | "ed25519-sha-256" => Ok(Algorithm::Ed25519Sha256),
            "rsa-sha-256" | "rsa-sha256" => Ok(Algorithm::RsaSha256),
            "rsa-sha-1" | "rsa-sha1" => Ok(Algorithm::RsaSha1),
            _ => Err(format!(
                "Invalid algorithm {:?} for key {:?}.",
                value,
                key.as_key()
            )),
        }
    }
}

impl ParseValue for HashAlgorithm {
    fn parse_value(key: impl AsKey, value: &str) -> super::Result<Self> {
        match value {
            "sha256" | "sha-256" => Ok(HashAlgorithm::Sha256),
            "sha-1" | "sha1" => Ok(HashAlgorithm::Sha1),
            _ => Err(format!(
                "Invalid hash algorithm {:?} for key {:?}.",
                value,
                key.as_key()
            )),
        }
    }
}
