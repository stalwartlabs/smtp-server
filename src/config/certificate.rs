use std::{io::Cursor, sync::Arc};

use rustls::{
    server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni},
    sign::CertifiedKey,
    version::{TLS12, TLS13},
    Certificate, PrivateKey, SupportedProtocolVersion,
};
use rustls_pemfile::{certs, read_one, Item};

use super::Config;

pub static TLS13_VERSION: &[&SupportedProtocolVersion] = &[&TLS13];
pub static TLS12_VERSION: &[&SupportedProtocolVersion] = &[&TLS12];

pub struct CertificateResolver {
    pub resolver: Option<ResolvesServerCertUsingSni>,
    pub default_cert: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolver
            .as_ref()
            .and_then(|r| r.resolve(hello))
            .or_else(|| self.default_cert.clone())
    }
}

impl Config {
    pub fn rustls_certificate(&self, cert_id: &str) -> super::Result<Certificate> {
        certs(&mut Cursor::new(self.file_contents((
            "certificate",
            cert_id,
            "cert",
        ))?))
        .map_err(|err| {
            format!("Failed to read certificates in \"certificate.{cert_id}.cert\": {err}")
        })?
        .into_iter()
        .map(Certificate)
        .next()
        .ok_or_else(|| format!("No certificates found in \"certificate.{cert_id}.cert\"."))
    }

    pub fn rustls_private_key(&self, cert_id: &str) -> super::Result<PrivateKey> {
        match read_one(&mut Cursor::new(self.file_contents((
            "certificate",
            cert_id,
            "private-key",
        ))?))
        .map_err(|err| {
            format!("Failed to read private keys in \"certificate.{cert_id}.private-key\": {err}",)
        })?
        .into_iter()
        .next()
        {
            Some(Item::PKCS8Key(key) | Item::RSAKey(key) | Item::ECKey(key)) => Ok(PrivateKey(key)),
            Some(_) => Err(format!(
                "Unsupported private keys found in \"certificate.{cert_id}.private-key\".",
            )),
            None => Err(format!(
                "No private keys found in \"certificate.{cert_id}.private-key\".",
            )),
        }
    }
}
