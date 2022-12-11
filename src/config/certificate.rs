use std::{io::Cursor, sync::Arc};

use rustls::{
    server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni},
    sign::CertifiedKey,
    version::{TLS12, TLS13},
    Certificate, KeyLog, PrivateKey, SupportedProtocolVersion,
};
use rustls_pemfile::{certs, read_one, Item};

use super::Config;

pub static TLS13_VERSION: &[&SupportedProtocolVersion] = &[&TLS13];
pub static TLS12_VERSION: &[&SupportedProtocolVersion] = &[&TLS12];

pub struct CertificateResolver {
    pub default_cert: Option<Arc<CertifiedKey>>,
    pub resolver: ResolvesServerCertUsingSni,
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolver
            .resolve(hello)
            .or_else(|| self.default_cert.clone())
    }
}

#[derive(Default)]
pub struct KeyLogger;

impl KeyLog for KeyLogger {
    fn log(&self, _label: &str, _client_random: &[u8], _secret: &[u8]) {
        //TODO
    }
}

impl Config {
    pub fn rustls_certificate(&self, cert_id: &str) -> super::Result<Certificate> {
        certs(&mut Cursor::new(self.file_contents((
            "key",
            cert_id,
            "certificate",
        ))?))
        .map_err(|err| {
            format!(
                "Failed to read certificates in \"certificates.{}.cert\": {}",
                cert_id, err
            )
        })?
        .into_iter()
        .map(Certificate)
        .next()
        .ok_or_else(|| {
            format!(
                "No certificates found in \"certificates.{}.cert\".",
                cert_id
            )
        })
    }

    pub fn rustls_private_key(&self, cert_id: &str) -> super::Result<PrivateKey> {
        match read_one(&mut Cursor::new(self.file_contents((
            "key",
            cert_id,
            "private-key",
        ))?))
        .map_err(|err| {
            format!(
                "Failed to read private keys in \"certificates.{}.pki\": {}",
                cert_id, err
            )
        })?
        .into_iter()
        .next()
        {
            Some(Item::PKCS8Key(key) | Item::RSAKey(key) | Item::ECKey(key)) => Ok(PrivateKey(key)),
            Some(_) => Err(format!(
                "Unsupported private keys found in \"certificates.{}.pki\".",
                cert_id
            )),
            None => Err(format!(
                "No private keys found in \"certificates.{}.pki\".",
                cert_id
            )),
        }
    }
}
