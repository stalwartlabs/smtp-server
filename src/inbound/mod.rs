use mail_auth::{
    arc::ArcSet, dkim::Signature, ArcOutput, AuthenticatedMessage, AuthenticationResults,
};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;

use crate::config::{ArcSealer, DkimSigner};

pub mod auth;
pub mod data;
pub mod ehlo;
pub mod mail;
pub mod rcpt;
pub mod session;
pub mod spawn;
pub mod vrfy;

pub trait IsTls {
    fn is_tls(&self) -> bool;
    fn write_tls_header(&self, headers: &mut Vec<u8>);
}

impl IsTls for TcpStream {
    fn is_tls(&self) -> bool {
        false
    }
    fn write_tls_header(&self, _headers: &mut Vec<u8>) {}
}

impl IsTls for TlsStream<TcpStream> {
    fn is_tls(&self) -> bool {
        true
    }

    fn write_tls_header(&self, headers: &mut Vec<u8>) {
        let (_, conn) = self.get_ref();
        headers.extend_from_slice(b"(using ");
        headers.extend_from_slice(
            match conn
                .protocol_version()
                .unwrap_or(rustls::ProtocolVersion::Unknown(0))
            {
                rustls::ProtocolVersion::SSLv2 => "SSLv2",
                rustls::ProtocolVersion::SSLv3 => "SSLv3",
                rustls::ProtocolVersion::TLSv1_0 => "TLSv1.0",
                rustls::ProtocolVersion::TLSv1_1 => "TLSv1.1",
                rustls::ProtocolVersion::TLSv1_2 => "TLSv1.2",
                rustls::ProtocolVersion::TLSv1_3 => "TLSv1.3",
                rustls::ProtocolVersion::DTLSv1_0 => "DTLSv1.0",
                rustls::ProtocolVersion::DTLSv1_2 => "DTLSv1.2",
                rustls::ProtocolVersion::DTLSv1_3 => "DTLSv1.3",
                rustls::ProtocolVersion::Unknown(_) => "unknown",
            }
            .as_bytes(),
        );
        headers.extend_from_slice(b" with cipher ");
        headers.extend_from_slice(
            match conn.negotiated_cipher_suite() {
                Some(rustls::SupportedCipherSuite::Tls13(cs)) => {
                    cs.common.suite.as_str().unwrap_or("unknown")
                }
                Some(rustls::SupportedCipherSuite::Tls12(cs)) => {
                    cs.common.suite.as_str().unwrap_or("unknown")
                }
                None => "unknown",
            }
            .as_bytes(),
        );
        headers.extend_from_slice(b")\r\n\r");
    }
}

impl ArcSealer {
    pub fn seal<'x>(
        &self,
        message: &'x AuthenticatedMessage,
        results: &'x AuthenticationResults,
        arc_output: &'x ArcOutput,
    ) -> mail_auth::Result<ArcSet<'x>> {
        match self {
            ArcSealer::RsaSha256(sealer) => sealer.seal(message, results, arc_output),
            ArcSealer::Ed25519Sha256(sealer) => sealer.seal(message, results, arc_output),
        }
    }
}

impl DkimSigner {
    pub fn sign(&self, message: &[u8]) -> mail_auth::Result<Signature> {
        match self {
            DkimSigner::RsaSha256(signer) => signer.sign(message),
            DkimSigner::Ed25519Sha256(signer) => signer.sign(message),
        }
    }
    pub fn sign_chained(&self, message: &[&[u8]]) -> mail_auth::Result<Signature> {
        match self {
            DkimSigner::RsaSha256(signer) => signer.sign_chained(message.iter().copied()),
            DkimSigner::Ed25519Sha256(signer) => signer.sign_chained(message.iter().copied()),
        }
    }
}
