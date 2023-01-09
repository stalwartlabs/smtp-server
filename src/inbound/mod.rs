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
}

impl IsTls for TcpStream {
    fn is_tls(&self) -> bool {
        false
    }
}

impl IsTls for TlsStream<TcpStream> {
    fn is_tls(&self) -> bool {
        true
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
    pub fn sign(&self, message: &[&[u8]]) -> mail_auth::Result<Signature> {
        match self {
            DkimSigner::RsaSha256(signer) => signer.sign_chained(message.iter().copied()),
            DkimSigner::Ed25519Sha256(signer) => signer.sign_chained(message.iter().copied()),
        }
    }
}
