use identity::PeerId;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerifier},
    crypto::aws_lc_rs::cipher_suite::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    },
    pki_types::CertificateDer,
    server::danger::ClientCertVerifier,
    SignatureScheme, SupportedCipherSuite, SupportedProtocolVersion,
};

use crate::errors::{P2pError, Result};

use super::cert;

/// The protocol versions supported by this verifier.
///
/// The spec says:
///
/// > The libp2p handshake uses TLS 1.3 (and higher).
/// > Endpoints MUST NOT negotiate lower TLS versions.
pub(super) static PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];
/// A list of the TLS 1.3 cipher suites supported by rustls.
// By default rustls creates client/server configs with both
// TLS 1.3 __and__ 1.2 cipher suites. But we don't need 1.2.
pub(super) static CIPHERSUITES: &[SupportedCipherSuite] = &[
    // TLS1.3 suites
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_AES_128_GCM_SHA256,
];

/// Implementation of the `rustls` certificate verification traits for libp2p.
///
/// Only TLS 1.3 is supported. TLS 1.2 should be disabled in the configuration of `rustls`.
#[derive(Debug)]
pub(super) struct Libp2pCertificateVerifier {
    /// The peer ID we intend to connect to
    remote_peer_id: Option<PeerId>,
}

/// libp2p requires the following of X.509 server certificate chains:
///
/// - Exactly one certificate must be presented.
/// - The certificate must be self-signed.
/// - The certificate must have a valid libp2p extension that includes a
///   signature of its public key.
impl Libp2pCertificateVerifier {
    pub(crate) fn new() -> Self {
        Self {
            remote_peer_id: None,
        }
    }
    pub(crate) fn with_remote_peer_id(remote_peer_id: Option<PeerId>) -> Self {
        Self { remote_peer_id }
    }

    /// Return the list of SignatureSchemes that this verifier will handle,
    /// in `verify_tls12_signature` and `verify_tls13_signature` calls.
    ///
    /// This should be in priority order, with the most preferred first.
    fn verification_schemes() -> Vec<SignatureScheme> {
        vec![
            // TODO SignatureScheme::ECDSA_NISTP521_SHA512 is not supported by `ring` yet
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            // TODO SignatureScheme::ED448 is not supported by `ring` yet
            SignatureScheme::ED25519,
            // In particular, RSA SHOULD NOT be used unless
            // no elliptic curve algorithms are supported.
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

impl ServerCertVerifier for Libp2pCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        todo!()
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        todo!()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        todo!()
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        todo!()
    }
}

/// libp2p requires the following of X.509 client certificate chains:
///
/// - Exactly one certificate must be presented. In particular, client
///   authentication is mandatory in libp2p.
/// - The certificate must be self-signed.
/// - The certificate must have a valid libp2p extension that includes a
///   signature of its public key.
impl ClientCertVerifier for Libp2pCertificateVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        todo!()
    }

    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        todo!()
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        todo!()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        todo!()
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        todo!()
    }
}

/// When receiving the certificate chain, an endpoint
/// MUST check these conditions and abort the connection attempt if
/// (a) the presented certificate is not yet valid, OR
/// (b) if it is expired.
/// Endpoints MUST abort the connection attempt if more than one certificate is received,
/// or if the certificate’s self-signature is not valid.
fn verify_presented_certs(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> Result<PeerId> {
    if !intermediates.is_empty() {
        return Err(P2pError::Libp2pCert);
    }

    let cert = cert::parse(end_entity)?;

    Ok(cert.peer_id())
}

fn verify_tls13_signature(
    cert: &CertificateDer<'_>,
    signature_scheme: SignatureScheme,
    message: &[u8],
    signature: &[u8],
) -> Result<HandshakeSignatureValid> {
    cert::parse(cert)?.verify_signature(signature_scheme, message, signature)?;

    Ok(HandshakeSignatureValid::assertion())
}
