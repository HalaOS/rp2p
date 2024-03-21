use std::net::{IpAddr, SocketAddr};

use multiaddr::{Multiaddr, Protocol};
use rasi::utils::cancelable_would_block;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::{errors::Result, KeypairProvider};

pub(super) fn to_sockaddr(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut iter = addr.iter();

    let ip = match iter.next()? {
        Protocol::Ip4(ip) => IpAddr::from(ip),
        Protocol::Ip6(ip) => IpAddr::from(ip),
        _ => return None,
    };

    let next = iter.next()?;

    match next {
        Protocol::Tcp(port) | Protocol::Udp(port) => {
            return Some(SocketAddr::new(ip, port));
        }
        _ => {}
    }

    None
}

/// The libp2p Public Key Extension is a X.509 extension
/// with the Object Identifier 1.3.6.1.4.1.53594.1.1,
/// allocated by IANA to the libp2p project at Protocol Labs.
const P2P_EXT_OID: [u64; 9] = [1, 3, 6, 1, 4, 1, 53594, 1, 1];

/// The peer signs the concatenation of the string `libp2p-tls-handshake:`
/// and the public key that it used to generate the certificate carrying
/// the libp2p Public Key Extension, using its private host key.
/// This signature provides cryptographic proof that the peer was
/// in possession of the private host key at the time the certificate was signed.
const P2P_SIGNING_PREFIX: [u8; 21] = *b"libp2p-tls-handshake:";

static P2P_SIGNATURE_ALGORITHM: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ED25519;

/// Generate the libp2p tls handshake self-signed (X.509 certificate, privatekey)
pub(super) async fn tls_cer_gen(
    identity_keypair: &dyn KeypairProvider,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let certificate_keypair = rcgen::KeyPair::generate(P2P_SIGNATURE_ALGORITHM)?;

    let rustls_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        certificate_keypair.serialize_der(),
    ));

    let certificate = {
        let mut params = rcgen::CertificateParams::new(vec![]);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .custom_extensions
            .push(make_libp2p_extension(identity_keypair, &certificate_keypair).await?);
        params.alg = P2P_SIGNATURE_ALGORITHM;
        params.key_pair = Some(certificate_keypair);
        rcgen::Certificate::from_params(params)?
    };

    let rustls_certificate = CertificateDer::from(certificate.serialize_der()?);

    Ok((rustls_certificate, rustls_key))
}

async fn make_libp2p_extension(
    identity_keypair: &dyn KeypairProvider,
    certificate_keypair: &rcgen::KeyPair,
) -> Result<rcgen::CustomExtension> {
    // The peer signs the concatenation of the string `libp2p-tls-handshake:`
    // and the public key that it used to generate the certificate carrying
    // the libp2p Public Key Extension, using its private host key.
    let signature = {
        let mut msg = vec![];
        msg.extend(P2P_SIGNING_PREFIX);
        msg.extend(certificate_keypair.public_key_der());

        cancelable_would_block(|cx, pending| identity_keypair.sign(cx, &msg, pending)).await?
    };

    // The public host key and the signature are ANS.1-encoded
    // into the SignedKey data structure, which is carried
    // in the libp2p Public Key Extension.
    // SignedKey ::= SEQUENCE {
    //    publicKey OCTET STRING,
    //    signature OCTET STRING
    // }
    let extension_content = {
        let serialized_pubkey =
            cancelable_would_block(|cx, pending| identity_keypair.public_key(cx, pending))
                .await?
                .encode_protobuf();

        yasna::encode_der(&(serialized_pubkey, signature))
    };

    // This extension MAY be marked critical.
    let mut ext = rcgen::CustomExtension::from_oid_content(&P2P_EXT_OID, extension_content);
    ext.set_criticality(true);

    Ok(ext)
}

#[cfg(test)]
mod tests {
    use crate::plugin::keypair::memory::MemoryKeyProvider;

    use super::tls_cer_gen;

    #[futures_test::test]
    async fn test_cer_gen() {
        let provider = MemoryKeyProvider::default();

        tls_cer_gen(&provider).await.unwrap();
    }
}
