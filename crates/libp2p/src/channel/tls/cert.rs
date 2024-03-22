use rasi::utils::cancelable_would_block;
use rcgen::CustomExtension;

use crate::{errors::P2pResult, KeypairProvider};

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

static P2P_SIGNATURE_ALGORITHM: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;

/// In order to be able to use arbitrary key types, peers don’t use their host key to sign
/// the X.509 certificate they send during the handshake. Instead, the host key is encoded
/// into the libp2p Public Key Extension, which is carried in a self-signed certificate.
///
/// The key used to generate and sign this certificate SHOULD NOT be related to the host's key.
/// Endpoints MAY generate a new key and certificate for every connection attempt,
/// or they MAY reuse the same key and certificate for multiple connections.
///
/// The `keypair` is the host key provider.
pub async fn generate_libp2p_cert(keypair: &dyn KeypairProvider) -> P2pResult<Vec<u8>> {
    let certificate_keypair = rcgen::KeyPair::generate(P2P_SIGNATURE_ALGORITHM)?;

    let certificate = {
        let mut params = rcgen::CertificateParams::new(vec![]);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .custom_extensions
            .push(x509_libp2p_extension(keypair, &certificate_keypair).await?);
        params.alg = P2P_SIGNATURE_ALGORITHM;
        params.key_pair = Some(certificate_keypair);
        rcgen::Certificate::from_params(params)?
    };

    Ok(certificate.serialize_der()?)
}

async fn x509_libp2p_extension(
    keypair: &dyn KeypairProvider,
    cert_pkey: &rcgen::KeyPair,
) -> P2pResult<CustomExtension> {
    // The peer signs the concatenation of the string `libp2p-tls-handshake:`
    // and the public key that it used to generate the certificate carrying
    // the libp2p Public Key Extension, using its private host key.
    let signature = {
        let mut msg = vec![];
        msg.extend(P2P_SIGNING_PREFIX);
        msg.extend(cert_pkey.public_key_der());

        cancelable_would_block(|cx| keypair.sign(cx, &msg)).await?
    };

    // The public host key and the signature are ANS.1-encoded
    // into the SignedKey data structure, which is carried
    // in the libp2p Public Key Extension.
    // SignedKey ::= SEQUENCE {
    //    publicKey OCTET STRING,
    //    signature OCTET STRING
    // }
    let extension_content = {
        let serialized_pubkey = cancelable_would_block(|cx| keypair.public_key(cx))
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

    use x509_cert::{der::Decode, Certificate};

    use crate::plugin::keypair::memory::MemoryKeyProvider;

    use super::*;

    #[futures_test::test]
    async fn test_rcgen() {
        let key_provider = MemoryKeyProvider::random();

        let der = generate_libp2p_cert(&key_provider).await.unwrap();

        let cert = Certificate::from_der(&der).unwrap();

        let exts = cert.tbs_certificate.extensions.unwrap();

        for ext in exts {
            println!("{:?}", ext);
        }
    }
}
