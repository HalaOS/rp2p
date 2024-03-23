//! Utilities for x509 certificate of libp2p

use std::{
    str::FromStr,
    time::{Duration, SystemTime},
};

use const_oid::{db::rfc5912::ECDSA_WITH_SHA_256, AssociatedOid, ObjectIdentifier};
use der::{asn1::OctetString, Decode, Encode, Sequence};
use identity::Keypair;
use p256::ecdsa::{signature::Verifier, DerSignature, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, thread_rng, Rng};
use rasi::utils::cancelable_would_block;
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    ext::{AsExtension, Extension},
    name::Name,
    serial_number::SerialNumber,
    spki::{DecodePublicKey, EncodePublicKey, SubjectPublicKeyInfoOwned},
    time::Validity,
    Certificate,
};

use crate::{
    errors::{P2pError, P2pResult},
    KeypairProvider,
};

/// The peer signs the concatenation of the string `libp2p-tls-handshake:`
/// and the public key that it used to generate the certificate carrying
/// the libp2p Public Key Extension, using its private host key.
/// This signature provides cryptographic proof that the peer was
/// in possession of the private host key at the time the certificate was signed.
static P2P_SIGNING_PREFIX: [u8; 21] = *b"libp2p-tls-handshake:";

const P2P_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.53594.1.1");

/// The public host key and the signature are ANS.1-encoded
/// into the SignedKey data structure, which is carried
/// in the libp2p Public Key Extension.
/// SignedKey ::= SEQUENCE {
///    publicKey OCTET STRING,
///    signature OCTET STRING
/// }
#[derive(Sequence)]
pub struct Libp2pExtension {
    public_key: OctetString,
    signature: OctetString,
}

impl AssociatedOid for Libp2pExtension {
    /// The libp2p Public Key Extension is a X.509 extension
    /// with the Object Identifier 1.3.6.1.4.1.53594.1.1,
    /// allocated by IANA to the libp2p project at Protocol Labs.

    const OID: ObjectIdentifier = P2P_OID;
}

impl AsExtension for Libp2pExtension {
    fn critical(&self, _subject: &x509_cert::name::Name, _extensions: &[Extension]) -> bool {
        true
    }
}

impl Libp2pExtension {
    /// Create a libp2p public key extension with host `keypair` and public key used to generate the certifacte.
    pub async fn new<PubKey: AsRef<[u8]>>(
        keypair: &dyn KeypairProvider,
        cert_pub_key: PubKey,
    ) -> P2pResult<Self> {
        // The peer signs the concatenation of the string `libp2p-tls-handshake:`
        // and the public key that it used to generate the certificate carrying
        // the libp2p Public Key Extension, using its private host key.
        let signature = {
            let mut msg = vec![];
            msg.extend(P2P_SIGNING_PREFIX);
            msg.extend(cert_pub_key.as_ref());

            cancelable_would_block(|cx| keypair.sign(cx, &msg)).await?
        };

        let public_key = cancelable_would_block(|cx| keypair.public_key(cx))
            .await?
            .encode_protobuf();

        Ok(Self {
            public_key: OctetString::new(public_key)?,
            signature: OctetString::new(signature)?,
        })
    }
}

/// In order to be able to use arbitrary key types, peers don’t use their host key to sign
/// the X.509 certificate they send during the handshake. Instead, the host key is encoded
/// into the libp2p Public Key Extension, which is carried in a self-signed certificate.
///
/// The key used to generate and sign this certificate SHOULD NOT be related to the host's key.
/// Endpoints MAY generate a new key and certificate for every connection attempt,
/// or they MAY reuse the same key and certificate for multiple connections.
///
/// The `keypair` is the host key provider.
pub async fn generate(keypair: &dyn KeypairProvider) -> P2pResult<(Vec<u8>, Keypair)> {
    let signer = p256::SecretKey::random(&mut OsRng);

    let cert_keypair = identity::Keypair::from(identity::ecdsa::Keypair::from(
        identity::ecdsa::SecretKey::try_from_bytes(signer.to_bytes()).unwrap(),
    ));

    let public_key = signer.public_key();

    let signer = SigningKey::from(signer);

    let serial_number = SerialNumber::from(thread_rng().gen::<u64>());
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let profile = Profile::Manual { issuer: None };
    let subject = Name::from_str("CN=World domination corporation,O=World domination Inc,C=US")
        .unwrap()
        .to_der()
        .unwrap();
    let subject = Name::from_der(&subject).unwrap();
    let pub_key = SubjectPublicKeyInfoOwned::from_key(public_key)?;

    let mut builder =
        CertificateBuilder::new(profile, serial_number, validity, subject, pub_key, &signer)?;

    let libp2p_extension =
        Libp2pExtension::new(keypair, public_key.to_public_key_der()?.as_bytes()).await?;

    builder.add_extension(&libp2p_extension)?;

    let certifacte = builder.build::<DerSignature>()?;

    Ok((certifacte.to_der()?, cert_keypair))
}

/// Parse and verify the libp2p certificate from der-encoding format.
pub fn verify<D: AsRef<[u8]>>(der: D) -> P2pResult<Certificate> {
    let cert = Certificate::from_der(der.as_ref())?;

    validity(&cert)?;

    verify_signature(&cert)?;

    let _extension = extract_libp2p_extension(&cert)?;

    Ok(cert)
}

// Certificates MUST use the NamedCurve encoding for elliptic curve parameters.
// Similarly, hash functions with an output length less than 256 bits
// MUST NOT be used, due to the possibility of collision attacks.
// In particular, MD5 and SHA1 MUST NOT be used.
// Endpoints MUST abort the connection attempt if it is not used.
fn verify_signature(cert: &Certificate) -> P2pResult<()> {
    match cert.signature_algorithm.oid {
        ECDSA_WITH_SHA_256 => return verify_ecsda_with_sha256_signature(cert),
        oid => {
            return Err(P2pError::Libp2pCert(format!(
                "forbidden signature({})",
                oid
            )))
        }
    }
}

fn verify_ecsda_with_sha256_signature(cert: &Certificate) -> P2pResult<()> {
    let input = cert.tbs_certificate.to_der()?;

    let pub_key = cert.tbs_certificate.subject_public_key_info.to_der()?;

    let verify_key = VerifyingKey::from_public_key_der(&pub_key)?;

    let signature =
        p256::ecdsa::DerSignature::from_bytes(cert.signature.as_bytes().unwrap_or(&[]))?;

    verify_key.verify(&input, &signature)?;

    Ok(())
}

// be valid at the time it is received by the peer;
fn validity(cert: &Certificate) -> P2pResult<()> {
    let not_after = cert.tbs_certificate.validity.not_after.to_system_time();
    let not_before = cert.tbs_certificate.validity.not_before.to_system_time();

    let now = SystemTime::now();

    if not_after < now || now < not_before {
        return Err(P2pError::Libp2pCert(format!(
            "Valid time error, not_after={:?}, not_before={:?}, now={:?}",
            not_after, not_before, now
        )));
    }

    Ok(())
}

fn extract_libp2p_extension(cert: &Certificate) -> P2pResult<Libp2pExtension> {
    let extensions = match &cert.tbs_certificate.extensions {
        Some(extension) => extension,
        None => {
            return Err(P2pError::Libp2pCert(
                "libp2p public key extension not found".into(),
            ))
        }
    };

    let mut libp2p_extension = None;

    for ext in extensions {
        // found p2p extension.
        if ext.extn_id == P2P_OID {
            if libp2p_extension.is_some() {
                return Err(P2pError::Libp2pCert(
                    "duplicate libp2p public key extension".into(),
                ));
            }

            libp2p_extension = Some(Libp2pExtension::from_der(ext.extn_value.as_bytes())?);

            continue;
        }

        if ext.critical {
            return Err(P2pError::Libp2pCert(format!(
                "Unknown critical: {}",
                ext.extn_id
            )));
        }
    }

    let libp2p_extension = libp2p_extension.ok_or(P2pError::Libp2pCert(
        "libp2p public key extension not found".into(),
    ))?;

    Ok(libp2p_extension)
}

#[cfg(test)]
mod tests {

    use crate::plugin::keypair::memory::MemoryKeyProvider;

    use super::*;

    #[futures_test::test]
    async fn test_cert_gen() {
        let key_provider = MemoryKeyProvider::random();

        let (der, _) = generate(&key_provider).await.unwrap();

        verify(der).unwrap();
    }
}
