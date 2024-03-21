use der_parser::asn1_rs::FromDer;
use identity::PeerId;
use rasi::utils::cancelable_would_block;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    SignatureScheme,
};

use x509_parser::{certificate::X509Certificate, signature_algorithm::SignatureAlgorithm};

use crate::{
    errors::{P2pError, Result},
    KeypairProvider,
};

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

/// Attempts to parse the provided bytes as a [`P2pCertificate`].
///
/// For this to succeed, the certificate must contain the specified extension and the signature must
/// match the embedded public key.
pub(super) fn parse<'a>(certificate: &'a CertificateDer<'_>) -> Result<P2pCertificate<'a>> {
    let certificate = parse_unverified(certificate.as_ref())?;

    certificate.verify()?;

    Ok(certificate)
}

/// An X.509 certificate with a libp2p-specific extension
/// is used to secure libp2p connections.
#[derive(Debug)]
pub(super) struct P2pCertificate<'a> {
    certificate: X509Certificate<'a>,
    /// This is a specific libp2p Public Key Extension with two values:
    /// * the public host key
    /// * a signature performed using the private host key
    extension: P2pExtension,
}

impl P2pCertificate<'_> {
    /// The [`PeerId`] of the remote peer.
    pub fn peer_id(&self) -> PeerId {
        self.extension.public_key.to_peer_id()
    }

    /// Verify the `signature` of the `message` signed by the private key corresponding to the public key stored
    /// in the certificate.
    pub fn verify_signature(
        &self,
        signature_scheme: rustls::SignatureScheme,
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let pk = self.public_key(signature_scheme)?;
        pk.verify(message, signature)
            .map_err(|_| P2pError::UnsupportPublicKey)?;

        Ok(())
    }

    /// Get a [`ring::signature::UnparsedPublicKey`] for this `signature_scheme`.
    /// Return `Error` if the `signature_scheme` does not match the public key signature
    /// and hashing algorithm or if the `signature_scheme` is not supported.
    fn public_key(
        &self,
        signature_scheme: rustls::SignatureScheme,
    ) -> Result<ring::signature::UnparsedPublicKey<&[u8]>> {
        use ring::signature;
        use rustls::SignatureScheme::*;

        let current_signature_scheme = self.signature_scheme()?;
        if signature_scheme != current_signature_scheme {
            // This certificate was signed with a different signature scheme
            return Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey.into());
        }

        let verification_algorithm: &dyn signature::VerificationAlgorithm = match signature_scheme {
            RSA_PKCS1_SHA256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            RSA_PKCS1_SHA384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            RSA_PKCS1_SHA512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            ECDSA_NISTP256_SHA256 => &signature::ECDSA_P256_SHA256_ASN1,
            ECDSA_NISTP384_SHA384 => &signature::ECDSA_P384_SHA384_ASN1,
            ECDSA_NISTP521_SHA512 => {
                // See https://github.com/briansmith/ring/issues/824
                return Err(webpki::Error::UnsupportedSignatureAlgorithm.into());
            }
            RSA_PSS_SHA256 => &signature::RSA_PSS_2048_8192_SHA256,
            RSA_PSS_SHA384 => &signature::RSA_PSS_2048_8192_SHA384,
            RSA_PSS_SHA512 => &signature::RSA_PSS_2048_8192_SHA512,
            ED25519 => &signature::ED25519,
            ED448 => {
                // See https://github.com/briansmith/ring/issues/463
                return Err(webpki::Error::UnsupportedSignatureAlgorithm.into());
            }
            // Similarly, hash functions with an output length less than 256 bits
            // MUST NOT be used, due to the possibility of collision attacks.
            // In particular, MD5 and SHA1 MUST NOT be used.
            RSA_PKCS1_SHA1 => return Err(webpki::Error::UnsupportedSignatureAlgorithm.into()),
            ECDSA_SHA1_Legacy => return Err(webpki::Error::UnsupportedSignatureAlgorithm.into()),
            _ => return Err(webpki::Error::UnsupportedSignatureAlgorithm.into()),
        };
        let spki = &self.certificate.tbs_certificate.subject_pki;
        let key = signature::UnparsedPublicKey::new(
            verification_algorithm,
            spki.subject_public_key.as_ref(),
        );

        Ok(key)
    }

    /// This method validates the certificate according to libp2p TLS 1.3 specs.
    /// The certificate MUST:
    /// 1. be valid at the time it is received by the peer;
    /// 2. use the NamedCurve encoding;
    /// 3. use hash functions with an output length not less than 256 bits;
    /// 4. be self signed;
    /// 5. contain a valid signature in the specific libp2p extension.
    fn verify(&self) -> Result<()> {
        use webpki::Error;
        // The certificate MUST have NotBefore and NotAfter fields set
        // such that the certificate is valid at the time it is received by the peer.
        if !self.certificate.validity().is_valid() {
            return Err(Error::InvalidCertValidity.into());
        }

        // Certificates MUST use the NamedCurve encoding for elliptic curve parameters.
        // Similarly, hash functions with an output length less than 256 bits
        // MUST NOT be used, due to the possibility of collision attacks.
        // In particular, MD5 and SHA1 MUST NOT be used.
        // Endpoints MUST abort the connection attempt if it is not used.
        let signature_scheme = self.signature_scheme()?;
        // Endpoints MUST abort the connection attempt if the certificate’s
        // self-signature is not valid.
        let raw_certificate = self.certificate.tbs_certificate.as_ref();
        let signature = self.certificate.signature_value.as_ref();
        // check if self signed
        self.verify_signature(signature_scheme, raw_certificate, signature)
            .map_err(|_| Error::SignatureAlgorithmMismatch)?;

        let subject_pki = self.certificate.public_key().raw;

        // The peer signs the concatenation of the string `libp2p-tls-handshake:`
        // and the public key that it used to generate the certificate carrying
        // the libp2p Public Key Extension, using its private host key.
        let mut msg = vec![];
        msg.extend(P2P_SIGNING_PREFIX);
        msg.extend(subject_pki);

        // This signature provides cryptographic proof that the peer was in possession
        // of the private host key at the time the certificate was signed.
        // Peers MUST verify the signature, and abort the connection attempt
        // if signature verification fails.
        let user_owns_sk = self
            .extension
            .public_key
            .verify(&msg, &self.extension.signature);
        if !user_owns_sk {
            return Err(Error::UnknownIssuer.into());
        }

        Ok(())
    }

    /// Return the signature scheme corresponding to [`AlgorithmIdentifier`]s
    /// of `subject_pki` and `signature_algorithm`
    /// according to <https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3>.
    fn signature_scheme(&self) -> Result<SignatureScheme> {
        // Certificates MUST use the NamedCurve encoding for elliptic curve parameters.
        // Endpoints MUST abort the connection attempt if it is not used.
        use oid_registry::*;
        use rustls::SignatureScheme::*;

        let signature_algorithm = &self.certificate.signature_algorithm;
        let pki_algorithm = &self.certificate.tbs_certificate.subject_pki.algorithm;

        if pki_algorithm.algorithm == OID_PKCS1_RSAENCRYPTION {
            if signature_algorithm.algorithm == OID_PKCS1_SHA256WITHRSA {
                return Ok(RSA_PKCS1_SHA256);
            }
            if signature_algorithm.algorithm == OID_PKCS1_SHA384WITHRSA {
                return Ok(RSA_PKCS1_SHA384);
            }
            if signature_algorithm.algorithm == OID_PKCS1_SHA512WITHRSA {
                return Ok(RSA_PKCS1_SHA512);
            }
            if signature_algorithm.algorithm == OID_PKCS1_RSASSAPSS {
                // According to https://datatracker.ietf.org/doc/html/rfc4055#section-3.1:
                // Inside of params there should be a sequence of:
                // - Hash Algorithm
                // - Mask Algorithm
                // - Salt Length
                // - Trailer Field

                // We are interested in Hash Algorithm only

                if let Ok(SignatureAlgorithm::RSASSA_PSS(params)) =
                    SignatureAlgorithm::try_from(signature_algorithm)
                {
                    let hash_oid = params.hash_algorithm_oid();
                    if hash_oid == &OID_NIST_HASH_SHA256 {
                        return Ok(RSA_PSS_SHA256);
                    }
                    if hash_oid == &OID_NIST_HASH_SHA384 {
                        return Ok(RSA_PSS_SHA384);
                    }
                    if hash_oid == &OID_NIST_HASH_SHA512 {
                        return Ok(RSA_PSS_SHA512);
                    }
                }

                // Default hash algo is SHA-1, however:
                // In particular, MD5 and SHA1 MUST NOT be used.
                return Err(webpki::Error::UnsupportedSignatureAlgorithm.into());
            }
        }

        if pki_algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY {
            let signature_param = pki_algorithm
                .parameters
                .as_ref()
                .ok_or(webpki::Error::BadDer)?
                .as_oid()
                .map_err(|_| webpki::Error::BadDer)?;
            if signature_param == OID_EC_P256
                && signature_algorithm.algorithm == OID_SIG_ECDSA_WITH_SHA256
            {
                return Ok(ECDSA_NISTP256_SHA256);
            }
            if signature_param == OID_NIST_EC_P384
                && signature_algorithm.algorithm == OID_SIG_ECDSA_WITH_SHA384
            {
                return Ok(ECDSA_NISTP384_SHA384);
            }
            if signature_param == OID_NIST_EC_P521
                && signature_algorithm.algorithm == OID_SIG_ECDSA_WITH_SHA512
            {
                return Ok(ECDSA_NISTP521_SHA512);
            }
            return Err(webpki::Error::UnsupportedSignatureAlgorithm.into());
        }

        if signature_algorithm.algorithm == OID_SIG_ED25519 {
            return Ok(ED25519);
        }
        if signature_algorithm.algorithm == OID_SIG_ED448 {
            return Ok(ED448);
        }

        Err(webpki::Error::UnsupportedSignatureAlgorithm.into())
    }
}

/// The contents of the specific libp2p extension, containing the public host key
/// and a signature performed using the private host key.
#[derive(Debug)]
pub struct P2pExtension {
    public_key: identity::PublicKey,
    /// This signature provides cryptographic proof that the peer was
    /// in possession of the private host key at the time the certificate was signed.
    signature: Vec<u8>,
}

/// Internal function that only parses but does not verify the certificate.
///
/// Useful for testing but unsuitable for production.
fn parse_unverified(der_input: &[u8]) -> Result<P2pCertificate> {
    let x509 = X509Certificate::from_der(der_input)
        .map(|(_rest_input, x509)| x509)
        .map_err(|err| match err {
            der_parser::nom::Err::Incomplete(_) => P2pError::Libp2pCert,
            der_parser::nom::Err::Error(err) => P2pError::X509Error(err),
            der_parser::nom::Err::Failure(err) => P2pError::X509Error(err),
        })?;

    let p2p_ext_oid = der_parser::oid::Oid::from(&P2P_EXT_OID)
        .expect("This is a valid OID of p2p extension; qed");

    let mut libp2p_extension = None;

    for ext in x509.extensions() {
        let oid = &ext.oid;
        if oid == &p2p_ext_oid && libp2p_extension.is_some() {
            // The extension was already parsed
            return Err(P2pError::BadDer);
        }

        if oid == &p2p_ext_oid {
            // The public host key and the signature are ANS.1-encoded
            // into the SignedKey data structure, which is carried
            // in the libp2p Public Key Extension.
            // SignedKey ::= SEQUENCE {
            //    publicKey OCTET STRING,
            //    signature OCTET STRING
            // }
            let (public_key, signature): (Vec<u8>, Vec<u8>) = yasna::decode_der(ext.value)?;
            // The publicKey field of SignedKey contains the public host key
            // of the endpoint, encoded using the following protobuf:
            // enum KeyType {
            //    RSA = 0;
            //    Ed25519 = 1;
            //    Secp256k1 = 2;
            //    ECDSA = 3;
            // }
            // message PublicKey {
            //    required KeyType Type = 1;
            //    required bytes Data = 2;
            // }
            let public_key = identity::PublicKey::try_decode_protobuf(&public_key)?;
            let ext = P2pExtension {
                public_key,
                signature,
            };
            libp2p_extension = Some(ext);
            continue;
        }

        if ext.critical {
            // Endpoints MUST abort the connection attempt if the certificate
            // contains critical extensions that the endpoint does not understand.
            return Err(P2pError::UnsupportedCriticalExtension);
        }

        // Implementations MUST ignore non-critical extensions with unknown OIDs.
    }

    // The certificate MUST contain the libp2p Public Key Extension.
    // If this extension is missing, endpoints MUST abort the connection attempt.
    let extension = libp2p_extension.ok_or(P2pError::BadDer)?;

    let certificate = P2pCertificate {
        certificate: x509,
        extension,
    };

    Ok(certificate)
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
