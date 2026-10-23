//! Private keys: decoding PKCS#8, PKCS#1 and SEC1 DER, and signing.
//!
//! Every decoded key lives in RustCrypto types that wipe themselves when dropped
//! (`RsaPrivateKey`, `ecdsa::SigningKey`); the DER buffers they come from are
//! [`Zeroizing`](zeroize::Zeroizing) at the call sites.

use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts as _;
use signature::RandomizedSigner as _;
use signature::hazmat::PrehashSigner as _;

use crate::algorithms::{
    DigestAlgorithm, KeyKind, MAX_RSA_BITS, MIN_RSA_SIGNING_BITS, check_signing_combination, oid,
};
use crate::error::{Error, Result};
use crate::keys::public::{PublicKey, curve_name, magnitude_bits};

/// A private key Folioxide can sign with.
pub(crate) enum PrivateKey {
    /// RSA, with its modulus size in bits.
    Rsa(Box<RsaPrivateKey>, u32),
    /// ECDSA on P-256.
    P256(p256::ecdsa::SigningKey),
    /// ECDSA on P-384.
    P384(p384::ecdsa::SigningKey),
}

/// The RNG source of an RSA signature (the blinding of RFC 8017 §5.1.2, M3 brief R-9).
pub(crate) enum Rng<'a> {
    /// The operating system's RNG (`getrandom` `SysRng`).
    #[cfg(feature = "sys-rng")]
    System,
    /// A caller-supplied RNG.
    Custom(&'a mut (dyn rand_core::CryptoRng + Send)),
    /// No RNG: RSA signing is refused.
    #[cfg_attr(feature = "sys-rng", allow(dead_code))]
    None,
}

impl PrivateKey {
    /// Decodes an unencrypted PKCS#8 `PrivateKeyInfo` (RFC 5208 §5, RFC 5958 §2).
    ///
    /// # Errors
    /// [`Error::KeyLoad`] for malformed keys and RSA keys outside 2048 to 8192 bits,
    /// [`Error::Unsupported`] for other key types and curves.
    pub(crate) fn from_pkcs8_der(der: &[u8]) -> Result<PrivateKey> {
        use pkcs8::DecodePrivateKey as _;
        let info = pkcs8::PrivateKeyInfoRef::try_from(der)
            .map_err(|_| Error::KeyLoad("the PKCS#8 private key does not parse".into()))?;
        let algorithm = info.algorithm.oid.to_string();
        match algorithm.as_str() {
            oid::RSA_ENCRYPTION => {
                let key = RsaPrivateKey::from_pkcs8_der(der)
                    .map_err(|_| Error::KeyLoad("the RSA private key does not parse".into()))?;
                PrivateKey::rsa(key)
            }
            oid::EC_PUBLIC_KEY => {
                let curve = info
                    .algorithm
                    .parameters_oid()
                    .map_err(|_| Error::KeyLoad("the EC private key names no curve".into()))?
                    .to_string();
                match curve.as_str() {
                    oid::PRIME256V1 => p256::ecdsa::SigningKey::from_pkcs8_der(der)
                        .map(PrivateKey::P256)
                        .map_err(|_| Error::KeyLoad("the P-256 private key does not parse".into())),
                    oid::SECP384R1 => p384::ecdsa::SigningKey::from_pkcs8_der(der)
                        .map(PrivateKey::P384)
                        .map_err(|_| Error::KeyLoad("the P-384 private key does not parse".into())),
                    other => Err(unsupported_curve(other)),
                }
            }
            oid::RSASSA_PSS => Err(Error::Unsupported(
                "RSA-PSS keys are not supported for signing; use an rsaEncryption key".into(),
            )),
            "1.3.101.112" => Err(Error::Unsupported("Ed25519 keys are not supported".into())),
            "1.3.101.113" => Err(Error::Unsupported("Ed448 keys are not supported".into())),
            "1.2.840.10040.4.1" => Err(Error::Unsupported("DSA keys are not supported".into())),
            other => Err(Error::Unsupported(format!(
                "private keys of type {other} are not supported (RSA, P-256 and P-384 are)"
            ))),
        }
    }

    /// Decodes a PKCS#1 `RSAPrivateKey` (RFC 8017 Appendix A.1.2).
    ///
    /// # Errors
    /// As [`PrivateKey::from_pkcs8_der`].
    pub(crate) fn from_pkcs1_der(der: &[u8]) -> Result<PrivateKey> {
        use rsa::pkcs1::DecodeRsaPrivateKey as _;
        let key = RsaPrivateKey::from_pkcs1_der(der)
            .map_err(|_| Error::KeyLoad("the PKCS#1 RSA private key does not parse".into()))?;
        PrivateKey::rsa(key)
    }

    /// Decodes a SEC1 `ECPrivateKey` (RFC 5915 §3). The curve comes from its parameters, or from
    /// the key length when they are absent.
    ///
    /// # Errors
    /// As [`PrivateKey::from_pkcs8_der`].
    pub(crate) fn from_sec1_der(der: &[u8]) -> Result<PrivateKey> {
        let parsed = sec1::EcPrivateKey::try_from(der)
            .map_err(|_| Error::KeyLoad("the SEC1 EC private key does not parse".into()))?;
        let curve = match parsed.parameters.and_then(|p| p.named_curve()) {
            Some(curve) => curve.to_string(),
            None => match parsed.private_key.len() {
                32 => oid::PRIME256V1.to_owned(),
                48 => oid::SECP384R1.to_owned(),
                _ => {
                    return Err(Error::KeyLoad(
                        "the SEC1 EC private key names no curve".into(),
                    ));
                }
            },
        };
        match curve.as_str() {
            oid::PRIME256V1 => p256::SecretKey::from_sec1_der(der)
                .map(|k| PrivateKey::P256(k.into()))
                .map_err(|_| Error::KeyLoad("the P-256 private key does not parse".into())),
            oid::SECP384R1 => p384::SecretKey::from_sec1_der(der)
                .map(|k| PrivateKey::P384(k.into()))
                .map_err(|_| Error::KeyLoad("the P-384 private key does not parse".into())),
            other => Err(unsupported_curve(other)),
        }
    }

    /// Wraps an RSA key after checking its size (M3 brief §3.1, D-12).
    fn rsa(key: RsaPrivateKey) -> Result<PrivateKey> {
        let bits = magnitude_bits(&key.n().to_be_bytes());
        if !(MIN_RSA_SIGNING_BITS..=MAX_RSA_BITS).contains(&bits) {
            return Err(Error::KeyLoad(format!(
                "RSA keys must have {MIN_RSA_SIGNING_BITS} to {MAX_RSA_BITS} bits to sign, \
                 this one has {bits}"
            )));
        }
        Ok(PrivateKey::Rsa(Box::new(key), bits))
    }

    /// The kind and size of the key.
    pub(crate) fn kind(&self) -> KeyKind {
        match self {
            PrivateKey::Rsa(_, bits) => KeyKind::Rsa { bits: *bits },
            PrivateKey::P256(_) => KeyKind::EcP256,
            PrivateKey::P384(_) => KeyKind::EcP384,
        }
    }

    /// Whether `public` is this key's public half.
    pub(crate) fn matches(&self, public: &PublicKey) -> bool {
        match (self, public) {
            (PrivateKey::Rsa(key, _), PublicKey::Rsa(pk, ..)) => {
                // Compare the values, independent of the integers' internal precision.
                let strip = |b: Box<[u8]>| {
                    let skip = b.iter().take_while(|&&x| x == 0).count();
                    b.get(skip..).unwrap_or_default().to_vec()
                };
                let own = key.as_public_key();
                strip(own.n().to_be_bytes()) == strip(pk.n().to_be_bytes())
                    && strip(own.e().to_be_bytes()) == strip(pk.e().to_be_bytes())
            }
            (PrivateKey::P256(key), PublicKey::P256(pk)) => key.verifying_key() == pk,
            (PrivateKey::P384(key), PublicKey::P384(pk)) => key.verifying_key() == pk,
            _ => false,
        }
    }

    /// Signs `to_be_signed`, hashing it with `digest`.
    ///
    /// - RSA: RSASSA-PKCS1-v1_5 (RFC 8017 §8.2.1) through the blinded
    ///   `RandomizedSigner::try_sign_with_rng` path (M3 brief R-9); exactly the modulus length.
    /// - ECDSA: RFC 6979 deterministic `k`; `signature::Signer` with the curve's own digest,
    ///   else `PrehashSigner::sign_prehash(H(tbs))`. The value is a minimal DER
    ///   `ECDSA-Sig-Value`.
    ///
    /// # Errors
    /// [`Error::InvalidArgument`] for SHA-1 or a missing RNG, [`Error::Crypto`] when the
    /// primitive or the RNG fails.
    pub(crate) fn sign(
        &self,
        digest: DigestAlgorithm,
        to_be_signed: &[u8],
        rng: Rng<'_>,
    ) -> Result<Vec<u8>> {
        check_signing_combination(self.kind(), digest)?;
        match self {
            PrivateKey::Rsa(key, _) => {
                let signature = match digest {
                    DigestAlgorithm::Sha256 => rsa_sign::<sha2::Sha256>(key, to_be_signed, rng),
                    DigestAlgorithm::Sha384 => rsa_sign::<sha2::Sha384>(key, to_be_signed, rng),
                    DigestAlgorithm::Sha512 => rsa_sign::<sha2::Sha512>(key, to_be_signed, rng),
                    // Refused by check_signing_combination above.
                    DigestAlgorithm::Sha1 => Err(Error::InvalidArgument(
                        "sha1 is not allowed for signing".into(),
                    )),
                }?;
                crate::keys::public::rsa_left_pad(&signature, key.size()).ok_or_else(|| {
                    Error::Crypto("the RSA signature is longer than the modulus".into())
                })
            }
            PrivateKey::P256(key) => {
                let signature: p256::ecdsa::Signature = if digest == DigestAlgorithm::Sha256 {
                    signature::Signer::try_sign(key, to_be_signed)
                } else {
                    key.sign_prehash(&digest.digest(&[to_be_signed]))
                }
                .map_err(|_| Error::Crypto("ECDSA signing failed".into()))?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
            PrivateKey::P384(key) => {
                let signature: p384::ecdsa::Signature = if digest == DigestAlgorithm::Sha384 {
                    signature::Signer::try_sign(key, to_be_signed)
                } else {
                    key.sign_prehash(&digest.digest(&[to_be_signed]))
                }
                .map_err(|_| Error::Crypto("ECDSA signing failed".into()))?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
        }
    }
}

/// RSASSA-PKCS1-v1_5 with digest `D` through the blinded path.
fn rsa_sign<D>(key: &RsaPrivateKey, to_be_signed: &[u8], rng: Rng<'_>) -> Result<Vec<u8>>
where
    D: sha2::Digest + const_oid::AssociatedOid,
{
    let signing_key = rsa::pkcs1v15::SigningKey::<D>::new(key.clone());
    let signature = match rng {
        #[cfg(feature = "sys-rng")]
        Rng::System => signing_key.try_sign_with_rng(&mut getrandom::SysRng, to_be_signed),
        Rng::Custom(rng) => signing_key.try_sign_with_rng(rng, to_be_signed),
        Rng::None => {
            return Err(Error::InvalidArgument(
                "RSA signing needs an RNG for blinding: enable the `sys-rng` feature or call \
                 LocalSigner::with_rng"
                    .into(),
            ));
        }
    }
    .map_err(|_| Error::Crypto("RSA signing failed".into()))?;
    Ok(Box::<[u8]>::from(signature).into_vec())
}

fn unsupported_curve(dotted: &str) -> Error {
    Error::Unsupported(format!(
        "EC keys on curve {} are not supported (P-256 and P-384 are)",
        curve_name(dotted)
    ))
}
