//! Public keys from certificates, and the signature primitives that verify with them.
//!
//! - RSA (RFC 8017): PKCS#1 v1.5 (§8.2.2) and RSASSA-PSS (§8.1.2), moduli of 1024 to 8192 bits
//!   ([`MIN_RSA_VERIFY_BITS`], [`MAX_RSA_BITS`]).
//! - ECDSA (FIPS 186-5) on P-256 and P-384, over a prehash of any length, with the signature value
//!   as DER `ECDSA-Sig-Value` (RFC 5480 §2.2, X.690) or IEEE P1363 `r || s`.
//!
//! Crate-private: RustCrypto types never leave the crate (ARCHITECTURE §A.5 gap 5).

use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey as _;
use rsa::traits::PublicKeyParts as _;
use signature::hazmat::PrehashVerifier as _;

use crate::algorithms::{DigestAlgorithm, KeyKind, MAX_RSA_BITS, MIN_RSA_VERIFY_BITS, oid};
use crate::cms::tlv::{self, TAG_INTEGER, TAG_SEQUENCE};
use crate::error::{Error, Result};

/// A public key Folioxide can verify signatures with.
#[derive(Clone, Debug)]
pub(crate) enum PublicKey {
    /// RSA, with its modulus size in bits.
    Rsa(Box<RsaPublicKey>, u32),
    /// ECDSA on P-256.
    P256(p256::ecdsa::VerifyingKey),
    /// ECDSA on P-384.
    P384(p384::ecdsa::VerifyingKey),
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PublicKey::Rsa(a, _), PublicKey::Rsa(b, _)) => a == b,
            (PublicKey::P256(a), PublicKey::P256(b)) => a == b,
            (PublicKey::P384(a), PublicKey::P384(b)) => a == b,
            _ => false,
        }
    }
}

/// Why a signature did not verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum VerifyFailure {
    /// The value does not verify with the key.
    Invalid(String),
}

impl PublicKey {
    /// Decodes a DER `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7).
    ///
    /// # Errors
    /// [`Error::Unsupported`] for key types and curves other than RSA, P-256 and P-384, and for
    /// RSA moduli outside 1024 to 8192 bits; [`Error::Certificate`] for a malformed key.
    pub(crate) fn from_spki_der(spki: &[u8]) -> Result<PublicKey> {
        let info = spki::SubjectPublicKeyInfoRef::try_from(spki)
            .map_err(|_| Error::Certificate("the subject public key info does not parse".into()))?;
        let algorithm = info.algorithm.oid.to_string();
        match algorithm.as_str() {
            oid::RSA_ENCRYPTION | oid::RSASSA_PSS => {
                let bits = rsa_modulus_bits(info.subject_public_key.raw_bytes())?;
                if !(MIN_RSA_VERIFY_BITS..=MAX_RSA_BITS).contains(&bits) {
                    return Err(Error::Unsupported(format!(
                        "RSA keys of {bits} bits are not supported (\
                         {MIN_RSA_VERIFY_BITS} to {MAX_RSA_BITS} bits are)"
                    )));
                }
                let key = if algorithm == oid::RSA_ENCRYPTION {
                    RsaPublicKey::from_public_key_der(spki)
                } else {
                    // An id-RSASSA-PSS key: the same RSAPublicKey inside (RFC 4055 §1.2).
                    use rsa::pkcs1::DecodeRsaPublicKey as _;
                    RsaPublicKey::from_pkcs1_der(info.subject_public_key.raw_bytes())
                        .map_err(|_| rsa::pkcs8::spki::Error::KeyMalformed)
                }
                .map_err(|_| Error::Certificate("the RSA public key does not parse".into()))?;
                Ok(PublicKey::Rsa(Box::new(key), bits))
            }
            oid::EC_PUBLIC_KEY => {
                let curve = info
                    .algorithm
                    .parameters_oid()
                    .map_err(|_| Error::Certificate("the EC key names no curve".into()))?
                    .to_string();
                match curve.as_str() {
                    oid::PRIME256V1 => p256::ecdsa::VerifyingKey::from_public_key_der(spki)
                        .map(PublicKey::P256)
                        .map_err(|_| {
                            Error::Certificate("the P-256 public key does not parse".into())
                        }),
                    oid::SECP384R1 => p384::ecdsa::VerifyingKey::from_public_key_der(spki)
                        .map(PublicKey::P384)
                        .map_err(|_| {
                            Error::Certificate("the P-384 public key does not parse".into())
                        }),
                    other => Err(Error::Unsupported(format!(
                        "EC keys on curve {} are not supported (P-256 and P-384 are)",
                        curve_name(other)
                    ))),
                }
            }
            other => Err(Error::Unsupported(format!(
                "{} keys are not supported (RSA, P-256 and P-384 are)",
                key_algorithm_name(other)
            ))),
        }
    }

    /// The kind and size of the key.
    pub(crate) fn kind(&self) -> KeyKind {
        match self {
            PublicKey::Rsa(_, bits) => KeyKind::Rsa { bits: *bits },
            PublicKey::P256(_) => KeyKind::EcP256,
            PublicKey::P384(_) => KeyKind::EcP384,
        }
    }

    /// For ECDSA keys, the size of the curve's field in bytes (32 for P-256, 48 for P-384).
    pub(crate) fn ecdsa_field_len(&self) -> Option<usize> {
        match self {
            PublicKey::P256(_) => Some(32),
            PublicKey::P384(_) => Some(48),
            PublicKey::Rsa(..) => None,
        }
    }

    /// Verifies an RSASSA-PKCS1-v1_5 signature over `hashed` (RFC 8017 §8.2.2). A signature
    /// shorter than the modulus is left-padded with zeros first (as OpenSSL and pyHanko do); a
    /// longer one is invalid. Returns the padded signature.
    pub(crate) fn verify_rsa_pkcs1v15(
        &self,
        digest: DigestAlgorithm,
        hashed: &[u8],
        signature: &[u8],
    ) -> std::result::Result<Vec<u8>, VerifyFailure> {
        let PublicKey::Rsa(key, _) = self else {
            return Err(VerifyFailure::Invalid(
                "an RSA signature with a non-RSA key".into(),
            ));
        };
        let padded = rsa_left_pad(signature, key.size()).ok_or_else(|| {
            VerifyFailure::Invalid("the RSA signature is longer than the modulus".into())
        })?;
        let scheme = match digest {
            DigestAlgorithm::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
            DigestAlgorithm::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
            DigestAlgorithm::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
            DigestAlgorithm::Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
        };
        key.verify(scheme, hashed, &padded)
            .map(|()| padded)
            .map_err(|_| {
                VerifyFailure::Invalid("the RSA PKCS#1 v1.5 signature does not verify".into())
            })
    }

    /// Verifies an RSASSA-PSS signature over `hashed` with MGF1 on the same digest and the
    /// given salt length (RFC 8017 §8.1.2, §9.1.2).
    pub(crate) fn verify_rsa_pss(
        &self,
        digest: DigestAlgorithm,
        salt_len: usize,
        hashed: &[u8],
        signature: &[u8],
    ) -> std::result::Result<(), VerifyFailure> {
        let PublicKey::Rsa(key, _) = self else {
            return Err(VerifyFailure::Invalid(
                "an RSA-PSS signature with a non-RSA key".into(),
            ));
        };
        let padded = rsa_left_pad(signature, key.size()).ok_or_else(|| {
            VerifyFailure::Invalid("the RSA signature is longer than the modulus".into())
        })?;
        if salt_len > key.size() {
            return Err(VerifyFailure::Invalid(
                "the RSA-PSS salt is longer than the modulus".into(),
            ));
        }
        let result = match digest {
            DigestAlgorithm::Sha256 => key.verify(
                rsa::Pss::<sha2::Sha256>::new_with_salt(salt_len),
                hashed,
                &padded,
            ),
            DigestAlgorithm::Sha384 => key.verify(
                rsa::Pss::<sha2::Sha384>::new_with_salt(salt_len),
                hashed,
                &padded,
            ),
            DigestAlgorithm::Sha512 => key.verify(
                rsa::Pss::<sha2::Sha512>::new_with_salt(salt_len),
                hashed,
                &padded,
            ),
            DigestAlgorithm::Sha1 => key.verify(
                rsa::Pss::<sha1::Sha1>::new_with_salt(salt_len),
                hashed,
                &padded,
            ),
        };
        result.map_err(|_| VerifyFailure::Invalid("the RSA-PSS signature does not verify".into()))
    }

    /// Verifies an ECDSA signature over the prehash `hashed` (FIPS 186-5 §6.4.2; the hash is
    /// truncated to the order's bit length, so any digest pairs with any curve).
    ///
    /// `signature` may be a DER `ECDSA-Sig-Value` (non-minimal INTEGERs accepted) or IEEE P1363
    /// `r || s` of exactly twice the field size; when the bytes admit both, both are tried.
    /// Returns the minimal DER encoding of the interpretation that verifies.
    pub(crate) fn verify_ecdsa(
        &self,
        hashed: &[u8],
        signature: &[u8],
    ) -> std::result::Result<Vec<u8>, VerifyFailure> {
        let field = match self {
            PublicKey::P256(_) => 32,
            PublicKey::P384(_) => 48,
            PublicKey::Rsa(..) => {
                return Err(VerifyFailure::Invalid(
                    "an ECDSA signature with an RSA key".into(),
                ));
            }
        };
        let candidates = ecdsa_candidates(signature, field);
        if candidates.is_empty() {
            return Err(VerifyFailure::Invalid(format!(
                "the ECDSA signature ({} bytes) is neither DER nor IEEE P1363",
                signature.len()
            )));
        }
        for r_s in &candidates {
            let ok = match self {
                PublicKey::P256(key) => p256::ecdsa::Signature::from_slice(r_s)
                    .is_ok_and(|sig| key.verify_prehash(hashed, &sig).is_ok()),
                PublicKey::P384(key) => p384::ecdsa::Signature::from_slice(r_s)
                    .is_ok_and(|sig| key.verify_prehash(hashed, &sig).is_ok()),
                PublicKey::Rsa(..) => false,
            };
            if ok {
                return Ok(ecdsa_der_from_fixed(r_s, field));
            }
        }
        Err(VerifyFailure::Invalid(
            "the ECDSA signature does not verify".into(),
        ))
    }
}

/// The bit length of the modulus of a DER `RSAPublicKey ::= SEQUENCE { modulus INTEGER,
/// publicExponent INTEGER }` (RFC 8017 Appendix A.1.1).
pub(crate) fn rsa_modulus_bits(rsa_public_key: &[u8]) -> Result<u32> {
    let malformed = || Error::Certificate("the RSA public key does not parse".into());
    let seq = tlv::read_exact(rsa_public_key, 4).map_err(|_| malformed())?;
    if seq.tag != TAG_SEQUENCE {
        return Err(malformed());
    }
    let modulus = tlv::children(rsa_public_key, &seq, 0, 4)
        .next()
        .ok_or_else(malformed)?
        .map_err(|_| malformed())?;
    if modulus.tag != TAG_INTEGER {
        return Err(malformed());
    }
    Ok(magnitude_bits(modulus.content(rsa_public_key)))
}

/// The bit length of a big-endian unsigned magnitude.
pub(crate) fn magnitude_bits(magnitude: &[u8]) -> u32 {
    let skip = magnitude.iter().take_while(|&&b| b == 0).count();
    match magnitude.get(skip..) {
        Some([first, rest @ ..]) => {
            let rest_bits = u32::try_from(rest.len())
                .unwrap_or(u32::MAX / 16)
                .saturating_mul(8);
            rest_bits.saturating_add(8 - first.leading_zeros())
        }
        _ => 0,
    }
}

/// `signature` left-padded with zeros to `k` bytes, or `None` when it is longer (after
/// stripping leading zeros) than `k`.
pub(crate) fn rsa_left_pad(signature: &[u8], k: usize) -> Option<Vec<u8>> {
    let skip = signature
        .len()
        .saturating_sub(k)
        .min(signature.iter().take_while(|&&b| b == 0).count());
    let significant = signature.get(skip..)?;
    if significant.len() > k {
        return None;
    }
    let mut out = vec![0u8; k - significant.len()];
    out.extend_from_slice(significant);
    Some(out)
}

/// The fixed-size `r || s` interpretations of an ECDSA signature value for a field of `field`
/// bytes, DER first (M3 brief §4.3 "Normalisation"): a DER `ECDSA-Sig-Value` that consumes every
/// byte (non-minimal INTEGERs accepted), then IEEE P1363 when the length is exactly `2 * field`.
pub(crate) fn ecdsa_candidates(signature: &[u8], field: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(2);
    if let Some(r_s) = ecdsa_der_to_fixed(signature, field) {
        out.push(r_s);
    }
    if signature.len() == 2 * field && out.first().is_none_or(|first| first != signature) {
        out.push(signature.to_vec());
    }
    out
}

/// Decodes `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` into `r || s` with each
/// half left-padded to `field` bytes. Accepts redundant leading zero octets in the INTEGERs
/// (some KMSes emit them) and any definite length form, but requires the SEQUENCE to consume
/// every byte and both values to be positive and to fit the field.
pub(crate) fn ecdsa_der_to_fixed(signature: &[u8], field: usize) -> Option<Vec<u8>> {
    let seq = tlv::read_exact(signature, 2).ok()?;
    if seq.tag != TAG_SEQUENCE || seq.indefinite {
        return None;
    }
    let ints = tlv::children_vec(signature, &seq, 0, 2, 3).ok()?;
    let [r, s] = ints.as_slice() else {
        return None;
    };
    let mut out = Vec::with_capacity(2 * field);
    for int in [r, s] {
        if int.tag != TAG_INTEGER {
            return None;
        }
        let content = int.content(signature);
        // A negative value (high bit set without a leading zero) is not a valid r or s.
        if content.first().is_none_or(|&b| b & 0x80 != 0) {
            return None;
        }
        let skip = content.iter().take_while(|&&b| b == 0).count();
        let magnitude = content.get(skip..)?;
        if magnitude.is_empty() || magnitude.len() > field {
            return None;
        }
        out.extend(std::iter::repeat_n(0u8, field - magnitude.len()));
        out.extend_from_slice(magnitude);
    }
    Some(out)
}

/// The minimal DER `ECDSA-Sig-Value` of a fixed-size `r || s` (X.690 §8.3: no redundant
/// leading octets, a zero octet before a high bit).
pub(crate) fn ecdsa_der_from_fixed(r_s: &[u8], field: usize) -> Vec<u8> {
    let r = r_s.get(..field).unwrap_or_default();
    let s = r_s.get(field..).unwrap_or_default();
    let r = tlv::unsigned_integer(r);
    let s = tlv::unsigned_integer(s);
    tlv::tlv_parts(TAG_SEQUENCE, &[&r, &s])
}

/// A readable name for a SubjectPublicKeyInfo algorithm OID.
fn key_algorithm_name(dotted: &str) -> String {
    match dotted {
        "1.3.101.112" => "Ed25519".to_owned(),
        "1.3.101.113" => "Ed448".to_owned(),
        "1.2.840.10040.4.1" => "DSA".to_owned(),
        other => format!("OID {other}"),
    }
}

/// A readable name for a named-curve OID.
pub(crate) fn curve_name(dotted: &str) -> String {
    match dotted {
        oid::PRIME256V1 => "P-256".to_owned(),
        oid::SECP384R1 => "P-384".to_owned(),
        "1.3.132.0.35" => "P-521".to_owned(),
        "1.3.132.0.10" => "secp256k1".to_owned(),
        other => other.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_padding() {
        assert_eq!(rsa_left_pad(&[1, 2], 4), Some(vec![0, 0, 1, 2]));
        assert_eq!(rsa_left_pad(&[0, 0, 1, 2], 4), Some(vec![0, 0, 1, 2]));
        assert_eq!(
            rsa_left_pad(&[0, 0, 0, 1, 2], 4),
            Some(vec![0, 0, 0, 1, 2][1..].to_vec())
        );
        assert_eq!(rsa_left_pad(&[1, 0, 0, 0, 0], 4), None);
        assert_eq!(rsa_left_pad(&[], 2), Some(vec![0, 0]));
    }

    #[test]
    fn bits() {
        assert_eq!(magnitude_bits(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(magnitude_bits(&[0x01]), 1);
        assert_eq!(magnitude_bits(&[0x00]), 0);
        assert_eq!(magnitude_bits(&[]), 0);
        let mut n = vec![0x00, 0xC0];
        n.extend([0u8; 255]);
        assert_eq!(magnitude_bits(&n), 2048);
    }

    #[test]
    fn ecdsa_value_forms() {
        let field = 4;
        // r = 0x80 (needs a sign octet), s = 0x01 with redundant leading zeros.
        let lax = [
            0x30, 0x09, 0x02, 0x02, 0x00, 0x80, 0x02, 0x03, 0x00, 0x00, 0x01,
        ];
        let fixed = ecdsa_der_to_fixed(&lax, field).unwrap();
        assert_eq!(fixed, [0, 0, 0, 0x80, 0, 0, 0, 1]);
        assert_eq!(
            ecdsa_der_from_fixed(&fixed, field),
            [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01]
        );
        // Negative, too long, trailing bytes, three INTEGERs: not DER signatures.
        assert!(
            ecdsa_der_to_fixed(&[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01], field).is_none()
        );
        assert!(
            ecdsa_der_to_fixed(&[0x30, 0x08, 0x02, 0x03, 1, 2, 3, 0x02, 0x01, 0x01], 2).is_none()
        );
        assert!(
            ecdsa_der_to_fixed(
                &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00],
                field
            )
            .is_none()
        );
        assert!(
            ecdsa_der_to_fixed(
                &[0x30, 0x09, 0x02, 0x01, 1, 0x02, 0x01, 1, 0x02, 0x01, 1],
                field
            )
            .is_none()
        );
        // Both readings: an 8-byte value that is also DER.
        let both = [0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x06];
        assert_eq!(ecdsa_candidates(&both, 4).len(), 2);
        assert_eq!(ecdsa_candidates(&[7; 8], 4), vec![vec![7; 8]]);
        assert!(ecdsa_candidates(&[7; 7], 4).is_empty());
    }
}
