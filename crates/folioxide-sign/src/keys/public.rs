//! Public keys from certificates, and the signature primitives that verify with them.
//!
//! - RSA (RFC 8017): PKCS#1 v1.5 (§8.2.2) and RSASSA-PSS (§8.1.2), moduli of 1024 to 8192 bits
//!   ([`MIN_RSA_VERIFY_BITS`], [`MAX_RSA_BITS`]). A key whose SubjectPublicKeyInfo algorithm is
//!   `id-RSASSA-PSS` verifies RSASSA-PSS signatures only, with the parameters it states when it
//!   states them ([`RsaKeyUse`]; RFC 4055 §1.2, §3.1; manager ruling R-22 (b)).
//! - ECDSA (FIPS 186-5) on P-256 and P-384, over a prehash of any length: an embedded signature
//!   value must be a strict DER `ECDSA-Sig-Value` (RFC 5480 §2.2, X.690; as OpenSSL verifies), a
//!   value a signer hands to `finish` may also be IEEE P1363 `r || s` or non-minimal DER, which
//!   is normalised before it is embedded.
//!
//! Crate-private: RustCrypto types never leave the crate (ARCHITECTURE §A.5 gap 5).

use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey as _;
use rsa::traits::PublicKeyParts as _;
use signature::hazmat::PrehashVerifier as _;

use crate::algorithms::{DigestAlgorithm, KeyKind, MAX_RSA_BITS, MIN_RSA_VERIFY_BITS, oid};
use crate::cms::tlv::{self, TAG_INTEGER, TAG_SEQUENCE};
use crate::error::{Error, Result};

/// What an RSA public key may verify, from the algorithm of its SubjectPublicKeyInfo (RFC 4055
/// §1.2: "a public key associated with id-RSASSA-PSS ... MUST only be used with the RSASSA-PSS
/// signature scheme"; §3.1: when the parameters are present they fix the scheme's parameters).
///
/// pyhanko-certvalidator refuses a PKCS #1 v1.5 signature with an `id-RSASSA-PSS` key (an
/// assertion in `_validate_raw`) and a PSS signature whose parameters differ from the key's
/// (`PSSParameterMismatch`); OpenSSL refuses the first (`illegal or unsupported padding mode`)
/// and treats the key's salt length as a minimum. Folioxide requires equal parameters, as
/// pyHanko does (M4 QA round 5 finding 36).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RsaKeyUse {
    /// `rsaEncryption`: RSASSA-PKCS1-v1_5 and RSASSA-PSS.
    Any,
    /// `id-RSASSA-PSS` without parameters: RSASSA-PSS with any parameters.
    PssOnly,
    /// `id-RSASSA-PSS` with `RSASSA-PSS-params`: RSASSA-PSS with exactly this hash (MGF1 on the
    /// same hash, trailer field 1) and salt length.
    PssWith {
        /// The hash, also MGF1's.
        hash: DigestAlgorithm,
        /// The salt length in octets.
        salt_len: usize,
    },
}

/// A public key Folioxide can verify signatures with.
#[derive(Clone, Debug)]
pub(crate) enum PublicKey {
    /// RSA, with its modulus size in bits and the signatures it may verify.
    Rsa(Box<RsaPublicKey>, u32, RsaKeyUse),
    /// ECDSA on P-256.
    P256(p256::ecdsa::VerifyingKey),
    /// ECDSA on P-384.
    P384(p384::ecdsa::VerifyingKey),
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PublicKey::Rsa(a, ..), PublicKey::Rsa(b, ..)) => a == b,
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
    /// Decodes a DER `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7). An `id-RSASSA-PSS` key keeps
    /// the restriction of its algorithm ([`RsaKeyUse`]).
    ///
    /// # Errors
    /// [`Error::Unsupported`] for key types and curves other than RSA, P-256 and P-384, and for
    /// RSA moduli outside 1024 to 8192 bits; [`Error::Certificate`] for a malformed key,
    /// including `id-RSASSA-PSS` parameters that are not `RSASSA-PSS-params` Folioxide can
    /// verify with (RFC 4055 §3.1).
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
                let usage = if algorithm == oid::RSA_ENCRYPTION {
                    RsaKeyUse::Any
                } else {
                    rsa_pss_key_use(info.algorithm.parameters.as_ref())?
                };
                let key = if algorithm == oid::RSA_ENCRYPTION {
                    RsaPublicKey::from_public_key_der(spki)
                } else {
                    // An id-RSASSA-PSS key: the same RSAPublicKey inside (RFC 4055 §1.2).
                    use rsa::pkcs1::DecodeRsaPublicKey as _;
                    RsaPublicKey::from_pkcs1_der(info.subject_public_key.raw_bytes())
                        .map_err(|_| rsa::pkcs8::spki::Error::KeyMalformed)
                }
                .map_err(|_| Error::Certificate("the RSA public key does not parse".into()))?;
                Ok(PublicKey::Rsa(Box::new(key), bits, usage))
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
            PublicKey::Rsa(_, bits, _) => KeyKind::Rsa { bits: *bits },
            PublicKey::P256(_) => KeyKind::EcP256,
            PublicKey::P384(_) => KeyKind::EcP384,
        }
    }

    /// Whether this is an RSA key restricted to RSASSA-PSS (`id-RSASSA-PSS`, RFC 4055 §1.2),
    /// which cannot verify the PKCS #1 v1.5 signatures Folioxide makes with RSA keys.
    pub(crate) fn is_rsa_pss_only(&self) -> bool {
        matches!(self, PublicKey::Rsa(_, _, usage) if *usage != RsaKeyUse::Any)
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
    /// longer one is invalid. Returns the padded signature. An `id-RSASSA-PSS` key verifies no
    /// PKCS #1 v1.5 signature (RFC 4055 §1.2).
    pub(crate) fn verify_rsa_pkcs1v15(
        &self,
        digest: DigestAlgorithm,
        hashed: &[u8],
        signature: &[u8],
    ) -> std::result::Result<Vec<u8>, VerifyFailure> {
        let PublicKey::Rsa(key, _, usage) = self else {
            return Err(VerifyFailure::Invalid(
                "an RSA signature with a non-RSA key".into(),
            ));
        };
        if *usage != RsaKeyUse::Any {
            return Err(VerifyFailure::Invalid(
                "the key is an id-RSASSA-PSS key, which RFC 4055 §1.2 restricts to RSASSA-PSS \
                 signatures, and this is an RSA PKCS#1 v1.5 signature"
                    .into(),
            ));
        }
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
    /// given salt length (RFC 8017 §8.1.2, §9.1.2). An `id-RSASSA-PSS` key with parameters
    /// verifies only signatures with exactly those parameters (RFC 4055 §3.1).
    pub(crate) fn verify_rsa_pss(
        &self,
        digest: DigestAlgorithm,
        salt_len: usize,
        hashed: &[u8],
        signature: &[u8],
    ) -> std::result::Result<(), VerifyFailure> {
        let PublicKey::Rsa(key, _, usage) = self else {
            return Err(VerifyFailure::Invalid(
                "an RSA-PSS signature with a non-RSA key".into(),
            ));
        };
        if let RsaKeyUse::PssWith {
            hash,
            salt_len: key_salt,
        } = *usage
            && (hash != digest || key_salt != salt_len)
        {
            return Err(VerifyFailure::Invalid(format!(
                "the RSASSA-PSS parameters of the signature ({digest}, salt {salt_len}) differ \
                 from the ones its id-RSASSA-PSS key allows ({hash}, salt {key_salt}; RFC 4055 \
                 §3.1)"
            )));
        }
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
    /// truncated to the order's bit length, so any digest pairs with any curve), **leniently**:
    /// for normalising a signature value a signer handed over (`finish`, M3 brief §4.3
    /// "Normalisation"), never for verifying an embedded one ([`PublicKey::verify_ecdsa_der`]).
    ///
    /// `signature` may be a DER `ECDSA-Sig-Value` (non-minimal INTEGERs accepted) or IEEE P1363
    /// `r || s` of exactly twice the field size; when the bytes admit both, both are tried.
    /// Returns the minimal DER encoding of the interpretation that verifies.
    pub(crate) fn verify_ecdsa(
        &self,
        hashed: &[u8],
        signature: &[u8],
    ) -> std::result::Result<Vec<u8>, VerifyFailure> {
        let field = self.ecdsa_field_or_err()?;
        let candidates = ecdsa_candidates(signature, field);
        if candidates.is_empty() {
            return Err(VerifyFailure::Invalid(format!(
                "the ECDSA signature ({} bytes) is neither DER nor IEEE P1363",
                signature.len()
            )));
        }
        for r_s in &candidates {
            if self.verify_ecdsa_fixed(hashed, r_s) {
                return Ok(ecdsa_der_from_fixed(r_s, field));
            }
        }
        Err(VerifyFailure::Invalid(
            "the ECDSA signature does not verify".into(),
        ))
    }

    /// Verifies an embedded ECDSA signature value over the prehash `hashed` **strictly**: the
    /// value must be the DER encoding of `ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
    /// (RFC 5753 §7.2; RFC 5480 §2.2 for certificates), minimal in every length and INTEGER
    /// (X.690 §10.1, §8.3.2), with positive values that fit the curve and nothing after it
    /// ([`ecdsa_strict_der_to_fixed`]). OpenSSL's `ECDSA_verify` re-encodes the decoded value
    /// and compares, so pyHanko, `openssl cms -verify` and `openssl ts -verify` reject IEEE P1363
    /// `r || s` and redundant leading zero octets; the verifier must not be more lenient
    /// (DECISIONS D10.1; M4 QA finding F1). A high `s` is accepted, as by both.
    pub(crate) fn verify_ecdsa_der(
        &self,
        hashed: &[u8],
        signature: &[u8],
    ) -> std::result::Result<(), VerifyFailure> {
        let field = self.ecdsa_field_or_err()?;
        let Some(r_s) = ecdsa_strict_der_to_fixed(signature, field) else {
            return Err(VerifyFailure::Invalid(format!(
                "the ECDSA signature ({} bytes) is not the DER encoding of an ECDSA-Sig-Value \
                 (minimal positive INTEGERs r and s, RFC 5753 §7.2)",
                signature.len()
            )));
        };
        if self.verify_ecdsa_fixed(hashed, &r_s) {
            Ok(())
        } else {
            Err(VerifyFailure::Invalid(
                "the ECDSA signature does not verify".into(),
            ))
        }
    }

    /// The field size of an ECDSA key, or the failure for an RSA key.
    fn ecdsa_field_or_err(&self) -> std::result::Result<usize, VerifyFailure> {
        self.ecdsa_field_len()
            .ok_or_else(|| VerifyFailure::Invalid("an ECDSA signature with an RSA key".into()))
    }

    /// Whether the fixed-size `r || s` verifies over the prehash `hashed`.
    fn verify_ecdsa_fixed(&self, hashed: &[u8], r_s: &[u8]) -> bool {
        match self {
            PublicKey::P256(key) => p256::ecdsa::Signature::from_slice(r_s)
                .is_ok_and(|sig| key.verify_prehash(hashed, &sig).is_ok()),
            PublicKey::P384(key) => p384::ecdsa::Signature::from_slice(r_s)
                .is_ok_and(|sig| key.verify_prehash(hashed, &sig).is_ok()),
            PublicKey::Rsa(..) => false,
        }
    }
}

/// The [`RsaKeyUse`] of an `id-RSASSA-PSS` key whose SubjectPublicKeyInfo algorithm has the
/// parameters `parameters` (RFC 4055 §3.1: absent, or `RSASSA-PSS-params`).
///
/// # Errors
/// [`Error::Certificate`] when the parameters are not `RSASSA-PSS-params` with a hash Folioxide
/// verifies, MGF1 on the same hash and trailer field 1 (OpenSSL refuses such a key too; a NULL is
/// no `RSASSA-PSS-params`).
fn rsa_pss_key_use(parameters: Option<&der::asn1::AnyRef<'_>>) -> Result<RsaKeyUse> {
    let Some(parameters) = parameters else {
        return Ok(RsaKeyUse::PssOnly);
    };
    let der = der::Encode::to_der(parameters)
        .map_err(|_| Error::Certificate("the id-RSASSA-PSS key parameters do not parse".into()))?;
    let (hash, salt_len) = crate::cms::verify::pss_parameters(Some(&der)).map_err(|why| {
        Error::Certificate(format!(
            "the id-RSASSA-PSS key parameters are unusable: {why}"
        ))
    })?;
    Ok(RsaKeyUse::PssWith { hash, salt_len })
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

/// Decodes a **strict** DER `ECDSA-Sig-Value` into `r || s` (each half left-padded to `field`
/// bytes): [`ecdsa_der_to_fixed`], and the input must be exactly the minimal DER re-encoding of
/// the values it holds ([`ecdsa_der_from_fixed`]), as OpenSSL's `ECDSA_verify` requires (it
/// re-encodes the decoded value and compares). Redundant leading zero octets, long-form lengths
/// that fit the short form, IEEE P1363 `r || s` and trailing bytes are all refused.
pub(crate) fn ecdsa_strict_der_to_fixed(signature: &[u8], field: usize) -> Option<Vec<u8>> {
    let fixed = ecdsa_der_to_fixed(signature, field)?;
    (ecdsa_der_from_fixed(&fixed, field) == signature).then_some(fixed)
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

    #[test]
    fn strict_der_is_the_minimal_encoding_only() {
        let field = 4;
        // r = 0x80 (with its sign octet), s = 0x01: the minimal encoding is accepted.
        let minimal = [0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01];
        assert_eq!(
            ecdsa_strict_der_to_fixed(&minimal, field),
            Some(vec![0, 0, 0, 0x80, 0, 0, 0, 1])
        );
        for bad in [
            // A redundant leading zero octet in s (accepted by the lax decoder).
            vec![0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x00, 0x01],
            // A long-form SEQUENCE length that fits the short form.
            vec![0x30, 0x81, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01],
            // A long-form INTEGER length.
            vec![0x30, 0x08, 0x02, 0x81, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01],
            // IEEE P1363 r || s.
            vec![0, 0, 0, 0x80, 0, 0, 0, 1],
            // A trailing byte.
            vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01, 0x00],
            // Negative s.
            vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x81],
        ] {
            assert_eq!(ecdsa_strict_der_to_fixed(&bad, field), None, "{bad:02x?}");
        }
    }
}
