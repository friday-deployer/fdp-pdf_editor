//! Private-key and certificate loading: PKCS#12, PEM and PKCS#8 (M3 brief §3.1 "Key loading").
//!
//! [`LocalSigner`](crate::signer::LocalSigner) is the public entry point for keys; this module
//! does the decoding behind it and offers [`certificates_from_pem`] for certificate files.
//!
//! - **PKCS#12:** the MAC is verified before anything is decrypted; a MAC failure is
//!   [`Error::WrongPassword`]. RC2-40 and 3DES bags need the
//!   `pkcs12-legacy` feature, else [`Error::Unsupported`].
//! - **PEM keys:** `BEGIN PRIVATE KEY` (PKCS#8), `BEGIN ENCRYPTED PRIVATE KEY` (PKCS#8 PBES2),
//!   `BEGIN RSA PRIVATE KEY` (PKCS#1) and `BEGIN EC PRIVATE KEY` (SEC1). Legacy OpenSSL
//!   `Proc-Type: 4,ENCRYPTED` keys are [`Error::Unsupported`].
//! - **Hygiene:** error messages never contain passwords or key bytes, and decrypted key
//!   buffers are wiped when dropped. (`p12-keystore` keeps an unwiped copy of a PKCS#12 key
//!   while it is loaded; it is dropped before loading returns.)

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::x509info::cert;

pub(crate) mod pem;
pub(crate) mod pkcs12;
pub(crate) mod private;
pub(crate) mod public;

use private::PrivateKey;

/// The largest PBKDF2 iteration count of an encrypted PEM key that Folioxide runs (a defence
/// against a key file that would keep the CPU busy for hours; OpenSSL writes 2048, current
/// OWASP advice is 600 000 for HMAC-SHA-256).
const MAX_PBKDF2_ITERATIONS: u32 = 10_000_000;
/// The most memory an scrypt-encrypted PEM key may ask for: `128 · r · (N + p)` bytes, the
/// array `V` plus the `p` blocks `B` of RFC 7914 §5-6, counted as OpenSSL counts them. 256 MiB:
/// OpenSSL 3.0's default limit is 32 MiB, and its `-scrypt` option writes N = 16384, r = 8,
/// p = 1 (16 MiB).
const MAX_SCRYPT_MEMORY: u64 = 256 << 20;
/// The most scrypt work an encrypted PEM key may ask for: `128 · N · r · p` bytes mixed (each of
/// the `p` lanes fills and then reads `V`, RFC 7914 §5-6). 1 GiB, which takes about as long as
/// the PBKDF2 cap.
const MAX_SCRYPT_WORK: u64 = 1 << 30;

/// The DER bytes of every `BEGIN CERTIFICATE` block in `certs_pem`, in order.
///
/// The bytes are exactly the base64-decoded block contents (never re-encoded). Text outside the
/// blocks, such as OpenSSL's `subject=` lines, is ignored, and so are blocks of other types.
///
/// ```
/// use folioxide_sign::keys::certificates_from_pem;
///
/// let err = certificates_from_pem("no certificates here").unwrap_err();
/// assert_eq!(err.code(), folioxide_syntax::ErrorCode::Certificate);
/// ```
///
/// # Errors
/// [`Error::Certificate`] when there is no certificate block or a
/// block does not decode to a certificate.
pub fn certificates_from_pem(certs_pem: &str) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    for (index, block) in pem::blocks(certs_pem)
        .into_iter()
        .filter(|b| b.label == "CERTIFICATE" || b.label == "X509 CERTIFICATE")
        .enumerate()
    {
        let der = block.decode().ok_or_else(|| {
            Error::Certificate(format!(
                "certificate block {} is not valid base64",
                index + 1
            ))
        })?;
        cert::CertParts::parse(&der).map_err(|e| {
            Error::Certificate(format!(
                "certificate block {} does not parse: {e}",
                index + 1
            ))
        })?;
        out.push(der.to_vec());
    }
    if out.is_empty() {
        return Err(Error::Certificate(
            "no BEGIN CERTIFICATE block was found".into(),
        ));
    }
    Ok(out)
}

/// Decodes the private key of `key_pem` (brief §3.1 "PEM").
pub(crate) fn private_key_from_pem(key_pem: &str, password: Option<&str>) -> Result<PrivateKey> {
    let blocks = pem::blocks(key_pem);
    let Some(block) = blocks.iter().find(|b| b.label.ends_with("PRIVATE KEY")) else {
        return Err(Error::KeyLoad(
            "no private key PEM block was found (BEGIN PRIVATE KEY, ENCRYPTED PRIVATE KEY, \
             RSA PRIVATE KEY or EC PRIVATE KEY)"
                .into(),
        ));
    };
    if block.is_legacy_encrypted() {
        return Err(Error::Unsupported(
            "legacy OpenSSL encrypted PEM keys (Proc-Type: 4,ENCRYPTED) are not supported; \
             convert the key to PKCS#8 (openssl pkcs8 -topk8)"
                .into(),
        ));
    }
    if block.has_headers() {
        return Err(Error::KeyLoad(
            "PEM headers are not supported in key files".into(),
        ));
    }
    let label = block.label;
    let decode = || {
        block
            .decode()
            .ok_or_else(|| Error::KeyLoad(format!("the {label} PEM block is not valid base64")))
    };
    match label {
        "PRIVATE KEY" => PrivateKey::from_pkcs8_der(&decode()?),
        "ENCRYPTED PRIVATE KEY" => {
            let password = password.ok_or(Error::PasswordRequired)?;
            let der = decode()?;
            PrivateKey::from_pkcs8_der(&decrypt_pkcs8(&der, password)?)
        }
        "RSA PRIVATE KEY" => PrivateKey::from_pkcs1_der(&decode()?),
        "EC PRIVATE KEY" => PrivateKey::from_sec1_der(&decode()?),
        other => Err(Error::Unsupported(format!(
            "PEM keys of type `{other}` are not supported"
        ))),
    }
}

/// Decrypts a PKCS#8 `EncryptedPrivateKeyInfo` (RFC 5958 §3, PBES2 of RFC 8018 §6.2).
///
/// A decryption or padding failure, or plaintext that is not a `PrivateKeyInfo`, is
/// [`Error::WrongPassword`] (brief §3.1): with CBC padding a wrong password almost always fails
/// the padding check, and otherwise produces garbage.
fn decrypt_pkcs8(der: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>> {
    use pkcs8::pkcs5;
    // EncryptedPrivateKeyInfo ::= SEQUENCE { encryptionAlgorithm AlgorithmIdentifier,
    // encryptedData OCTET STRING }. `pkcs5` cannot even decode most PBES1 and PKCS#12 PBE
    // schemes, so the scheme is identified from the raw OID first.
    if let Some(scheme) = encryption_scheme_oid(der)
        && scheme != PBES2_OID
    {
        return Err(Error::Unsupported(format!(
            "PKCS#8 keys encrypted with scheme {scheme} are not supported; re-encrypt with \
             PBES2 (openssl pkcs8 -topk8 -v2 aes-256-cbc)"
        )));
    }
    let info = pkcs8::EncryptedPrivateKeyInfoRef::try_from(der)
        .map_err(|_| Error::KeyLoad("the encrypted PKCS#8 key does not parse".into()))?;
    let Some(params) = info.encryption_algorithm.pbes2() else {
        return Err(Error::Unsupported(
            "PBES1-encrypted PKCS#8 keys are not supported; re-encrypt with PBES2 \
             (openssl pkcs8 -topk8 -v2 aes-256-cbc)"
                .into(),
        ));
    };
    check_kdf_cost(&params.kdf)?;
    let plaintext = info.decrypt(password).map_err(|err| match err {
        pkcs8::Error::EncryptedPrivateKey(pkcs5::Error::UnsupportedAlgorithm { .. })
        | pkcs8::Error::EncryptedPrivateKey(pkcs5::Error::NoPbes1CryptSupport) => {
            Error::Unsupported(
                "the encrypted key uses a cipher or key-derivation function that is not supported"
                    .into(),
            )
        }
        pkcs8::Error::EncryptedPrivateKey(pkcs5::Error::AlgorithmParametersInvalid { .. }) => {
            Error::KeyLoad("the encrypted key has invalid encryption parameters".into())
        }
        _ => Error::WrongPassword,
    })?;
    let plaintext = Zeroizing::new(plaintext.as_bytes().to_vec());
    if pkcs8::PrivateKeyInfoRef::try_from(plaintext.as_slice()).is_err() {
        return Err(Error::WrongPassword);
    }
    Ok(plaintext)
}

/// Refuses key-derivation parameters that would make loading a key a denial of service (M3
/// brief R-18), before any derivation runs: more than [`MAX_PBKDF2_ITERATIONS`] PBKDF2
/// iterations, or scrypt parameters beyond [`MAX_SCRYPT_MEMORY`] or [`MAX_SCRYPT_WORK`].
///
/// scrypt parameters that RFC 7914 §2 does not allow (N not a power of two above 1, r or p of
/// 0) are [`Error::KeyLoad`] here too: `pkcs5` panics on N = 0 instead of returning an error.
fn check_kdf_cost(kdf: &pkcs8::pkcs5::pbes2::Kdf) -> Result<()> {
    use pkcs8::pkcs5::pbes2::Kdf;
    match kdf {
        Kdf::Pbkdf2(params) if params.iteration_count > MAX_PBKDF2_ITERATIONS => {
            Err(Error::KeyLoad(format!(
                "the encrypted key asks for more than {MAX_PBKDF2_ITERATIONS} PBKDF2 iterations"
            )))
        }
        Kdf::Pbkdf2(_) => Ok(()),
        Kdf::Scrypt(params) => {
            let n = params.cost_parameter;
            let r = u64::from(params.block_size);
            let p = u64::from(params.parallelization);
            if n < 2 || !n.is_power_of_two() || r == 0 || p == 0 {
                return Err(Error::KeyLoad(
                    "the encrypted key has invalid scrypt parameters (N must be a power of two \
                     above 1, r and p at least 1)"
                        .into(),
                ));
            }
            let memory = n
                .checked_add(p)
                .and_then(|blocks| blocks.checked_mul(r))
                .and_then(|m| m.checked_mul(128));
            let work = n
                .checked_mul(r)
                .and_then(|w| w.checked_mul(p))
                .and_then(|w| w.checked_mul(128));
            if memory.is_none_or(|m| m > MAX_SCRYPT_MEMORY)
                || work.is_none_or(|w| w > MAX_SCRYPT_WORK)
            {
                return Err(Error::KeyLoad(format!(
                    "the encrypted key asks for excessive scrypt parameters (N = {n}, r = {r}, \
                     p = {p}; at most {} MiB of memory and {} MiB of work are allowed)",
                    MAX_SCRYPT_MEMORY >> 20,
                    MAX_SCRYPT_WORK >> 20
                )));
            }
            Ok(())
        }
        // `Kdf` is non-exhaustive: a key-derivation function this check does not know has no
        // cost bound, so it is refused rather than run.
        _ => Err(Error::Unsupported(
            "the encrypted key uses a key-derivation function that is not supported".into(),
        )),
    }
}

/// `id-PBES2` (RFC 8018 Appendix A.4).
const PBES2_OID: &str = "1.2.840.113549.1.5.13";

/// The dotted encryption-scheme OID of a DER `EncryptedPrivateKeyInfo`, when it is shaped like
/// one.
fn encryption_scheme_oid(der: &[u8]) -> Option<String> {
    use crate::cms::tlv::{self, TAG_OID, TAG_SEQUENCE};
    let outer = tlv::read_exact(der, 8).ok()?;
    let algorithm = tlv::children(der, &outer, 0, 8).next()?.ok()?;
    let oid = tlv::children(der, &algorithm, 1, 8).next()?.ok()?;
    if outer.tag != TAG_SEQUENCE || algorithm.tag != TAG_SEQUENCE || oid.tag != TAG_OID {
        return None;
    }
    crate::cms::oid_to_string(oid.content(der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_unknown_key_blocks() {
        let err = private_key_from_pem("nothing", None).err().unwrap();
        assert!(matches!(err, Error::KeyLoad(_)), "{err:?}");
        let dsa = "-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----\n";
        let err = private_key_from_pem(dsa, None).err().unwrap();
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
        let enc =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let err = private_key_from_pem(enc, None).err().unwrap();
        assert!(matches!(err, Error::PasswordRequired), "{err:?}");
        let err = private_key_from_pem(enc, Some("x")).err().unwrap();
        assert!(matches!(err, Error::KeyLoad(_)), "{err:?}");
        let legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\
                      DEK-Info: AES-128-CBC,0011\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        let err = private_key_from_pem(legacy, Some("x")).err().unwrap();
        assert!(matches!(err, Error::Unsupported(_)), "{err:?}");
    }

    #[test]
    fn certificate_blocks_must_parse() {
        let not_a_cert = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n";
        let err = certificates_from_pem(not_a_cert).unwrap_err();
        assert!(matches!(err, Error::Certificate(_)), "{err:?}");
    }

    use pkcs8::pkcs5::pbes2::{self, Kdf, Pbkdf2Params, Pbkdf2Prf, Salt, ScryptParams};

    fn pbkdf2(iteration_count: u32) -> Kdf {
        Kdf::Pbkdf2(Pbkdf2Params {
            salt: Salt::new([7u8; 16]).unwrap(),
            iteration_count,
            key_length: None,
            prf: Pbkdf2Prf::HmacWithSha256,
        })
    }

    fn scrypt(n: u64, r: u16, p: u16) -> Kdf {
        Kdf::Scrypt(ScryptParams {
            salt: Salt::new([7u8; 16]).unwrap(),
            cost_parameter: n,
            block_size: r,
            parallelization: p,
            key_length: None,
        })
    }

    /// A crafted `BEGIN ENCRYPTED PRIVATE KEY` block with these KDF parameters (AES-256-CBC
    /// over 48 bytes of zeros, which no password decrypts to a key).
    fn crafted_encrypted_pem(kdf: Kdf) -> String {
        use der::Encode;
        let params = pbes2::Parameters {
            kdf,
            encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: [9; 16] },
        };
        let info = pkcs8::EncryptedPrivateKeyInfoOwned {
            encryption_algorithm: params.into(),
            encrypted_data: der::asn1::OctetString::new(vec![0u8; 48]).unwrap(),
        };
        let der = info.to_der().unwrap();
        der::pem::encode_string("ENCRYPTED PRIVATE KEY", der::pem::LineEnding::LF, &der).unwrap()
    }

    /// M3 brief R-18: an encrypted key file cannot make loading run for hours. The caps refuse
    /// the key before any derivation runs (a cap that did not would hang this test).
    #[test]
    fn pbkdf2_iteration_cap_refuses_before_deriving() {
        for iterations in [MAX_PBKDF2_ITERATIONS + 1, 11_000_000, u32::MAX] {
            let pem = crafted_encrypted_pem(pbkdf2(iterations));
            let err = private_key_from_pem(&pem, Some("pw")).err().unwrap();
            assert!(matches!(err, Error::KeyLoad(_)), "{iterations}: {err:?}");
            assert!(
                err.to_string()
                    .contains("more than 10000000 PBKDF2 iterations"),
                "{err}"
            );
        }
        // At the cap and below, the parameters are accepted (the derivation is not run here).
        assert!(check_kdf_cost(&pbkdf2(MAX_PBKDF2_ITERATIONS)).is_ok());
        assert!(check_kdf_cost(&pbkdf2(2048)).is_ok());
        // Zero iterations derive once and fail as a wrong password, never panic.
        let err = private_key_from_pem(&crafted_encrypted_pem(pbkdf2(0)), Some("pw"))
            .err()
            .unwrap();
        assert!(matches!(err, Error::WrongPassword), "{err:?}");
    }

    #[test]
    fn scrypt_memory_and_work_caps_refuse_before_deriving() {
        let excessive = [
            // 128 · r · (N + p) above 256 MiB: 2 GiB, just above 256 MiB, and the largest r
            // with a small N.
            (1u64 << 21, 8u16, 1u16),
            (1 << 18, 8, 1),
            (1 << 10, u16::MAX, 1),
            // Products that overflow u64.
            (1 << 62, u16::MAX, u16::MAX),
            (1 << 63, 8, 1),
            // Memory within the cap, but 128 · N · r · p above 1 GiB of work.
            (1 << 14, 8, u16::MAX),
            (1 << 17, 8, 9),
        ];
        for (n, r, p) in excessive {
            let pem = crafted_encrypted_pem(scrypt(n, r, p));
            let err = private_key_from_pem(&pem, Some("pw")).err().unwrap();
            assert!(
                matches!(err, Error::KeyLoad(_)),
                "N={n} r={r} p={p}: {err:?}"
            );
            assert!(
                err.to_string().contains("excessive scrypt parameters"),
                "{err}"
            );
        }
        // OpenSSL's defaults, the work cap exactly and the smallest valid parameters are
        // accepted (the derivation is not run here).
        for (n, r, p) in [(1u64 << 14, 8u16, 1u16), (1 << 17, 8, 8), (2, 1, 1)] {
            check_kdf_cost(&scrypt(n, r, p)).unwrap();
        }
    }

    /// RFC 7914 §2: N is a power of two above 1, r and p are at least 1. `pkcs5` panics on
    /// N = 0 (`u64::BITS - leading_zeros - 1` underflows), so the check must come first.
    #[test]
    fn scrypt_invalid_parameters_are_key_load_not_a_panic() {
        let invalid = [
            (0u64, 8u16, 1u16),
            (1, 8, 1),
            (3, 8, 1),
            (1000, 8, 1),
            (1 << 10, 0, 1),
            (1 << 10, 8, 0),
        ];
        for (n, r, p) in invalid {
            let pem = crafted_encrypted_pem(scrypt(n, r, p));
            let err = private_key_from_pem(&pem, Some("pw")).err().unwrap();
            assert!(
                matches!(err, Error::KeyLoad(_)),
                "N={n} r={r} p={p}: {err:?}"
            );
            assert!(
                err.to_string().contains("invalid scrypt parameters"),
                "{err}"
            );
        }
    }

    /// The positive control: a real scrypt-encrypted key with small parameters loads, and a
    /// wrong password is [`Error::WrongPassword`].
    #[test]
    fn scrypt_encrypted_key_within_the_caps_loads() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/pki/signer-p256.key.pem");
        let plain = std::fs::read_to_string(path).unwrap();
        let block = pem::blocks(&plain)
            .into_iter()
            .find(|b| b.label == "PRIVATE KEY")
            .unwrap();
        let der = block.decode().unwrap();
        let params = pbes2::Parameters {
            kdf: scrypt(1 << 10, 8, 1),
            encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: [3; 16] },
        };
        let encrypted = pkcs8::PrivateKeyInfoRef::try_from(der.as_slice())
            .unwrap()
            .encrypt_with_params(params, "correct horse")
            .unwrap();
        let pem = der::pem::encode_string(
            "ENCRYPTED PRIVATE KEY",
            der::pem::LineEnding::LF,
            encrypted.as_bytes(),
        )
        .unwrap();
        let key = private_key_from_pem(&pem, Some("correct horse")).unwrap();
        let reference = private_key_from_pem(&plain, None).unwrap();
        assert_eq!(key.kind(), reference.kind());
        let err = private_key_from_pem(&pem, Some("wrong")).err().unwrap();
        assert!(matches!(err, Error::WrongPassword), "{err:?}");
    }
}
