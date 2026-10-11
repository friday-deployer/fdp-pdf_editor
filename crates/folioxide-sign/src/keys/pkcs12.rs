//! PKCS#12 (RFC 7292) loading through `p12-keystore`, with Folioxide's error mapping (M3 brief
//! §3.1 "Key loading").
//!
//! `p12_keystore::KeyStore::from_pkcs12` verifies the MAC before it decrypts anything
//! (`Pkcs12Archive::from_pkcs12` → `codec::verify_mac`), so a wrong password is reported as a MAC
//! failure. Errors map as follows:
//!
//! | `p12_keystore::error::Error` | Folioxide |
//! |---|---|
//! | `MacError` | [`Error::WrongPassword`] |
//! | `Pkcs5Error`, `UnpadError` in a file **without** a MAC | [`Error::WrongPassword`] |
//! | `UnsupportedEncryptionScheme`, `UnsupportedMacAlgorithm` (also RC2/3DES without the `pkcs12-legacy` feature) | [`Error::Unsupported`] |
//! | everything else; no private key; no certificate for the key | [`Error::KeyLoad`] |
//!
//! `p12_keystore::PrivateKey` keeps its own copy of the PKCS#8 key, which is not wiped; it is
//! dropped before [`load`] returns, and Folioxide's copy is [`Zeroizing`].
//!
//! **Hostile key-derivation parameters** (M3 brief R-18). `p12-keystore` caps PBKDF2 at
//! 1 000 000 iterations and scrypt at 1 GiB, but hands scrypt N = 0 to `pkcs5` 0.8.1, which
//! panics (`u64::BITS - leading_zeros - 1` underflows). So before `p12-keystore` runs, every
//! PBES2 parameter set in the unencrypted part of the file goes through the checks of the PEM
//! loader ([`super::check_kdf_cost`]), and a panic inside `p12-keystore` (parameters hidden in
//! an encrypted container, which only the right password opens) is caught and reported as
//! [`Error::KeyLoad`] rather than unwinding into the caller.

use std::panic::catch_unwind;

use p12_keystore::{KeyStore, Pkcs12ImportPolicy};
use zeroize::Zeroizing;

use crate::cms::tlv::{self, Element, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE};
use crate::error::{Error, Result};

/// The decrypted PKCS#8 key and the certificate chain (leaf first) of a PKCS#12 file.
pub(crate) struct Pkcs12Contents {
    /// The PKCS#8 `PrivateKeyInfo` DER, wiped when dropped.
    pub key_pkcs8: Zeroizing<Vec<u8>>,
    /// The certificates, the key's certificate first, then its issuers as `p12-keystore` links
    /// them by name.
    pub chain: Vec<Vec<u8>>,
}

/// Loads the first private key with its certificate chain.
///
/// # Errors
/// See the module documentation. Messages never contain the password.
pub(crate) fn load(p12_der: &[u8], password: &str) -> Result<Pkcs12Contents> {
    check_visible_kdfs(p12_der)?;
    // The closure only reads its two borrowed inputs, so nothing is left half-updated when a
    // panic is caught (see the module documentation).
    let store =
        catch_unwind(|| KeyStore::from_pkcs12(p12_der, password, Pkcs12ImportPolicy::Strict))
            .map_err(|_| {
                Error::KeyLoad(
                    "the PKCS#12 file has invalid key-derivation or encryption parameters".into(),
                )
            })?
            .map_err(|err| map_error(&err, has_mac(p12_der)))?;
    let (_, chain) = store.private_key_chain().ok_or_else(|| {
        Error::KeyLoad("the PKCS#12 file holds no private key with a matching certificate".into())
    })?;
    let certs: Vec<Vec<u8>> = chain.certs().iter().map(|c| c.as_der().to_vec()).collect();
    if certs.is_empty() {
        return Err(Error::KeyLoad(
            "the PKCS#12 file holds no certificate for the private key".into(),
        ));
    }
    Ok(Pkcs12Contents {
        key_pkcs8: Zeroizing::new(chain.key().as_der().to_vec()),
        chain: certs,
    })
}

/// The deepest nesting [`check_visible_kdfs`] follows. A shrouded key bag's KDF parameters sit
/// 15 levels deep in a PFX (PFX, ContentInfo, `[0]`, OCTET STRING, AuthenticatedSafe,
/// ContentInfo, `[0]`, OCTET STRING, SafeContents, SafeBag, `[0]`, EncryptedPrivateKeyInfo,
/// AlgorithmIdentifier, PBES2-params, KDF AlgorithmIdentifier).
const SCAN_MAX_DEPTH: usize = 32;

/// The content octets of the `id-PBES2` OID, 1.2.840.113549.1.5.13 (RFC 8018 Appendix A.4).
const PBES2_OID_CONTENT: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D];

/// Refuses the PFX when its unencrypted structure holds PBES2 key-derivation parameters that
/// [`super::check_kdf_cost`] refuses: in the `encryptedData` content-encryption algorithms and
/// in the shrouded key bags of plain `data` contents (RFC 7292 §4.1-4.2).
///
/// The walk descends into every constructed element and into OCTET STRINGs that hold exactly
/// one element (the `data` contents), up to [`SCAN_MAX_DEPTH`]. What does not parse is left to
/// `p12-keystore`, which reports it with its own error.
fn check_visible_kdfs(p12_der: &[u8]) -> Result<()> {
    match tlv::read(p12_der, 0, p12_der.len(), 0, SCAN_MAX_DEPTH) {
        Ok(root) => scan_kdfs(p12_der, &root, 0),
        Err(_) => Ok(()),
    }
}

/// [`check_visible_kdfs`] for `element` (at nesting `depth`) and its descendants.
fn scan_kdfs(input: &[u8], element: &Element, depth: usize) -> Result<()> {
    if element.tag == TAG_SEQUENCE
        && let Some(Ok(first)) = tlv::children(input, element, depth, SCAN_MAX_DEPTH).next()
        && first.tag == TAG_OID
        && first.content(input) == PBES2_OID_CONTENT
    {
        // AlgorithmIdentifier { id-PBES2, PBES2-params } (RFC 8018 Appendix A.4).
        if let Ok(pkcs8::pkcs5::EncryptionScheme::Pbes2(params)) =
            pkcs8::pkcs5::EncryptionScheme::try_from(element.raw(input))
        {
            super::check_kdf_cost(&params.kdf)?;
        }
        return Ok(());
    }
    if element.is_constructed() {
        for child in tlv::children(input, element, depth, SCAN_MAX_DEPTH) {
            let Ok(child) = child else {
                break;
            };
            scan_kdfs(input, &child, depth + 1)?;
        }
    } else if element.tag == TAG_OCTET_STRING {
        let content = element.content(input);
        if let Ok(inner) = tlv::read(content, 0, content.len(), depth + 1, SCAN_MAX_DEPTH)
            && inner.end == content.len()
        {
            scan_kdfs(content, &inner, depth + 1)?;
        }
    }
    Ok(())
}

/// Whether the PFX has `macData` (RFC 7292 §4: `PFX ::= SEQUENCE { version, authSafe, macData
/// OPTIONAL }`).
fn has_mac(p12_der: &[u8]) -> bool {
    let Ok(pfx) = tlv::read(p12_der, 0, p12_der.len(), 0, 64) else {
        return false;
    };
    pfx.tag == TAG_SEQUENCE
        && tlv::children(p12_der, &pfx, 0, 64)
            .filter(|child| child.is_ok())
            .count()
            >= 3
}

/// Maps a `p12-keystore` error (brief §3.1).
fn map_error(err: &p12_keystore::error::Error, has_mac: bool) -> Error {
    use p12_keystore::error::Error as P12;
    match err {
        P12::MacError(_) => Error::WrongPassword,
        P12::Pkcs5Error(_) | P12::UnpadError if !has_mac => Error::WrongPassword,
        P12::Pkcs5Error(_) | P12::UnpadError => Error::KeyLoad(
            "the PKCS#12 file does not decrypt although its MAC verifies (corrupt file)".into(),
        ),
        P12::UnsupportedEncryptionScheme | P12::UnsupportedMacAlgorithm => {
            let hint = if cfg!(feature = "pkcs12-legacy") {
                ""
            } else {
                " (RC2 and 3DES files need the `pkcs12-legacy` feature)"
            };
            Error::Unsupported(format!(
                "the PKCS#12 file uses an encryption or MAC scheme that is not supported{hint}"
            ))
        }
        P12::InvalidParameters => Error::KeyLoad(
            "the PKCS#12 file has invalid or excessive key-derivation parameters".into(),
        ),
        P12::InvalidPrivateKey => Error::KeyLoad("the PKCS#12 private key does not parse".into()),
        _ => Error::KeyLoad("the PKCS#12 file does not parse".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_is_key_load() {
        for bytes in [
            &b""[..],
            b"not a pkcs12 file",
            &[0x30, 0x03, 0x02, 0x01, 0x03],
        ] {
            let err = load(bytes, "pw").err().unwrap();
            assert!(matches!(err, Error::KeyLoad(_)), "{err:?}");
        }
    }

    /// The scan is bounded: nesting far beyond [`SCAN_MAX_DEPTH`] (as SEQUENCEs, and as OCTET
    /// STRINGs that each hold the next level) neither recurses without bound nor fails.
    #[test]
    fn kdf_scan_is_depth_bounded() {
        for tag in [TAG_SEQUENCE, TAG_OCTET_STRING] {
            let mut nested = vec![0x05, 0x00];
            for _ in 0..10_000 {
                nested = tlv::tlv(tag, &nested);
            }
            assert!(check_visible_kdfs(&nested).is_ok());
        }
        assert!(check_visible_kdfs(&[]).is_ok());
        assert!(check_visible_kdfs(&[0x30, 0x80]).is_ok());
    }

    #[test]
    fn mac_detection() {
        assert!(!has_mac(&[]));
        assert!(!has_mac(&[0x30, 0x03, 0x02, 0x01, 0x03]));
        assert!(has_mac(&[
            0x30, 0x07, 0x02, 0x01, 0x03, 0x30, 0x00, 0x30, 0x00
        ]));
    }
}
