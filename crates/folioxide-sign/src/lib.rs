//! # folioxide-sign: layer L5, digital signatures
//!
//! PDF signing and verification (ISO 32000-2 §12.8, ETSI EN 319 142-1 PAdES):
//!
//! - key loading from PKCS#12 and PEM, and a pluggable `Signer` trait
//! - CMS `SignedData` assembly with the PAdES signed attributes (RFC 5652, RFC 5035)
//! - RFC 3161 timestamps through a pluggable timestamper, with no network I/O in the core
//! - signature fields, the `/ByteRange` placeholder, one-step `sign` and the two-phase
//!   `prepare`/`finish` flow for external (HSM/KMS) signers
//! - certification signatures (DocMDP), verification and modification analysis
//!
//! RustCrypto types never appear in the public API: signatures take and return DER bytes and
//! Folioxide's own enums, because several RustCrypto crates are pre-releases
//! (`docs/ARCHITECTURE.md` §A.5).
//!
//! Dependency direction: `folioxide-model + folioxide-content ← folioxide-sign`.
//!
//! ## Modules
//!
//! PDF-agnostic cryptography (M3 brief §3.1):
//! - [`algorithms`]: digest and signature algorithms, key kinds, OIDs
//! - [`keys`]: PKCS#12, PEM and PKCS#8 loading
//! - [`signer`]: the [`Signer`](signer::Signer) trait and [`LocalSigner`](signer::LocalSigner)
//! - [`cms`]: CMS `SignedData` building, parsing and verification
//! - [`x509info`]: certificate information and trust
//!
//! The PDF side (M3 brief §3.2):
//! - [`field`]: signature fields and widgets
//! - [`placeholder`]: the `/ByteRange` and `/Contents` placeholders
//! - [`prepare`] and [`finish`]: the two-phase flow for external signers
//! - [`sign`]: one-step signing
//! - [`verify_pdf`] and [`report`]: verification and its report
//!
//! Errors are [`Error`], whose [`Error::code`] is the shared
//! [`ErrorCode`](folioxide_syntax::ErrorCode). Verification problems are [`Problem`]s.
//!
//! ## Features
//!
//! | Feature | Default | Enables |
//! |---|---|---|
//! | `sys-rng` | yes | the operating-system RNG as the default RNG for RSA blinding |
//! | `pkcs12-legacy` | no | RC2-40 and 3DES PKCS#12 files |
//! | `serde` | no | `Serialize`/`Deserialize` on the DTOs, `camelCase` |
//!
//! **Status:** M3, PAdES baseline B-B.
//! - Complete on the crypto side: [`algorithms`], [`keys`] (PKCS#12, PEM, PKCS#8, PKCS#1,
//!   SEC1), [`signer`] ([`LocalSigner`](signer::LocalSigner) with blinded RSA and RFC 6979
//!   ECDSA), [`cms`] (B-B signed attributes, assembly, raw-slice parsing, detached
//!   verification) and [`x509info`] (certificate information and trust path building with
//!   [`build_trust`](x509info::build_trust): validity, CA and path-length constraints, key
//!   usage, weak hashes; no revocation and no network).
//! - Complete on the PDF side: [`field`], [`placeholder`] and [`prepare`]; [`finish`],
//!   [`sign`], [`verify_pdf`] and [`report`] are the second-stage PDF work package (WP3.2A).
//! - Later milestones: RFC 3161 timestamps (B-T), DocMDP certification and visible appearances
//!   (M4), LTV (M11).
//!
//! ```
//! use folioxide_sign::algorithms::{DigestAlgorithm, KeyKind, default_digest};
//!
//! let digest = default_digest(KeyKind::EcP384);
//! assert_eq!(digest, DigestAlgorithm::Sha384);
//! assert_eq!(digest.digest(&[b"%PDF-", b"1.7"]).len(), 48);
//! ```

pub mod algorithms;
pub mod cms;
mod error;
pub mod field;
pub mod finish;
pub mod keys;
pub mod placeholder;
pub mod prepare;
mod problem;
pub mod report;
mod revisions;
pub mod sign;
pub mod signer;
pub mod verify_pdf;
pub mod x509info;

pub use error::{Error, Result};
pub use problem::{Problem, ProblemCode};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_types_are_send_sync_static() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Error>();
        assert_send_sync::<Problem>();
        assert_send_sync::<algorithms::Hasher>();
        assert_send_sync::<signer::LocalSigner>();
        assert_send_sync::<Box<dyn signer::Signer>>();
        assert_send_sync::<crate::cms::ParsedCms>();
        assert_send_sync::<crate::cms::CmsVerification>();
        assert_send_sync::<x509info::CertificateInfo>();
        assert_send_sync::<x509info::TrustResult>();
    }

    /// Pins the crypto-side signatures of M3 brief §3.1, which the PDF side codes against from
    /// stage 0 on: changing one breaks this test at compile time.
    #[test]
    // The function-pointer types spell out the brief's signatures on purpose.
    #[allow(clippy::type_complexity)]
    fn public_signatures_match_the_m3_brief() {
        use crate::cms::{self as cms_api, CmsVerification, ParsedCms, SignedAttrsInput};
        use algorithms::{DigestAlgorithm, Hasher, KeyKind, SignatureAlgorithm};
        use signer::{CryptoRng, LocalSigner};
        use x509info::{CertificateInfo, TrustResult, UnixTime};

        let _: fn(DigestAlgorithm) -> usize = DigestAlgorithm::output_len;
        let _: fn(DigestAlgorithm) -> Hasher = DigestAlgorithm::hasher;
        let _: fn(DigestAlgorithm, &[&[u8]]) -> Vec<u8> = DigestAlgorithm::digest;
        let _: fn(&mut Hasher, &[u8]) = Hasher::update;
        let _: fn(Hasher) -> Vec<u8> = Hasher::finalize;
        let _: fn(KeyKind) -> DigestAlgorithm = algorithms::default_digest;

        let _: fn(&[u8], &str) -> Result<LocalSigner> = LocalSigner::from_pkcs12;
        let _: fn(&str, &str, Option<&str>) -> Result<LocalSigner> = LocalSigner::from_pem;
        let _: fn(&[u8], Vec<Vec<u8>>) -> Result<LocalSigner> = LocalSigner::from_pkcs8_der;
        let _: fn(LocalSigner, Box<dyn CryptoRng + Send>) -> LocalSigner = LocalSigner::with_rng;
        fn uses_signer(s: &dyn signer::Signer) -> Result<Vec<u8>> {
            let _: &[Vec<u8>] = s.certificate_chain();
            let _: SignatureAlgorithm = s.algorithm();
            let _: KeyKind = s.key_kind();
            s.sign(DigestAlgorithm::Sha256, b"tbs")
        }
        let _ = uses_signer;

        let _: fn(&SignedAttrsInput<'_>) -> Result<Vec<u8>> = cms_api::build_signed_attrs;
        let _: fn(
            &[u8],
            &[Vec<u8>],
            SignatureAlgorithm,
            KeyKind,
            DigestAlgorithm,
        ) -> Result<usize> = cms_api::cms_len_upper_bound;
        let _: fn(
            &[u8],
            &[u8],
            &[Vec<u8>],
            SignatureAlgorithm,
            KeyKind,
            DigestAlgorithm,
        ) -> Result<Vec<u8>> = cms_api::assemble;
        let _: fn(&[u8], SignatureAlgorithm, DigestAlgorithm, &[u8], &[u8]) -> Result<()> =
            cms_api::verify_raw;
        let _: fn(&[u8]) -> Result<ParsedCms> = cms_api::parse;
        let _: fn(
            &ParsedCms,
            &dyn Fn(DigestAlgorithm) -> Option<Vec<u8>>,
            &[Vec<u8>],
        ) -> CmsVerification = cms_api::verify_detached;

        let _: fn(&[u8]) -> Result<CertificateInfo> = x509info::certificate_info;
        let _: fn(&[u8], &[Vec<u8>], &[Vec<u8>], UnixTime) -> TrustResult = x509info::build_trust;

        // Additions beyond the brief that the PDF side may use.
        let _: fn(&[u8], SignatureAlgorithm, DigestAlgorithm, &[u8], &[u8]) -> Result<Vec<u8>> =
            cms_api::verify_and_normalize;
        let _: fn(&[u8]) -> Result<KeyKind> = x509info::certificate_key_kind;
        let _: fn(&folioxide_model::PdfDate) -> UnixTime = UnixTime::from_pdf_date;
        let _: fn(&str) -> Result<Vec<Vec<u8>>> = keys::certificates_from_pem;
        let _: fn(KeyKind, DigestAlgorithm) -> Result<()> = algorithms::check_signing_combination;
        let _: fn(DigestAlgorithm, &[u8]) -> Vec<u8> = DigestAlgorithm::digest_info;

        let input = SignedAttrsInput {
            digest: DigestAlgorithm::Sha256,
            document_digest: &[0; 32],
            signer_cert_der: &[],
        };
        let _ = input;
    }
}
