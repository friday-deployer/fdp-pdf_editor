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
//! Signatures II (M4 brief §3):
//! - [`tsp`]: RFC 3161 timestamp requests, responses and tokens, and the
//!   [`Timestamper`](tsp::Timestamper) trait
//! - [`bt`]: PAdES B-T, the two-phase timestamped flow on
//!   [`PreparedSignature`](prepare::PreparedSignature)
//! - [`docmdp`]: certification signatures and their DocMDP permissions
//! - [`appearance`]: visible signature appearances
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
//! **Status:** M4 stage 1, PAdES baseline B-B and B-T.
//! - Complete on the crypto side: [`algorithms`], [`keys`] (PKCS#12, PEM, PKCS#8, PKCS#1,
//!   SEC1), [`signer`] ([`LocalSigner`](signer::LocalSigner) with blinded RSA and RFC 6979
//!   ECDSA), [`cms`] (B-B signed attributes, assembly, raw-slice parsing, detached
//!   verification) and [`x509info`] (certificate information and trust path building with
//!   [`build_trust`](x509info::build_trust): validity, CA and path-length constraints, key
//!   usage, weak hashes; no revocation and no network).
//! - Complete on the PDF side: [`field`], [`placeholder`] and [`prepare`]; [`finish`],
//!   [`sign`], [`verify_pdf`] and [`report`] are the second-stage PDF work package (WP3.2A).
//! - M4, RFC 3161 timestamps (WP4.1B, WP4.2B): complete. [`tsp`] (requests, responses,
//!   TSTInfo and `genTime` decoding, response validation and token verification), signature
//!   timestamp tokens in [`cms`] and the timestamping purpose in [`x509info`]; PAdES B-T
//!   signing with a [`Timestamper`](tsp::Timestamper) in [`sign`] or through the two-phase
//!   [`bt`] flow; verification of signature timestamps and document timestamps in
//!   [`verify_pdf`] (the signer's trust time is a trusted `genTime`).
//! - M4, DocMDP certification ([`docmdp`]) and visible appearances ([`appearance`]): the other
//!   M4 work packages. Until they land, `prepare` and `sign` refuse a certification or an
//!   appearance with `Unsupported("M4 stage N")`.
//! - Later milestones: LTV (M11).
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
// M4 (brief §2 WP4.0).
pub mod appearance;
pub mod bt;
pub mod docmdp;
pub mod tsp;

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
        // M4.
        assert_send_sync::<tsp::TimeStampReq>();
        assert_send_sync::<tsp::TimeStampResp>();
        assert_send_sync::<tsp::TstInfo>();
        assert_send_sync::<tsp::ValidatedToken>();
        assert_send_sync::<tsp::TokenVerification>();
        assert_send_sync::<Box<dyn tsp::Timestamper>>();
        assert_send_sync::<bt::TimestampParams>();
        assert_send_sync::<report::TimestampInfo>();
        assert_send_sync::<appearance::SignatureAppearance>();
        assert_send_sync::<docmdp::DocMdpPermissions>();
        assert_send_sync::<sign::SignRequest<'static>>();
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

    /// Pins the public signatures of the M4 brief §3.1 (timestamps), the `folioxide-sign` side
    /// of §3.2 (certification and appearance options) and §3.3 (report, problems, errors),
    /// which both developers code against from stage 0 on: changing one breaks this test at
    /// compile time (as `public_signatures_match_the_m3_brief` does for M3).
    #[test]
    // The function-pointer types spell out the brief's signatures on purpose.
    #[allow(clippy::type_complexity)]
    fn public_signatures_match_the_m4_brief() {
        use crate::cms::{self as cms_api, CmsVerification, ParsedCms, ParsedSignerInfo};
        use algorithms::{DigestAlgorithm, KeyKind, SignatureAlgorithm};
        use appearance::{AppearanceText, ImagePosition, SignatureAppearance, Standard14Font};
        use bt::TimestampParams;
        use docmdp::DocMdpPermissions;
        use finish::FinishError;
        use folioxide_model::{Document, Rect};
        use folioxide_syntax::{Dict, ErrorCode, ObjectId};
        use prepare::{PreparedSignature, SignatureOptions};
        use report::{PadesLevel, SignatureReport, TimestampInfo};
        use sign::SignRequest;
        use tsp::{
            Accuracy, GenTime, MessageImprint, PkiStatus, PkiStatusInfo, TimeStampReq,
            TimeStampResp, Timestamper, TokenVerification, TstInfo, ValidatedToken,
        };
        use verify_pdf::VerifyOptions;
        use x509info::{TrustPurpose, TrustResult, UnixTime};

        // ---- §3.1 tsp ----
        let _: &str = tsp::OID_CT_TST_INFO;
        let _: &str = tsp::OID_AA_SIGNATURE_TIME_STAMP_TOKEN;
        let _: &str = tsp::OID_KP_TIME_STAMPING;
        let _: usize = tsp::DEFAULT_TSA_RESERVE;
        let _: usize = tsp::MAX_TIMESTAMP_TOKENS;
        assert_eq!(tsp::OID_CT_TST_INFO, "1.2.840.113549.1.9.16.1.4");
        assert_eq!(
            tsp::OID_AA_SIGNATURE_TIME_STAMP_TOKEN,
            "1.2.840.113549.1.9.16.2.14"
        );
        assert_eq!(tsp::OID_KP_TIME_STAMPING, "1.3.6.1.5.5.7.3.8");
        assert_eq!(tsp::DEFAULT_TSA_RESERVE, 8192);
        assert_eq!(tsp::MAX_TIMESTAMP_TOKENS, 8);

        fn imprint_fields(m: &MessageImprint) {
            let _: DigestAlgorithm = m.digest;
            let _: &Vec<u8> = &m.hashed_message;
        }
        fn request_fields(r: &TimeStampReq) {
            let _: &MessageImprint = &r.imprint;
            let _: &Option<String> = &r.policy;
            let _: &Option<Vec<u8>> = &r.nonce;
            let _: bool = r.cert_req;
        }
        let _: fn(MessageImprint, Option<u64>, Option<String>) -> TimeStampReq = TimeStampReq::new;
        let _: fn(&TimeStampReq) -> Vec<u8> = TimeStampReq::to_der;
        let _: fn(&[u8]) -> Result<TimeStampReq> = TimeStampReq::from_der;
        fn status_variants(s: PkiStatus) -> i64 {
            match s {
                PkiStatus::Granted => 0,
                PkiStatus::GrantedWithMods => 1,
                PkiStatus::Rejection => 2,
                PkiStatus::Waiting => 3,
                PkiStatus::RevocationWarning => 4,
                PkiStatus::RevocationNotification => 5,
                PkiStatus::Unknown(n) => n,
            }
        }
        fn status_fields(s: &PkiStatusInfo) {
            let _: PkiStatus = s.status;
            let _: &Vec<String> = &s.status_string;
            let _: Option<u32> = s.fail_info;
        }
        fn response_fields(r: &TimeStampResp) {
            let _: &PkiStatusInfo = &r.status;
            let _: &Option<Vec<u8>> = &r.token;
        }
        let _: fn(&[u8]) -> Result<TimeStampResp> = TimeStampResp::from_der;
        fn gen_time_fields(g: GenTime) {
            let _: i64 = g.unix_seconds;
            let _: u32 = g.nanos;
            let _: u8 = g.fraction_digits;
        }
        fn copy_ord_hash<T: Copy + Ord + std::hash::Hash>() {}
        copy_ord_hash::<GenTime>();
        let _: fn(&[u8]) -> Result<GenTime> = GenTime::parse;
        let _: fn(&GenTime) -> String = GenTime::to_rfc3339;
        fn accuracy_fields(a: &Accuracy) {
            let _: Option<u64> = a.seconds;
            let _: Option<u16> = a.millis;
            let _: Option<u16> = a.micros;
        }
        fn tst_info_fields(t: &TstInfo) {
            let _: u32 = t.version;
            let _: &String = &t.policy;
            let _: &MessageImprint = &t.imprint;
            let _: &Vec<u8> = &t.serial;
            let _: GenTime = t.gen_time;
            let _: &Option<Accuracy> = &t.accuracy;
            let _: bool = t.ordering;
            let _: &Option<Vec<u8>> = &t.nonce;
            let _: &Option<String> = &t.tsa_name;
            let _: bool = t.has_extensions;
        }
        let _: fn(&[u8]) -> Result<TstInfo> = TstInfo::from_der;
        fn uses_timestamper(t: &dyn Timestamper) -> Result<Vec<u8>> {
            t.timestamp(b"request")
        }
        fn send_sync<T: ?Sized + Send + Sync>() {}
        send_sync::<dyn Timestamper>();
        #[cfg(feature = "sys-rng")]
        let _: fn() -> Result<u64> = tsp::random_nonce;
        let _: fn(&TimeStampReq, &[u8]) -> Result<ValidatedToken> = tsp::validate_response;
        fn validated_fields(v: &ValidatedToken) {
            let _: &Vec<u8> = &v.token_der;
            let _: &TstInfo = &v.tst_info;
            let _: &Vec<u8> = &v.tsa_cert_der;
            let _: &Vec<String> = &v.warnings;
        }
        let _: fn(
            &[u8],
            &dyn Fn(DigestAlgorithm) -> Option<Vec<u8>>,
            &[Vec<u8>],
        ) -> TokenVerification = tsp::verify_token;
        fn verification_fields(v: &TokenVerification) {
            let _: bool = v.intact;
            let _: bool = v.valid;
            let _: &Option<TstInfo> = &v.tst_info;
            let _: &Option<Vec<u8>> = &v.tsa_cert;
            let _: &Vec<Vec<u8>> = &v.certificates;
            let _: &Option<String> = &v.signature_algorithm;
            let _: &Vec<Problem> = &v.problems;
            let _: &Vec<String> = &v.warnings;
        }
        let _ = TokenVerification::default();
        let _ = (
            imprint_fields,
            request_fields,
            status_variants,
            status_fields,
        );
        let _ = (
            response_fields,
            gen_time_fields,
            accuracy_fields,
            tst_info_fields,
        );
        let _ = (uses_timestamper, validated_fields, verification_fields);

        // ---- §3.1 cms and x509info ----
        let _: fn(&ParsedCms, &str, &[Vec<u8>]) -> CmsVerification = cms_api::verify_encapsulated;
        let _: fn(
            &[u8],
            &[u8],
            &[Vec<u8>],
            SignatureAlgorithm,
            KeyKind,
            DigestAlgorithm,
            &[u8],
        ) -> Result<Vec<u8>> = cms_api::assemble_with_timestamp;
        let _: fn(
            &[u8],
            &[Vec<u8>],
            SignatureAlgorithm,
            KeyKind,
            DigestAlgorithm,
            usize,
        ) -> Result<usize> = cms_api::cms_len_upper_bound_with_timestamp;
        let _: fn(&ParsedSignerInfo) -> Vec<Vec<u8>> = cms_api::signature_timestamp_tokens;
        fn purposes(p: TrustPurpose) -> u8 {
            match p {
                TrustPurpose::DocumentSigning => 0,
                TrustPurpose::TimeStamping => 1,
            }
        }
        let _ = purposes;
        let _: fn(TrustPurpose, &[u8], &[Vec<u8>], &[Vec<u8>], UnixTime) -> TrustResult =
            x509info::build_trust_for;
        let _: fn(&[u8]) -> std::result::Result<(), String> = x509info::check_tsa_certificate;

        // ---- §3.1 bt and sign ----
        fn params_fields(p: &TimestampParams) {
            let _: Option<DigestAlgorithm> = p.digest;
            let _: &Option<String> = &p.policy;
            let _: Option<u64> = p.nonce;
        }
        let _ = (params_fields, TimestampParams::default());
        let _: fn(&PreparedSignature, &[u8], &TimestampParams) -> Result<Vec<u8>> =
            PreparedSignature::timestamp_request;
        let _: fn(PreparedSignature, &[u8], &[u8], &[u8]) -> Result<Vec<u8>> =
            PreparedSignature::finish_with_timestamp;
        let _: fn(
            PreparedSignature,
            &[u8],
            &[u8],
            &[u8],
        ) -> std::result::Result<Vec<u8>, FinishError> =
            PreparedSignature::try_finish_with_timestamp;
        fn request_with<'a>(r: SignRequest<'a>, t: &'a dyn Timestamper) -> SignRequest<'a> {
            let _: &'a dyn signer::Signer = r.signer;
            let _: &SignatureOptions = &r.options;
            let _: Option<&'a dyn Timestamper> = r.timestamper;
            let _: &TimestampParams = &r.timestamp;
            r.with_timestamper(t, TimestampParams::default())
        }
        let _ = request_with;

        // ---- §3.2, the folioxide-sign side ----
        assert_eq!(DocMdpPermissions::NoChanges as u8, 1);
        assert_eq!(DocMdpPermissions::FormFilling as u8, 2);
        assert_eq!(DocMdpPermissions::FormFillingAndAnnotations as u8, 3);
        let _: fn(DocMdpPermissions) -> u8 = DocMdpPermissions::p;
        let _: fn(i64) -> Option<DocMdpPermissions> = DocMdpPermissions::from_p;
        let _: fn(&Document, &Dict, ObjectId) -> Option<u8> = docmdp::declared_permissions;
        fn options_fields(o: &SignatureOptions) {
            let _: Option<DocMdpPermissions> = o.certification;
            let _: &Option<SignatureAppearance> = &o.appearance;
            let _: Option<usize> = o.tsa_reserve;
        }
        fn appearance_fields(a: &SignatureAppearance) {
            let _: Option<Rect> = a.rect;
            let _: &AppearanceText = &a.text;
            let _: Standard14Font = a.font;
            let _: Option<f64> = a.font_size;
            let _: &Option<Vec<u8>> = &a.image;
            let _: ImagePosition = a.image_position;
            let _: f64 = a.border_width;
        }
        let _ = (options_fields, appearance_fields);
        let _: fn(SignatureOptions, Option<DocMdpPermissions>) -> SignatureOptions =
            SignatureOptions::with_certification;
        let _: fn(SignatureOptions, Option<SignatureAppearance>) -> SignatureOptions =
            SignatureOptions::with_appearance;
        let _: fn(SignatureOptions, Option<usize>) -> SignatureOptions =
            SignatureOptions::with_tsa_reserve;
        let _: fn(Rect) -> SignatureAppearance = SignatureAppearance::new;
        let _: fn() -> SignatureAppearance = SignatureAppearance::for_existing_field;
        fn text_variants(t: &AppearanceText) -> usize {
            match t {
                AppearanceText::Default => 0,
                AppearanceText::Lines(lines) => lines.len(),
            }
        }
        fn position_variants(p: ImagePosition) -> u8 {
            match p {
                ImagePosition::Left => 0,
                ImagePosition::Background => 1,
            }
        }
        let _ = (text_variants, position_variants);
        let _ = [Standard14Font::Helvetica, Standard14Font::HelveticaBold];

        // ---- §3.3 report, problems and errors ----
        fn pades_variants(p: PadesLevel) -> &'static str {
            match p {
                PadesLevel::BB => "B-B",
                PadesLevel::BT => "B-T",
            }
        }
        assert_eq!(pades_variants(PadesLevel::BT), PadesLevel::BT.as_str());
        fn timestamp_info_fields(t: &TimestampInfo) {
            let _: &String = &t.gen_time;
            let _: &Option<x509info::CertificateInfo> = &t.tsa;
            let _: &Option<String> = &t.tsa_name;
            let _: &Option<String> = &t.policy;
            let _: &Option<String> = &t.serial_hex;
            let _: Option<u64> = t.accuracy_micros;
            let _: bool = t.ordering;
            let _: &Option<String> = &t.imprint_algorithm;
            let _: &Option<String> = &t.signature_algorithm;
            let _: bool = t.intact;
            let _: bool = t.valid;
            let _: Option<bool> = t.trusted;
            let _: &Vec<Problem> = &t.problems;
            let _: &Vec<String> = &t.warnings;
        }
        fn report_fields(r: &SignatureReport) {
            let _: &Option<TimestampInfo> = &r.timestamp;
            let _: &Vec<TimestampInfo> = &r.timestamps;
            let _: Option<u8> = r.docmdp;
            let _: Option<bool> = r.docmdp_ok;
        }
        fn verify_options_fields(o: &VerifyOptions) {
            let _: &Option<Vec<Vec<u8>>> = &o.timestamp_trust_anchors_der;
        }
        let _: fn(VerifyOptions, Option<Vec<Vec<u8>>>) -> VerifyOptions =
            VerifyOptions::with_timestamp_trust_anchors_der;
        let _ = (timestamp_info_fields, report_fields, verify_options_fields);
        for (code, text) in [
            (ProblemCode::TimestampMalformed, "timestampMalformed"),
            (
                ProblemCode::TimestampImprintMismatch,
                "timestampImprintMismatch",
            ),
            (
                ProblemCode::TimestampSignatureInvalid,
                "timestampSignatureInvalid",
            ),
            (ProblemCode::TimestampEssMismatch, "timestampEssMismatch"),
            (
                ProblemCode::TsaCertificateUnsuitable,
                "tsaCertificateUnsuitable",
            ),
            (
                ProblemCode::TsaCertificateNotValidAtGenTime,
                "tsaCertificateNotValidAtGenTime",
            ),
            (ProblemCode::TsaNameMismatch, "tsaNameMismatch"),
            (ProblemCode::DocMdpInvalid, "docMdpInvalid"),
            (ProblemCode::CertificationNotFirst, "certificationNotFirst"),
            (ProblemCode::SigDictAmbiguous, "sigDictAmbiguous"),
            (
                ProblemCode::PendingTimestampVerification,
                "pendingTimestampVerification",
            ),
        ] {
            assert_eq!(code.as_str(), text);
            assert!(ProblemCode::ALL.contains(&code));
        }
        let err = Error::TimestampInvalid("x".into());
        assert_eq!(err.code(), ErrorCode::TimestampInvalid);
    }
}
