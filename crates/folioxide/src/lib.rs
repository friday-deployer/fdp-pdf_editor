//! # folioxide: a pure-Rust PDF editing engine
//!
//! This is the facade crate and the only crate with a semver promise. Applications (the Node
//! addon, and later a Tauri app) depend on it alone. It re-exports the public API of the layered
//! `folioxide-*` crates, owns the unified `Error`, the serde DTOs and the `std::fs` helpers, and
//! selects functionality through feature flags:
//!
//! | Feature | Default | Enables |
//! |---|---|---|
//! | `encryption` | yes | open and save encrypted documents (`folioxide-security`) |
//! | `signatures` | yes | digital signatures (`folioxide-sign`, RustCrypto) |
//! | `pkcs12-legacy` | yes | RC2-40 and 3DES PKCS#12 files |
//! | `fonts` | yes | TrueType/OpenType embedding and subsetting |
//! | `images` | yes | PNG decoding (JPEG passthrough is always on) |
//! | `interactive` | yes | annotations and forms (`folioxide-interactive`) |
//! | `jpeg-decode` | no | JPEG pixel decoding |
//! | `shaping` | no | complex-script shaping and bidi |
//! | `redact` | no | true redaction (`folioxide-redact`) |
//! | `render` | no | page rendering (`folioxide-render`) |
//! | `serde` | no | `Serialize`/`Deserialize` on all DTOs |
//! | `std-fs` | no | path helpers, `SystemClock`, optional mmap |
//!
//! No feature adds threads or network I/O.
//!
//! **Status:** pre-alpha; see `docs/ROADMAP.md`.
//! - M2, the document model: open or create a [`Document`], walk its pages ([`Page`]: boxes,
//!   rotation, resources; [`PageInfo`]), read and change its Info dictionary ([`DocInfo`],
//!   [`InfoUpdate`]), set page boxes and rotation, and save it as a full rewrite
//!   ([`SaveOptions`]) or as an incremental update that keeps the original bytes
//!   ([`IncrementalOptions`]).
//! - M3, signatures (feature `signatures`): local keys from PKCS#12 and PEM ([`LocalSigner`]),
//!   the [`Signer`] trait for HSMs and KMSes, invisible PAdES B-B signatures in one step
//!   ([`fn@sign`], [`SignRequest`]) or in two phases for external signers ([`prepare`],
//!   [`PreparedSignature`]), sequential signatures, and verification ([`verify`],
//!   [`verify_bytes`], [`VerifyOptions`]) with a [`SignatureReport`] per signature
//!   (integrity, validity, [`Coverage`], [`ModificationLevel`], certificate information
//!   ([`CertificateInfo`]) and trust). The whole signature layer is [`mod@sign`].
//! - Errors are one [`enum@Error`] with a stable [`ErrorCode`], whichever layer failed.
//!
//! Bytes in, bytes out: the core reads no files and has no clock, so the caller reads and writes
//! the files and passes dates in (ARCHITECTURE §A.8).
//!
//! ```
//! use folioxide::{
//!     Document, ErrorCode, IncrementalOptions, InfoUpdate, OpenOptions, PdfDate, Rect, Rotation,
//!     SaveOptions,
//! };
//!
//! # fn build(objects: &[&str]) -> Vec<u8> {
//! #     let mut out = b"%PDF-1.7\n".to_vec();
//! #     let mut offsets = Vec::new();
//! #     for (i, body) in objects.iter().enumerate() {
//! #         offsets.push(out.len());
//! #         out.extend(format!("{} 0 obj\n{body}\nendobj\n", i + 1).bytes());
//! #     }
//! #     let xref = out.len();
//! #     out.extend(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).bytes());
//! #     for offset in offsets {
//! #         out.extend(format!("{offset:010} 00000 n \n").bytes());
//! #     }
//! #     let trailer = format!("/Size {} /Root 1 0 R", objects.len() + 1);
//! #     out.extend(format!("trailer\n<< {trailer} >>\nstartxref\n{xref}\n%%EOF\n").bytes());
//! #     out
//! # }
//! // An A4 page whose media box comes from the page tree (a hidden helper builds the file).
//! let original: Vec<u8> = build(&[
//!     "<< /Type /Catalog /Pages 2 0 R >>",
//!     "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>",
//!     "<< /Type /Page /Parent 2 0 R >>",
//! ]);
//! let mut doc = Document::open(original.clone(), &OpenOptions::default())?;
//! let page = doc.page(0)?.info();
//! assert_eq!((page.width, page.height), (595.0, 842.0));
//!
//! // Turn the page, crop it, and record the title and the modification time.
//! doc.set_rotation(0, Rotation::R90)?;
//! doc.set_crop_box(0, Some(Rect::new(20.0, 20.0, 575.0, 822.0)))?;
//! doc.set_info(
//!     &InfoUpdate::default()
//!         .with_title(Some("Quarterly report"))
//!         .with_mod_date(PdfDate::new(2026, 10, 10, 9, 30, 0)),
//! )?;
//!
//! // Save as an incremental update, which keeps every original byte (as signed files need),
//! // or rewrite the whole file.
//! let updated = doc.save_incremental(&IncrementalOptions::default())?;
//! assert!(updated.starts_with(&original));
//! let rewritten = doc.save(&SaveOptions::default())?;
//! for pdf in [updated, rewritten] {
//!     let doc = Document::open(pdf, &OpenOptions::default())?;
//!     let page = doc.page(0)?.info();
//!     assert_eq!(page.rotation, Rotation::R90);
//!     assert_eq!((page.width, page.height), (802.0, 555.0)); // the crop box, turned
//!     assert_eq!(doc.info()?.title.as_deref(), Some("Quarterly report"));
//! }
//!
//! // A new document starts with an empty page tree.
//! assert_eq!(Document::new().page_count()?, 0);
//!
//! // Errors carry a stable code (`err.code === "E_XREF"` in Node).
//! let err = Document::open(b"not a PDF".to_vec(), &OpenOptions::default()).unwrap_err();
//! assert_eq!(err.code(), ErrorCode::Xref);
//! # Ok::<(), folioxide::Error>(())
//! ```
//!
//! Signing and verifying (feature `signatures`, on by default): a local key signs in one step;
//! an HSM, a KMS or WebCrypto signs [`PreparedSignature::to_be_signed`] between [`prepare`] and
//! [`PreparedSignature::finish`]. The core has no clock, so the signing time and the validation
//! time are passed in.
//!
//! Accept a signed document with [`SignatureReport::is_acceptable`], not with
//! [`SignatureReport::is_valid`] alone: a signature over an earlier revision stays valid when a
//! later incremental update replaces page content, fonts or the catalog, and only
//! [`SignatureReport::modification`] says so. Trust is separate: also require
//! `trusted == Some(true)`. [`ModificationLevel::FormFilling`] accepts later signatures
//! (sequential signing), and with them **visible signature fields added after signing**: a new
//! signature field with an appearance, signed or still empty, or the appearance a later
//! signature gives the field it signs. Such an appearance can cover signed content; pyHanko and
//! Acrobat accept it at the same level. No level accepts later signatures while refusing visible
//! ones (a later signature, visible or not, is `FormFilling`), so when no further signer is
//! expected, [`ModificationLevel::LtaUpdates`] is the strict choice.
//!
//! ```
//! # #[cfg(feature = "signatures")] {
//! use folioxide::{
//!     Coverage, Document, ModificationLevel, OpenOptions, PdfDate, PrepareRequest, SignRequest,
//!     Signer, VerifyOptions, certificates_from_pem, prepare, sign, verify_bytes, LocalSigner,
//! };
//!
//! # let pki = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pki");
//! # let read = |name: &str| std::fs::read_to_string(pki.join(name)).unwrap();
//! # let objects = [
//! #     "<< /Type /Catalog /Pages 2 0 R >>",
//! #     "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
//! #     "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>",
//! # ];
//! # let mut original = b"%PDF-1.7\n".to_vec();
//! # let mut offsets = Vec::new();
//! # for (i, body) in objects.iter().enumerate() {
//! #     offsets.push(original.len());
//! #     original.extend(format!("{} 0 obj\n{body}\nendobj\n", i + 1).bytes());
//! # }
//! # let xref = original.len();
//! # original.extend(b"xref\n0 4\n0000000000 65535 f \n");
//! # for offset in offsets {
//! #     original.extend(format!("{offset:010} 00000 n \n").bytes());
//! # }
//! # original.extend(format!("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").bytes());
//! // A key and its certificate chain (signer first), from PEM (or `LocalSigner::from_pkcs12`).
//! let signer = LocalSigner::from_pem(
//!     &read("signer-p256.key.pem"),
//!     &(read("signer-p256.pem") + &read("intermediate.pem")),
//!     None,
//! )?;
//! let time = PdfDate::parse(b"D:20261010120000Z").unwrap();
//!
//! // One step: prepare, sign with the local key, finish.
//! let doc = Document::open(original.clone(), &OpenOptions::default())?;
//! let signed = sign(&doc, &SignRequest::new(&signer, time))?;
//! assert!(signed.starts_with(&original)); // an incremental update
//!
//! // Two phases: anything that can sign bytes (here the same key) signs between them.
//! let doc = Document::open(signed, &OpenOptions::default())?;
//! let request = PrepareRequest::new(signer.certificate_chain().to_vec(), signer.algorithm(), time);
//! let prepared = prepare(&doc, &request)?;
//! let value = signer.sign(prepared.digest_algorithm(), prepared.to_be_signed())?;
//! let twice = prepared.finish(&value)?;
//!
//! // Verify both signatures against the test root, at a given time.
//! let root = certificates_from_pem(&read("root.pem"))?;
//! let options = VerifyOptions::default()
//!     .with_trust_anchors_der(root)
//!     .with_validation_time(Some(time));
//! let reports = verify_bytes(twice, &options)?;
//! assert_eq!(reports.len(), 2);
//! // Accept the document: every signature is sound, nothing but later signatures was appended
//! // after it, and its signer chains to the root.
//! let accepted = reports
//!     .iter()
//!     .all(|r| r.is_acceptable(ModificationLevel::FormFilling) && r.trusted == Some(true));
//! assert!(accepted);
//! // The first signature covers its own revision; the second added a signature (form filling),
//! // which the strict level refuses.
//! assert_eq!(reports[0].coverage, Coverage::EntireRevision);
//! assert_eq!(reports[0].modification, ModificationLevel::FormFilling);
//! assert!(!reports[0].is_acceptable(ModificationLevel::LtaUpdates));
//! assert_eq!(reports[1].coverage, Coverage::EntireFile);
//! assert_eq!(reports[1].modification, ModificationLevel::None);
//! assert!(reports[1].is_acceptable(ModificationLevel::None));
//! # }
//! # Ok::<(), folioxide::Error>(())
//! ```

/// The version of the `folioxide` crate, for example `"0.1.0"`.
///
/// The Node package exposes the same value as `version()`, which lets callers check that the
/// JavaScript wrapper and the native addon come from the same release.
///
/// ```
/// assert_eq!(folioxide::VERSION.split('.').count(), 3);
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// The document model (M2 WP2.2 read side, WP2.3 write side and DTOs).
pub use folioxide_model::{
    DocInfo, Document, InfoUpdate, NameTree, NumberTree, Page, PageId, PageInfo, PdfDate, Rect,
    Rotation, Trapped, text,
};
mod error;

// The unified error (ARCHITECTURE §A.4, M3 brief §3.2 "Facade").
pub use error::{Error, Result};
/// The error of the syntax and model layers, which [`Document`] methods return; it converts
/// into [`enum@Error`] with `?`.
pub use folioxide_syntax::Error as SyntaxError;
// The syntax layer: error codes, options, diagnostics and the object model that `Document`
// exposes.
pub use folioxide_syntax::{
    Diagnostic, DiagnosticKind, Dict, ErrorCode, Limits, Name, Object, ObjectId, OpenOptions,
    PdfString, SharedBytes, Store, Strictness, shared_bytes,
};
// The writers' options (M2 WP2.1), for `Document::save` and `Document::save_incremental`.
pub use folioxide_syntax::{IncrementalOptions, SaveOptions, StreamCompression, XrefStyle};

/// The signature layer (`folioxide-sign`): key loading, the [`Signer`] trait, CMS, PAdES
/// signing and verification, certificate information and trust (M3). Its most used items are
/// also re-exported at the crate root.
#[cfg(feature = "signatures")]
pub use folioxide_sign as sign;
// Signing (M3 brief §3.2 "Facade").
#[cfg(feature = "signatures")]
pub use folioxide_sign::{
    Problem, ProblemCode,
    algorithms::{DigestAlgorithm, KeyKind, SignatureAlgorithm},
    field::{FieldMode, FieldSpec, SubFilter},
    finish::FinishError,
    prepare::{PrepareRequest, PreparedSignature, SignatureOptions, prepare},
    signer::{LocalSigner, Signer},
    x509info::{CertificateInfo, KeyDescription},
};
// One-step signing, verification and its report, signature fields, certificates and trust (M3
// WP3.3B). The function `sign` is in the value namespace and the module `sign` in the type
// namespace, so `folioxide::sign(&doc, &request)` and `folioxide::sign::cms` both work.
#[cfg(feature = "signatures")]
pub use folioxide_sign::{
    algorithms::default_digest,
    field::{SignatureField, signature_fields},
    keys::certificates_from_pem,
    report::{Coverage, ModificationLevel, PadesLevel, SignatureKind, SignatureReport},
    sign::{SignRequest, sign},
    verify_pdf::{VerifyOptions, verify, verify_bytes},
    x509info::{TrustResult, UnixTime, build_trust, certificate_info},
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_semver_core() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "VERSION {VERSION:?} is not MAJOR.MINOR.PATCH"
        );
        for part in parts {
            assert!(
                !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()),
                "VERSION {VERSION:?} has a non-numeric component"
            );
        }
    }

    #[test]
    fn model_is_reexported() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<Document>();
        assert_send_sync_static::<Error>();
        assert_send_sync_static::<SyntaxError>();
        assert_eq!(Rotation::from_degrees(-90), Some(Rotation::R270));
        assert_eq!(text::encode_text_string("\u{20AC}"), b"\xA0");
        assert_eq!(PdfDate::parse(b"D:2024").map(|d| d.year), Some(2024));
        let err = Document::open(Vec::new(), &OpenOptions::default()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Xref);
    }

    #[test]
    fn write_side_is_reexported() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<InfoUpdate>();
        assert_send_sync_static::<PageInfo>();
        assert_send_sync_static::<SaveOptions>();
        assert_send_sync_static::<IncrementalOptions>();

        let mut doc = Document::new();
        assert!(doc.is_modified());
        doc.set_info(&InfoUpdate::default().with_title(Some("\u{1F600}")))
            .unwrap();
        let options = SaveOptions::default()
            .with_xref(XrefStyle::Stream)
            .with_compress(StreamCompression::CompressNew);
        let pdf = doc.save(&options).unwrap();
        let reopened = Document::open(pdf, &OpenOptions::default()).unwrap();
        assert_eq!(reopened.page_count().unwrap(), 0);
        assert_eq!(reopened.info().unwrap().title.as_deref(), Some("\u{1F600}"));
        assert!(!reopened.is_modified());
        // A new document has no file to append to.
        let err = doc
            .save_incremental(&IncrementalOptions::default())
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }

    /// With the `serde` feature the DTOs serialize with `camelCase` names (the same JSON shape
    /// the Node binding uses, ARCHITECTURE §A.7).
    #[cfg(feature = "serde")]
    #[test]
    fn serde_feature_reaches_the_model() {
        fn assert_serde<T: serde::Serialize + serde::de::DeserializeOwned>() {}
        assert_serde::<DocInfo>();
        assert_serde::<InfoUpdate>();
        assert_serde::<PageInfo>();
        assert_serde::<Rect>();
        assert_serde::<Rotation>();
        assert_serde::<PdfDate>();
        assert_serde::<Trapped>();
        assert_serde::<Diagnostic>();
        assert_serde::<SaveOptions>();
        #[cfg(feature = "signatures")]
        {
            assert_serde::<CertificateInfo>();
            assert_serde::<KeyDescription>();
            assert_serde::<DigestAlgorithm>();
            assert_serde::<SignatureAlgorithm>();
            assert_serde::<KeyKind>();
            assert_serde::<Problem>();
            assert_serde::<SignatureReport>();
            assert_serde::<Coverage>();
            assert_serde::<ModificationLevel>();
            assert_serde::<SignatureKind>();
            assert_serde::<PadesLevel>();
            assert_serde::<VerifyOptions>();
            assert_serde::<SignatureOptions>();
            assert_serde::<PrepareRequest>();
            assert_serde::<PreparedSignature>();
            assert_serde::<FieldSpec>();
            assert_serde::<SignatureField>();
        }
    }

    /// The signing and verification API of M3 is reachable from the facade root with the
    /// signatures of the brief (§3.2), and its types are `Send + Sync + 'static` (ARCHITECTURE
    /// §A.8).
    #[cfg(feature = "signatures")]
    #[test]
    // The function-pointer types spell out the signatures on purpose.
    #[allow(clippy::type_complexity)]
    fn signature_api_is_reexported() {
        fn assert_send_sync_static<T: Send + Sync + 'static>() {}
        assert_send_sync_static::<LocalSigner>();
        assert_send_sync_static::<PreparedSignature>();
        assert_send_sync_static::<SignatureReport>();
        assert_send_sync_static::<VerifyOptions>();
        assert_send_sync_static::<TrustResult>();
        assert_send_sync_static::<SignRequest<'static>>();

        let _: fn(&Document, &PrepareRequest) -> sign::Result<PreparedSignature> = prepare;
        let _: fn(&Document, &SignRequest<'_>) -> sign::Result<Vec<u8>> = sign;
        let _: fn(&Document, &VerifyOptions) -> sign::Result<Vec<SignatureReport>> = verify;
        let _: fn(Vec<u8>, &VerifyOptions) -> sign::Result<Vec<SignatureReport>> = verify_bytes;
        let _: fn(&Document) -> sign::Result<Vec<SignatureField>> = signature_fields;
        let _: fn(&str) -> sign::Result<Vec<Vec<u8>>> = certificates_from_pem;
        let _: fn(&[u8]) -> sign::Result<CertificateInfo> = certificate_info;
        let _: fn(&[u8], &[Vec<u8>], &[Vec<u8>], UnixTime) -> TrustResult = build_trust;
        let _: fn(KeyKind) -> DigestAlgorithm = default_digest;

        // The module and the function share the name `sign`.
        let _: sign::report::Coverage = Coverage::EntireFile;
        assert_eq!(ModificationLevel::FormFilling.as_str(), "formFilling");
        assert_eq!(PadesLevel::BB.as_str(), "B-B");
        assert_eq!(SignatureKind::DocTimeStamp.as_str(), "docTimeStamp");
        assert_eq!(SubFilter::default().name(), "ETSI.CAdES.detached");
        assert_eq!(FieldSpec::default().mode, FieldMode::CreateOrUse);
    }

    /// A document without signatures verifies to an empty list; one with pending edits is
    /// refused with the facade's error code.
    #[cfg(feature = "signatures")]
    #[test]
    fn verify_through_the_facade() {
        let doc = Document::new();
        let err = Error::from(verify(&doc, &VerifyOptions::default()).unwrap_err());
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
        let pdf = doc.save(&SaveOptions::default()).unwrap();
        assert!(verify_bytes(pdf, &VerifyOptions::new()).unwrap().is_empty());
        let err =
            Error::from(verify_bytes(b"not a PDF".to_vec(), &VerifyOptions::new()).unwrap_err());
        assert_eq!(err.code(), ErrorCode::Xref);
        assert!(matches!(err, Error::Syntax(_)));
    }
}
