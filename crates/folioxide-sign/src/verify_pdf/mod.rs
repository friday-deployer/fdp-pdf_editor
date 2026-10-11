//! PDF signature verification: [`verify`], [`verify_bytes`] and [`VerifyOptions`] (ISO 32000-2
//! §12.8.1; M3 brief §5; ARCHITECTURE §A.6.7).
//!
//! Every signature dictionary of the document gets one [`SignatureReport`] (one per field that
//! shares it, within the bounds of V1), in signing order (by the end of the signed bytes),
//! orphans last:
//!
//! - **V0 input.** A document with pending edits is refused (DECISIONS D10 D-8). Every object
//!   is resolved once, so the store's repair state is complete.
//! - **V1 discovery.** The terminal `/FT /Sig` fields of `/AcroForm /Fields` (with `/Kids`,
//!   depth-bounded, cycle-safe) whose `/V` is set; then every `/Type /Sig` or `/DocTimeStamp`
//!   dictionary with `/ByteRange` or `/Contents` that no field refers to, as an orphan (problem
//!   `Orphan`). A signature dictionary is never left out of the list, up to the bounds of hostile
//!   input: one dictionary is reported for at most [`MAX_REPORTS_PER_SIGNATURE_DICTIONARY`] of
//!   the fields that share it, and at most [`MAX_REPORTS`] reports are returned, with warnings
//!   that count what was left out.
//! - **V2–V4 dictionary.** The `/SubFilter` route, a direct `/ByteRange` of four non-negative
//!   integers from 0 inside the file, a direct hexadecimal `/Contents`, an uncompressed
//!   dictionary inside the signed bytes, and a gap that is exactly this dictionary's own
//!   `/Contents` token, found by re-lexing the dictionary from the file (signature wrapping).
//! - **V5 coverage** (pyHanko's algorithm): the byte range ends at the end of the file
//!   ([`Coverage::EntireFile`]), or at the `%%EOF` of a revision of the chain with every
//!   section up to it signed and the dictionary not listed later
//!   ([`Coverage::EntireRevision`]); otherwise contiguous or unclear.
//! - **V10 modification**: the signed revision is compared with each later revision, as
//!   pyHanko's diff policy does; re-listings, `/Info`, metadata and new invisible signature
//!   fields are LTA updates, a new signature is form filling, everything else (and any repaired
//!   structure) is other.
//! - **V6–V9 CMS.** `intact` and `signature_valid` from
//!   [`cms::verify_detached`](crate::cms::verify_detached) over the byte ranges as written,
//!   the PAdES B-B profile, certificate information, and trust through
//!   [`build_trust`](crate::x509info::build_trust) when trust anchors are given: at the
//!   validation time of the options (or the claimed `/M`, with a warning), its reasons as
//!   warnings and its typed problems (a weak certification path) as problems, and never for a
//!   signature that is not intact and valid (pyHanko's `trusted`).
//!
//! Nothing here panics on hostile input: a defect is a [`Problem`](crate::Problem) in the
//! report, and only an unusable document is an error.

use folioxide_model::{Document, PdfDate};
use folioxide_syntax::{Object, ObjectId, OpenOptions};

use crate::error::{Error, Result};
use crate::problem::ProblemCode;
use crate::report::{Coverage, ModificationLevel, SignatureKind, SignatureReport};
use crate::revisions::Revisions;

mod crypto;
mod dict;
mod digests;
mod discovery;

/// The most signatures one verification checks in full (their CMS, certificates, trust and
/// modification analysis); the others are listed with their dictionary checks and coverage, and
/// a warning (R-18: a file with thousands of signature dictionaries cannot pin a worker). The
/// signatures whose `/ByteRange` ends where a revision of the file ends are verified first, so
/// junk dictionaries cannot crowd out the real signatures. The bytes hashed in total and the work
/// of the modification analyses are bounded too; a signature past those budgets is reported not
/// intact or `Other`, with a warning.
pub const MAX_VERIFIED_SIGNATURES: usize = 256;

/// The most reports one verification returns (R-18; QA finding: a 12 MB file with 100,000
/// signature fields cost gigabytes as reports). The signature dictionaries and signed fields
/// past it are not reported, and every report says how many were left out. The list stays
/// fail-closed: it is only cut when there are more than [`MAX_REPORTS`] candidates, and then all
/// but [`MAX_VERIFIED_SIGNATURES`] of the reports listed are not verified (and not valid), so a
/// document cannot look validly signed by crowding a report out.
pub const MAX_REPORTS: usize = 1024;

/// The most fields one signature dictionary is reported for (brief §5 V1: a dictionary that
/// several fields share is reported for each, with a warning). The other fields that share it
/// are counted in that warning: their reports would only repeat the same verification under
/// another name.
pub const MAX_REPORTS_PER_SIGNATURE_DICTIONARY: usize = 8;

/// The most objects one report's [`SignatureReport::changed_objects`] names (the first, by
/// object number); a warning gives the full count. Every report of a signature over a revision
/// would otherwise copy the whole changed set of the later revisions.
pub const MAX_CHANGED_OBJECTS: usize = 1024;

/// The problems that make [`SignatureReport::byte_range_ok`] false: the dictionary, byte range,
/// gap and revision checks (brief §5 V1–V5).
const STRUCTURAL: &[ProblemCode] = &[
    ProblemCode::SigValueNotIndirect,
    ProblemCode::SigDictNotDictionary,
    ProblemCode::ByteRangeMissing,
    ProblemCode::ByteRangeIndirect,
    ProblemCode::ByteRangeMalformed,
    ProblemCode::ByteRangeNotFromZero,
    ProblemCode::ByteRangeOutOfBounds,
    ProblemCode::ContentsMissing,
    ProblemCode::ContentsNotHex,
    ProblemCode::GapNotContents,
    ProblemCode::SigDictCompressed,
    ProblemCode::SigDictOutsideSignedRange,
    ProblemCode::SigDictRedefinedLater,
    ProblemCode::SignedRevisionNotInChain,
];

/// The options of [`verify`]: trust anchors, extra certificates and the validation time
/// (brief §3.2).
///
/// With the `serde` feature the fields are `trustAnchorsDer`, `extraCertsDer` (arrays of byte
/// arrays) and `validationTime` (a PDF date string), all optional.
///
/// ```
/// use folioxide_model::PdfDate;
/// use folioxide_sign::verify_pdf::VerifyOptions;
///
/// let now = PdfDate::parse(b"D:20261010120000Z").unwrap();
/// let options = VerifyOptions::default()
///     .with_trust_anchors_der(vec![b"root DER".to_vec()])
///     .with_validation_time(Some(now));
/// assert_eq!(options.trust_anchors_der.len(), 1);
/// ```
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", default)
)]
pub struct VerifyOptions {
    /// Trusted root certificates (DER). Without any, [`SignatureReport::trusted`] is `None`.
    pub trust_anchors_der: Vec<Vec<u8>>,
    /// More certificates (DER) for finding the signer and building certification paths, besides
    /// those the CMS carries.
    pub extra_certs_der: Vec<Vec<u8>>,
    /// The time at which certificates must be valid. `None`: the signer's claimed signing time
    /// `/M`, with a warning in each report (the core has no clock; the Node binding passes the
    /// current time).
    pub validation_time: Option<PdfDate>,
}

impl VerifyOptions {
    /// The default options: no trust anchors, no extra certificates, the claimed time.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets [`VerifyOptions::trust_anchors_der`].
    #[must_use]
    pub fn with_trust_anchors_der(mut self, anchors: Vec<Vec<u8>>) -> Self {
        self.trust_anchors_der = anchors;
        self
    }

    /// Sets [`VerifyOptions::extra_certs_der`].
    #[must_use]
    pub fn with_extra_certs_der(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.extra_certs_der = certs;
        self
    }

    /// Sets [`VerifyOptions::validation_time`].
    #[must_use]
    pub fn with_validation_time(mut self, time: Option<PdfDate>) -> Self {
        self.validation_time = time;
        self
    }
}

/// Verifies every signature of `doc` (brief §5): one report per signature dictionary, in
/// signing order, orphan dictionaries last (one per field for a dictionary that several fields
/// share, up to [`MAX_REPORTS_PER_SIGNATURE_DICTIONARY`]; at most [`MAX_REPORTS`] in all, with
/// warnings that count what was left out).
///
/// A document signed twice, verified with the test PKI root as trust anchor at a fixed time
/// (the core has no clock: pass the current time to validate now). The first signature covers
/// its revision, and the second signature is form filling for it:
///
/// ```
/// use folioxide_model::{Document, PdfDate};
/// use folioxide_sign::keys::certificates_from_pem;
/// use folioxide_sign::report::{Coverage, ModificationLevel, PadesLevel};
/// use folioxide_sign::sign::{SignRequest, sign};
/// use folioxide_sign::signer::LocalSigner;
/// use folioxide_sign::verify_pdf::{VerifyOptions, verify};
/// use folioxide_syntax::OpenOptions;
///
/// # let pki = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pki");
/// # let read = |name: &str| std::fs::read_to_string(pki.join(name));
/// # let rsa = LocalSigner::from_pkcs12(
/// #     &std::fs::read(pki.join("signer-rsa2048-modern.p12"))?,
/// #     "folioxide",
/// # )?;
/// # let p256 = LocalSigner::from_pkcs12(
/// #     &std::fs::read(pki.join("signer-p256-modern.p12"))?,
/// #     "folioxide",
/// # )?;
/// let time = PdfDate::parse(b"D:20261010120000Z").expect("a PDF date");
/// let open = |pdf: Vec<u8>| Document::open(pdf, &OpenOptions::default());
/// let once = sign(
///     &open(folioxide_testkit::fixtures::syntax::minimal())?,
///     &SignRequest::new(&rsa, time),
/// )?;
/// let twice = sign(&open(once)?, &SignRequest::new(&p256, time))?;
///
/// let options = VerifyOptions::new()
///     .with_trust_anchors_der(certificates_from_pem(&read("root.pem")?)?)
///     .with_validation_time(Some(time));
/// let reports = verify(&open(twice)?, &options)?;
/// let [first, second] = reports.as_slice() else { panic!("two signatures") };
///
/// assert_eq!(first.field_name.as_deref(), Some("Signature1"));
/// assert!(first.is_valid() && first.trusted == Some(true));
/// assert_eq!(first.coverage, Coverage::EntireRevision);
/// assert_eq!(first.modification, ModificationLevel::FormFilling);
///
/// assert!(second.is_valid() && second.trusted == Some(true));
/// assert_eq!(second.coverage, Coverage::EntireFile);
/// assert_eq!(second.modification, ModificationLevel::None);
/// assert_eq!(second.pades_level, Some(PadesLevel::BB));
/// assert_eq!(
///     second.signer.as_ref().and_then(|c| c.common_name.as_deref()),
///     Some("Folioxide Test Signer P-256")
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// A document without signatures has no report:
///
/// ```
/// use folioxide_model::Document;
/// use folioxide_sign::verify_pdf::{VerifyOptions, verify};
/// use folioxide_syntax::OpenOptions;
///
/// let pdf = folioxide_testkit::fixtures::syntax::minimal();
/// let doc = Document::open(pdf, &OpenOptions::default())?;
/// assert!(verify(&doc, &VerifyOptions::default())?.is_empty());
/// # Ok::<(), folioxide_sign::Error>(())
/// ```
///
/// # Errors
/// Only when the document is unusable:
/// - [`Error::InvalidArgument`]: the document has pending edits (the bytes on disk would not be
///   what is verified; save first, DECISIONS D10 D-8).
/// - The errors of [`Document::catalog`] (a missing or unreadable catalog).
pub fn verify(doc: &Document, opts: &VerifyOptions) -> Result<Vec<SignatureReport>> {
    let store = doc.store();
    if store.is_modified() {
        return Err(Error::InvalidArgument(
            "the document has pending edits; save it and verify the saved file".to_owned(),
        ));
    }
    // V0: resolve every object once, so that the repair state (recovered objects) is complete.
    for id in store.object_ids() {
        let _ = store.resolve(id);
    }

    let found = discovery::discover(doc)?;
    let revisions = Revisions::new(doc);
    let digests = digests::Digests::new(store.source());
    let repairs = repair_summary(doc);

    let full = verified_in_full(&found.candidates, &revisions);
    let mut reports = Vec::with_capacity(found.candidates.len());
    for (index, candidate) in found.candidates.iter().enumerate() {
        let full = full.contains(&index);
        let mut report = verify_one(doc, &revisions, &digests, candidate, opts, full);
        apply_repairs(&mut report, repairs.as_deref());
        for warning in &found.warnings {
            report.warn(warning.clone());
        }
        reports.push(report);
    }
    // Signing order: by the end of the signed bytes; orphans last (validate_sig.py's order).
    reports.sort_by_key(|r| (r.field_name.is_none(), sort_key(r)));
    Ok(reports)
}

/// [`verify`] for the bytes of a PDF file, opened leniently with the default limits.
///
/// A changed byte inside the signed ranges breaks the signature (`intact` false), and a
/// changed document is never trusted:
///
/// ```
/// use folioxide_model::{Document, PdfDate};
/// use folioxide_sign::ProblemCode;
/// use folioxide_sign::sign::{SignRequest, sign};
/// use folioxide_sign::signer::LocalSigner;
/// use folioxide_sign::verify_pdf::{VerifyOptions, verify_bytes};
/// use folioxide_syntax::OpenOptions;
///
/// # let pki = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pki");
/// # let signer = LocalSigner::from_pkcs12(
/// #     &std::fs::read(pki.join("signer-p256-modern.p12"))?,
/// #     "folioxide",
/// # )?;
/// # let root = folioxide_sign::keys::certificates_from_pem(
/// #     &std::fs::read_to_string(pki.join("root.pem"))?,
/// # )?;
/// let time = PdfDate::parse(b"D:20261010120000Z").expect("a PDF date");
/// let source = folioxide_testkit::fixtures::syntax::minimal();
/// let doc = Document::open(source, &OpenOptions::default())?;
/// let mut signed = sign(&doc, &SignRequest::new(&signer, time))?;
/// let options = VerifyOptions::new()
///     .with_trust_anchors_der(root)
///     .with_validation_time(Some(time));
/// assert!(verify_bytes(signed.clone(), &options)?[0].is_valid());
///
/// // Change one byte of the page content (signed part 1).
/// let at = signed.windows(8).position(|w| w == b"minimal)").expect("the page text");
/// signed[at] = b'M';
/// let report = &verify_bytes(signed, &options)?[0];
/// assert!(!report.intact && !report.is_valid());
/// assert!(report.has_problem(ProblemCode::DigestMismatch));
/// assert_eq!(report.trusted, Some(false));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
/// The errors of [`Document::open`] (an unreadable or encrypted file), and those of
/// [`verify`].
pub fn verify_bytes(pdf: Vec<u8>, opts: &VerifyOptions) -> Result<Vec<SignatureReport>> {
    let doc = Document::open(pdf, &OpenOptions::default())?;
    verify(&doc, opts)
}

/// The candidates verified in full, at most [`MAX_VERIFIED_SIGNATURES`]: first those whose
/// `/ByteRange` ends where a revision of the file ends (a signature can only cover a revision
/// there, so junk dictionaries cannot crowd out the real signatures), then the others, each
/// group in discovery order.
fn verified_in_full(
    candidates: &[discovery::Candidate],
    revisions: &Revisions<'_>,
) -> std::collections::BTreeSet<usize> {
    if candidates.len() <= MAX_VERIFIED_SIGNATURES {
        return (0..candidates.len()).collect();
    }
    let ends_a_revision = |candidate: &discovery::Candidate| {
        let range = candidate
            .dict
            .as_deref()
            .and_then(Object::as_dict)
            .and_then(|d| d.get_array(b"ByteRange"))
            .and_then(|items| {
                items
                    .iter()
                    .map(Object::as_int)
                    .collect::<Option<Vec<i64>>>()
            });
        match range.as_deref() {
            Some([_, _, o2, l2]) => o2
                .checked_add(*l2)
                .and_then(|end| u64::try_from(end).ok())
                .is_some_and(|end| revisions.find_signed_revision(end).is_some()),
            _ => false,
        }
    };
    let mut order: Vec<usize> = (0..candidates.len()).collect();
    order.sort_by_key(|&index| !candidates.get(index).is_some_and(ends_a_revision));
    order.into_iter().take(MAX_VERIFIED_SIGNATURES).collect()
}

/// The order key: the end of the signed bytes (`o2 + l2`), unknown last.
fn sort_key(report: &SignatureReport) -> i64 {
    match report.byte_range.as_deref() {
        Some([_, _, o2, l2, ..]) => o2.saturating_add(*l2),
        _ => i64::MAX,
    }
}

/// One report; `full` false checks only the dictionary and the coverage (past
/// [`MAX_VERIFIED_SIGNATURES`]).
fn verify_one(
    doc: &Document,
    revisions: &Revisions<'_>,
    digests: &digests::Digests<'_>,
    candidate: &discovery::Candidate,
    opts: &VerifyOptions,
    full: bool,
) -> SignatureReport {
    let sig_object = candidate
        .sig_id
        .or(candidate.field_id)
        .unwrap_or(ObjectId::new(0, 0));
    let sig_dict = candidate.dict.as_deref().and_then(Object::as_dict);
    let kind = match sig_dict {
        Some(dict) => dict::kind_of(dict),
        None => SignatureKind::Signature,
    };
    let mut report = SignatureReport::new(kind, sig_object);
    report.field_name = candidate.field_name.clone();
    for (code, message) in &candidate.problems {
        report.problem(*code, message.clone());
    }
    for warning in &candidate.warnings {
        report.warn(warning.clone());
    }
    let Some(sig_dict) = sig_dict else {
        // /V is not a dictionary: nothing else can be checked.
        return report;
    };

    // V2–V4: the dictionary, the byte range, /Contents and the gap.
    let checked = dict::check(doc, candidate.sig_id, sig_dict, &mut report);

    // V6–V9: the CMS.
    if full {
        crypto::check(doc, sig_dict, &checked, opts, digests, &mut report);
    } else {
        report.warn(format!(
            "not verified: the document has more than {MAX_VERIFIED_SIGNATURES} signature \
             dictionaries, and only {MAX_VERIFIED_SIGNATURES} are verified in full (those whose \
             byte range ends at a revision first)"
        ));
    }

    // V5: coverage.
    let outcome = match &report.byte_range {
        Some(values) => revisions.coverage(values, checked.gap_ok, candidate.sig_id),
        None => revisions.coverage(&[], false, candidate.sig_id),
    };
    report.coverage = outcome.coverage;
    report.signed_revision = outcome.signed_revision;
    if let Some((code, message)) = outcome.problem {
        report.problem(code, message);
    }

    // V10: what later revisions changed.
    match report.coverage {
        Coverage::EntireFile => report.modification = ModificationLevel::None,
        Coverage::EntireRevision if !full => report.modification = ModificationLevel::Other,
        Coverage::EntireRevision => match report.signed_revision {
            Some(k) => {
                let outcome = revisions.modification(k);
                report.modification = outcome.level;
                report.changed_objects = outcome.changed;
                if outcome.changed_total > report.changed_objects.len() {
                    report.warn(format!(
                        "the revisions after the signed one list {} objects; changed objects \
                         names the first {}",
                        outcome.changed_total,
                        report.changed_objects.len()
                    ));
                }
                for note in outcome.notes {
                    report.warn(format!("modified after signing: {note}"));
                }
            }
            None => report.modification = ModificationLevel::Other,
        },
        _ => report.modification = ModificationLevel::Other,
    }

    report.byte_range_ok = !STRUCTURAL.iter().any(|&code| report.has_problem(code));
    // V8: PAdES B-B only for a signature that is sound in every other way.
    if !(report.byte_range_ok && report.intact && report.signature_valid) {
        report.pades_level = None;
    }
    report
}

/// What was repaired when the file was opened, or `None` when nothing was: the diagnostic
/// kinds, and the recovered objects.
fn repair_summary(doc: &Document) -> Option<String> {
    let store = doc.store();
    let recovered = store.recovered_objects();
    if !store.structure_repaired() && recovered.is_empty() {
        return None;
    }
    let mut kinds: Vec<String> = store
        .diagnostics()
        .iter()
        .map(|d| format!("{:?}", d.kind))
        .collect();
    kinds.sort_unstable();
    kinds.dedup();
    let mut summary = if kinds.is_empty() {
        "the file's structure was repaired when it was opened".to_owned()
    } else {
        format!(
            "the file's structure was repaired when it was opened ({})",
            kinds.join(", ")
        )
    };
    if !recovered.is_empty() {
        let shown: Vec<String> = recovered.iter().take(8).map(ToString::to_string).collect();
        summary.push_str(&format!(
            "; {} object(s) were recovered: {}",
            recovered.len(),
            shown.join(", ")
        ));
    }
    Some(summary)
}

/// Repairs are changes that cannot be attributed to a revision (brief §5 V10 "Repairs"): a
/// signature over the whole file keeps `None` with a warning; any other is `Other` with the
/// problem `StructureRepaired`.
fn apply_repairs(report: &mut SignatureReport, repairs: Option<&str>) {
    let Some(repairs) = repairs else {
        return;
    };
    if report.coverage == Coverage::EntireFile {
        report.warn(format!(
            "{repairs}; every byte of the file is signed, so the signature is not affected"
        ));
    } else {
        report.modification = ModificationLevel::Other;
        report.problem(
            ProblemCode::StructureRepaired,
            format!("{repairs}: changes after the signed revision cannot be attributed"),
        );
        report.byte_range_ok =
            report.byte_range_ok && !STRUCTURAL.iter().any(|&code| report.has_problem(code));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_builders() {
        let time = PdfDate::parse(b"D:20261010120000Z").unwrap();
        let options = VerifyOptions::new()
            .with_trust_anchors_der(vec![vec![1]])
            .with_extra_certs_der(vec![vec![2], vec![3]])
            .with_validation_time(Some(time));
        assert_eq!(options.trust_anchors_der, [vec![1]]);
        assert_eq!(options.extra_certs_der.len(), 2);
        assert_eq!(options.validation_time, Some(time));
        assert_eq!(VerifyOptions::new(), VerifyOptions::default());
    }

    #[test]
    fn sort_keys() {
        let mut report = SignatureReport::new(SignatureKind::Signature, ObjectId::new(1, 0));
        assert_eq!(sort_key(&report), i64::MAX);
        report.byte_range = Some(vec![0, 10, 20, 5]);
        assert_eq!(sort_key(&report), 25);
        report.byte_range = Some(vec![0, 10, i64::MAX, 5]);
        assert_eq!(sort_key(&report), i64::MAX);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn options_serde() {
        let options: VerifyOptions = serde_json::from_value(serde_json::json!({
            "trustAnchorsDer": [[1, 2]],
            "validationTime": "D:20261010120000Z"
        }))
        .unwrap();
        assert_eq!(options.trust_anchors_der, [vec![1, 2]]);
        assert!(options.validation_time.is_some());
        assert!(options.extra_certs_der.is_empty());
    }
}
