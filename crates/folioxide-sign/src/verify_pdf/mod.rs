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
//!   fields are LTA updates, a new signature and whitelisted form filling (M4 brief §5.1) are
//!   form filling, whitelisted markup annotations (§5.2, D-1) are annotations, everything else
//!   (and any repaired structure) is other. After a certification signature (or a signature
//!   whose field's `/Lock` has `/P`) a new visible signature field is other (§5.3 C1).
//! - **V11 DocMDP** (M4 brief §5 V11, §5.3): the permissions `P` a signature declares, by its
//!   DocMDP reference or its field's `/Lock /P`, the stricter of the two (`DocMdpInvalid` for a
//!   declaration that cannot be read, which then counts as `P = 1`; `CertificationNotFirst` for
//!   a certification that is not the first signature), and `docmdp_ok`: whether the later
//!   revisions respect the permissions in force for the signature (its own `P`, else that of
//!   an earlier signature that set permissions, else 2); `None` for a document timestamp.
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

use std::collections::BTreeSet;

use folioxide_model::{Document, PdfDate};
use folioxide_syntax::{Object, ObjectId, OpenOptions};

use crate::docmdp;
use crate::error::{Error, Result};
use crate::problem::ProblemCode;
use crate::report::{Coverage, ModificationLevel, SignatureKind, SignatureReport};
use crate::revisions::{ChangeClass, ModificationContext, Revisions};

mod crypto;
mod dict;
mod digests;
mod discovery;
mod timestamp;

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
    ProblemCode::SigDictAmbiguous,
    ProblemCode::SignedRevisionNotInChain,
];

/// The options of [`verify`]: trust anchors, extra certificates and the validation time
/// (brief §3.2), and the trust anchors of timestamps (M4 brief §3.3).
///
/// With the `serde` feature the fields are `trustAnchorsDer`, `extraCertsDer` (arrays of byte
/// arrays), `validationTime` (a PDF date string) and `timestampTrustAnchorsDer`, all optional.
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
    /// The time at which certificate paths are validated (M4 brief §5 V7b step 9 and V9), for
    /// the signer and every TSA alike. `None` (the core has no clock):
    ///
    /// - a timestamp token's TSA path is validated at that token's own `genTime`, and a token
    ///   trusted that way carries a warning;
    /// - the signer's path at the `genTime` of its selected signature timestamp when that token
    ///   is trusted (DECISIONS D13 D-7), else at the claimed signing time `/M`, each with a
    ///   warning in the report (and not trusted without `/M`).
    ///
    /// **`None` is circular for a retired TSA key** (QA round 1 finding F8): `genTime` is the
    /// TSA's own claim, so a TSA key whose certificate has expired (or a key stolen after its
    /// TSA retired it) can still sign a token that claims a time inside that certificate's
    /// validity; validated at that time, the token is trusted, and so is a signer whose
    /// certificate was valid then. Only a validation time breaks the circle.
    ///
    /// This is no ETSI EN 319 102-1 past-time validation (no proof of existence, no revocation
    /// data): a `genTime` or `/M` only moves the time the certificates are checked at. To ask
    /// whether a signature is trusted now, pass the current time, as the Node binding does.
    pub validation_time: Option<PdfDate>,
    /// Trusted root certificates (DER) for timestamp authorities (M4 brief §5 V7b step 9);
    /// `None`: [`trust_anchors_der`](Self::trust_anchors_der), as pyHanko does.
    pub timestamp_trust_anchors_der: Option<Vec<Vec<u8>>>,
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

    /// Sets [`VerifyOptions::timestamp_trust_anchors_der`].
    #[must_use]
    pub fn with_timestamp_trust_anchors_der(mut self, anchors: Option<Vec<Vec<u8>>>) -> Self {
        self.timestamp_trust_anchors_der = anchors;
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
/// - [`Error::Syntax`] with [`ErrorCode::Xref`](folioxide_syntax::ErrorCode::Xref): the
///   revision chain is ambiguous, because a trailer or cross-reference stream dictionary of the
///   chain gives `/Prev` or `/XRefStm` twice with different values (M4 QA round 2, finding 9).
///   Readers that keep the first value (pyHanko, pypdf) follow other revisions than Folioxide's
///   parser (the last), and may see a signed revision, and signatures, that this reading skips;
///   an empty or partial list would then be wrong, so there is none.
/// - The errors of [`Document::catalog`] (a missing or unreadable catalog).
pub fn verify(doc: &Document, opts: &VerifyOptions) -> Result<Vec<SignatureReport>> {
    let store = doc.store();
    if store.is_modified() {
        return Err(Error::InvalidArgument(
            "the document has pending edits; save it and verify the saved file".to_owned(),
        ));
    }
    if let Some(reason) = crate::revisions::differential::chain_ambiguity(store) {
        return Err(Error::Syntax(folioxide_syntax::Error::Xref {
            offset: None,
            message: format!("the signatures cannot be verified: {reason}").into(),
        }));
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
    let mut checked = Vec::with_capacity(found.candidates.len());
    for (index, candidate) in found.candidates.iter().enumerate() {
        let full = full.contains(&index);
        checked.push(verify_one(doc, &revisions, &digests, candidate, opts, full));
    }
    docmdp_verdicts(
        &mut checked,
        &revisions,
        repairs.as_deref(),
        &found.warnings,
    );
    let mut reports: Vec<SignatureReport> = checked.into_iter().map(|(r, _)| r).collect();
    // Signing order: by the end of the signed bytes; orphans last (validate_sig.py's order).
    reports.sort_by_key(|r| (r.field_name.is_none(), sort_key(r)));
    Ok(reports)
}

/// What V10 and V11 need of one report besides the report: the classes of the changes after its
/// signed revision, whether its dictionary declares a certification (valid or not), whether it
/// sets DocMDP permissions for the document (a certification, or a field `/Lock /P`), and the
/// V10 analysis still to run once the permissions in force are known (its signed revision and
/// context; [`docmdp_verdicts`]).
struct Classified {
    classes: BTreeSet<ChangeClass>,
    certification: bool,
    restricts: bool,
    pending: Option<(usize, ModificationContext)>,
}

/// The end of a report's signed bytes (`o2 + l2`), when its byte range has four values.
fn signed_end(report: &SignatureReport) -> Option<i64> {
    match report.byte_range.as_deref() {
        Some([_, _, o2, l2]) => o2.checked_add(*l2),
        _ => None,
    }
}

/// V10 and V11 across the reports (M4 brief §5 V10, V11, §5.3):
///
/// - `CertificationNotFirst` for a certification signature that is not the earliest-ending
///   signed field (by `b + c`, document timestamps included; ISO 32000-2 §12.8.2.2.1);
/// - `P_effective`: for a signature that sets permissions (a certification's, or its field's
///   `/Lock /P`, the stricter of the two; an invalid declaration counts as 1), the stricter of
///   its own `P` and the smallest `P` of the signatures of fields that set permissions and whose
///   signed bytes end no later than its own (ISO 32000-2 §12.7.5.5, the field lock's `/P`:
///   permissions already in effect can be denied but not added, a greater number is ignored;
///   M4 QA round 4, expert finding); for any other signature that smallest `P`, else 2;
/// - the modification analysis of each signature whose revision is covered (V10), run with
///   `P_effective` as the permissions of a signature that sets them, so that a new annotation
///   after an approval with `/Lock /P 3` in a document certified with `P = 2` is `Other` (as in
///   pyHanko), not `Annotations`, and of a document timestamp too, so that a new annotation
///   after it is `Other` unless `P = 3` is in force (manager ruling R-20: a timestamp's
///   `docmdp_ok` is `None`, so its level alone must respect the permissions); then what the
///   opening repaired (`repairs`, which makes a change after the signed revision `Other`) and
///   the discovery `warnings`;
/// - `docmdp_ok` for every report but a document timestamp's (which has no DocMDP of its own,
///   as in pyHanko: its integrity is `modification`; manager ruling R-5), from `P_effective`:
///   - `P = 1`: nothing but re-listings, orphans, cross-reference streams and document
///     timestamps (D-2; stricter than pyHanko, which accepts `LTA_UPDATES`);
///   - `P = 2`: at most `FormFilling`;
///   - `P = 3`: at most `Annotations` (D-1, the only level more lenient than pyHanko);
///   - `Other` is never acceptable (pyHanko: `docmdp_ok` false), whatever the coverage.
fn docmdp_verdicts(
    reports: &mut [(SignatureReport, Classified)],
    revisions: &Revisions<'_>,
    repairs: Option<&str>,
    warnings: &[String],
) {
    let fields = reports
        .iter()
        .filter(|(r, _)| r.field_name.is_some())
        .filter_map(|(r, c)| signed_end(r).map(|end| (end, r, c)));
    let earliest = fields.clone().map(|(end, ..)| end).min();
    // The signed fields that set permissions (certifications and field locks with /P): their
    // end and their P (1 when it cannot be read).
    let certifications: Vec<(i64, u8)> = fields
        .filter(|(_, _, c)| c.restricts)
        .map(|(end, r, _)| (end, r.docmdp.unwrap_or(1)))
        .collect();
    for (report, classified) in reports.iter_mut() {
        let end = signed_end(report);
        // The permissions in force when the signature was made, its own included.
        let in_force = end.and_then(|end| {
            certifications
                .iter()
                .filter(|(cert_end, _)| *cert_end <= end)
                .map(|(_, p)| *p)
                .min()
        });
        let p_effective = if classified.restricts {
            let own = report.docmdp.unwrap_or(1);
            in_force.map_or(own, |p| p.min(own))
        } else {
            in_force.unwrap_or(2)
        };
        if let Some((k, mut context)) = classified.pending.take() {
            // A signature that sets permissions, and a document timestamp (which has no
            // docmdp_ok of its own, so its level must respect them: manager ruling R-20), are
            // judged with the permissions in force.
            if classified.restricts || context.timestamp {
                context.permissions = Some(p_effective);
            }
            classify(report, classified, revisions, k, &context);
        }
        apply_repairs(report, repairs);
        for warning in warnings {
            report.warn(warning.clone());
        }
        if classified.certification
            && report.field_name.is_some()
            && let (Some(end), Some(earliest)) = (end, earliest)
            && end > earliest
        {
            report.problem(
                ProblemCode::CertificationNotFirst,
                "the signature declares DocMDP permissions, but another signature was signed \
                 before it; a certification signature shall be the first signed field (ISO \
                 32000-2 §12.8.2.2.1)",
            );
        }
        if report.kind == SignatureKind::DocTimeStamp {
            report.docmdp_ok = None;
            continue;
        }
        report.docmdp_ok = Some(docmdp_ok(
            p_effective,
            report.modification,
            &classified.classes,
        ));
    }
}

/// V10 for a report whose signed revision `k` is covered: what the later revisions changed,
/// judged in `context` (brief §5 V10).
fn classify(
    report: &mut SignatureReport,
    classified: &mut Classified,
    revisions: &Revisions<'_>,
    k: usize,
    context: &ModificationContext,
) {
    let outcome = revisions.modification(k, context);
    report.modification = outcome.level;
    report.changed_objects = outcome.changed;
    if !outcome.classes.is_empty() {
        let classes: Vec<&str> = outcome.classes.iter().map(|c| c.as_str()).collect();
        report.warn(format!(
            "changes after signing, by class: {}",
            classes.join(", ")
        ));
    }
    classified.classes = outcome.classes;
    if outcome.changed_total > report.changed_objects.len() {
        report.warn(format!(
            "the revisions after the signed one list {} objects; changed objects names the \
             first {}",
            outcome.changed_total,
            report.changed_objects.len()
        ));
    }
    for note in outcome.notes {
        report.warn(format!("modified after signing: {note}"));
    }
}

/// The `docmdp_ok` formula of M4 brief §5.3 C3 for the permissions `p` in force.
fn docmdp_ok(p: u8, modification: ModificationLevel, classes: &BTreeSet<ChangeClass>) -> bool {
    if modification == ModificationLevel::Other {
        return false;
    }
    match p {
        1 => classes.iter().all(|c| ChangeClass::NO_CHANGES.contains(c)),
        2 => modification <= ModificationLevel::FormFilling,
        _ => modification <= ModificationLevel::Annotations,
    }
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

/// One report, and what V11 needs of it; `full` false checks only the dictionary and the
/// coverage (past [`MAX_VERIFIED_SIGNATURES`]).
fn verify_one(
    doc: &Document,
    revisions: &Revisions<'_>,
    digests: &digests::Digests<'_>,
    candidate: &discovery::Candidate,
    opts: &VerifyOptions,
    full: bool,
) -> (SignatureReport, Classified) {
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
    let mut classified = Classified {
        classes: BTreeSet::new(),
        certification: false,
        restricts: false,
        pending: None,
    };
    let Some(sig_dict) = sig_dict else {
        // /V is not a dictionary: nothing else can be checked.
        return (report, classified);
    };

    // V2–V4: the dictionary, the byte range, /Contents and the gap.
    let mut checked = dict::check(doc, candidate.sig_id, sig_dict, &mut report);

    // M4 QA round 2, finding 8 (manager ruling R-1 applied to what the verdict reads; round 3,
    // ruling R-12): an entry of the signature dictionary or of its field that readers read
    // differently (written twice, or not canonical: a duplicate key, ISO 32000-2 §7.3.7, pyHanko
    // keeps the first value and Folioxide's parser the last; or a number or name spelling such
    // as `++2` or `4294967298`, which PDFium reads as 0). A /ByteRange or /Contents read either
    // way names other signed bytes, so
    // the signature is not intact and its coverage unclear; an ambiguous /Reference or /Lock
    // is DocMdpInvalid (V11 below).
    let ambiguity = docmdp::Ambiguity::of(
        doc.store(),
        revisions.ambiguous_keys(),
        candidate.sig_id,
        candidate.field_id,
    );
    let named = |keys: &BTreeSet<Vec<u8>>| -> Vec<String> {
        keys.iter()
            .map(|key| format!("/{}", String::from_utf8_lossy(key)))
            .collect()
    };
    if let Some(reason) = &ambiguity.unreadable {
        report.problem(
            ProblemCode::SigDictAmbiguous,
            format!(
                "the signature dictionary or its field cannot be re-read to check that every \
                 reader reads it the same way: {reason}"
            ),
        );
    } else if !ambiguity.sig_keys.is_empty() || !ambiguity.field_keys.is_empty() {
        let mut parts = Vec::new();
        if !ambiguity.sig_keys.is_empty() {
            parts.push(format!(
                "the signature dictionary's {}",
                named(&ambiguity.sig_keys).join(", ")
            ));
        }
        if !ambiguity.field_keys.is_empty() {
            parts.push(format!(
                "the signature field's {}",
                named(&ambiguity.field_keys).join(", ")
            ));
        }
        report.problem(
            ProblemCode::SigDictAmbiguous,
            format!(
                "{} written twice, or holding a duplicate key or a number or name spelling \
                 that readers read differently: readers differ on what it holds (pyHanko keeps \
                 the first value of a key, Folioxide's parser the last, ISO 32000-2 §7.3.7; \
                 PDFium reads `++2` or `4294967298` as 0, manager ruling R-12)",
                parts.join(" and ")
            ),
        );
    }
    let ranges_ambiguous = ambiguity.unreadable.is_some()
        || ambiguity
            .sig_keys
            .iter()
            .any(|key| matches!(key.as_slice(), b"ByteRange" | b"Contents"));
    if ranges_ambiguous {
        // Not digested: another reader signs other bytes (pyHanko: not intact).
        checked.ranges = None;
        checked.gap_ok = false;
    }

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

    // V11: what the dictionary declares (M4 brief §5 V11), and the field's /Lock (FieldMDP, and
    // its /P: manager ruling R-4).
    let field = candidate
        .field_id
        .and_then(|field| doc.store().resolve(field).ok());
    let declared = docmdp::declared(
        doc,
        sig_dict,
        sig_object,
        field.as_deref().and_then(Object::as_dict),
        &ambiguity,
    );
    report.docmdp = declared.permissions;
    for (code, message) in &declared.problems {
        report.problem(*code, message.clone());
    }
    for warning in &declared.warnings {
        report.warn(warning.clone());
    }
    let context = ModificationContext {
        certifying: declared.restricts,
        permissions: declared.permissions,
        field_mdp: declared.field_mdp,
        timestamp: kind == SignatureKind::DocTimeStamp,
    };
    classified.certification = declared.certification;
    classified.restricts = declared.restricts;

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

    // V10: what later revisions changed, analysed once the permissions in force across the
    // signatures are known (`docmdp_verdicts`: an earlier certification may grant fewer than
    // this signature's field lock declares).
    match report.coverage {
        Coverage::EntireFile => report.modification = ModificationLevel::None,
        Coverage::EntireRevision if !full => report.modification = ModificationLevel::Other,
        Coverage::EntireRevision => match report.signed_revision {
            Some(k) => classified.pending = Some((k, context)),
            None => report.modification = ModificationLevel::Other,
        },
        _ => report.modification = ModificationLevel::Other,
    }

    report.byte_range_ok = !STRUCTURAL.iter().any(|&code| report.has_problem(code));
    // V8: PAdES B-B only for a signature that is sound in every other way.
    if !(report.byte_range_ok && report.intact && report.signature_valid) {
        report.pades_level = None;
    }
    (report, classified)
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
