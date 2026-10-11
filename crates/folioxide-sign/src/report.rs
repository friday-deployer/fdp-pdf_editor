//! The verification report (M3 brief §3.2, DECISIONS D10 D-4): [`SignatureReport`] and its enums
//! [`SignatureKind`], [`Coverage`], [`ModificationLevel`] and [`PadesLevel`].
//!
//! [`Coverage`] and [`ModificationLevel`] mirror pyHanko's `SignatureCoverageLevel` and
//! `ModificationLevel` one to one, so that a report can be compared with the reference validator
//! (brief §0). The problem codes are [`Problem`] and [`ProblemCode`](crate::ProblemCode).
//!
//! With the `serde` feature every DTO is `camelCase`: the enums are the strings
//! [`Coverage::as_str`], [`ModificationLevel::as_str`] and so on return (`"entireFile"`,
//! `"formFilling"`, `"B-B"`), and an [`ObjectId`] is `{"num": 12, "gen": 0}`.

use std::fmt;

use folioxide_syntax::ObjectId;

use crate::problem::Problem;
use crate::x509info::CertificateInfo;

/// What a signature dictionary is (ISO 32000-2 §12.8.1, Table 255 `/Type`).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum SignatureKind {
    /// A signature (`/Type /Sig`, or no `/Type`).
    Signature,
    /// A document timestamp (`/Type /DocTimeStamp` or `/SubFilter /ETSI.RFC3161`, §12.8.5). M3
    /// lists them without verifying them (problem `PendingTimestampVerification`).
    DocTimeStamp,
}

impl SignatureKind {
    /// `"signature"` or `"docTimeStamp"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            SignatureKind::Signature => "signature",
            SignatureKind::DocTimeStamp => "docTimeStamp",
        }
    }
}

/// How much of the file a signature's byte ranges cover (pyHanko's `SignatureCoverageLevel`,
/// brief §5 V5), from the best to the worst.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum Coverage {
    /// The byte ranges cover the whole file but the signature's own `/Contents`.
    EntireFile,
    /// The byte ranges cover exactly one complete revision (up to its `%%EOF`), and later
    /// revisions were appended: see [`SignatureReport::modification`].
    EntireRevision,
    /// The byte ranges start at 0 and leave out only `/Contents`, but do not end at a revision
    /// of the file's revision chain.
    ContiguousBlockFromStart,
    /// Anything else: an unusual byte range, or a gap that is not the signature's `/Contents`.
    Unclear,
}

impl Coverage {
    /// `"entireFile"`, `"entireRevision"`, `"contiguousBlockFromStart"` or `"unclear"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Coverage::EntireFile => "entireFile",
            Coverage::EntireRevision => "entireRevision",
            Coverage::ContiguousBlockFromStart => "contiguousBlockFromStart",
            Coverage::Unclear => "unclear",
        }
    }
}

impl fmt::Display for Coverage {
    /// Writes [`Coverage::as_str`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the revisions appended after a signature changed, in pyHanko's vocabulary (its
/// `ModificationLevel`, brief §5 V10), ordered from harmless to anything: `None < LtaUpdates <
/// FormFilling < Annotations < Other`.
///
/// The level is **never more lenient than pyHanko's** default diff policy: for any file it is
/// the level pyHanko 0.37 reports or a higher one, never a lower one. The classifier is a
/// whitelist: a later revision gets a level below [`Other`](ModificationLevel::Other) only for
/// the exact changes legitimate later signers make. Where that is stricter than pyHanko, the
/// case is listed in the deliberate-differences table of the M3 brief (§0) and in the attack
/// corpus: generic form-field changes, `/DSS` updates, annotations and repaired structures are
/// `Other` in M3 (DECISIONS D10 D-9), and so is every change outside the whitelist, for example
/// a new signature field with an action, optional content or a `/Parent`, and every change to
/// the AcroForm beyond its three allowed changes (new root-level signature fields in `/Fields`,
/// `/SigFlags` as signing requires, new `/DR` names the signed revision does not name): any
/// change to `/NeedAppearances` (removing it too, also when a later signer such as pyHanko's
/// removes it while signing) or `/DA` (adding one too), any `/Q` change, changing or removing a
/// `/DR` name, adding one the signed revision already names, or adding a `/DR` entry outside
/// the resource categories. The residuals of the levels below `Other` are documented on
/// [`SignatureReport::is_acceptable`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum ModificationLevel {
    /// Nothing was appended after the signed revision.
    None,
    /// Only updates that keep the document's content: re-listed objects, `/Info`, XMP metadata,
    /// cross-reference streams, new invisible signature fields (without actions), new
    /// `/Fields` entries for them.
    LtaUpdates,
    /// Signing (a new signature dictionary) and filling signature fields, with the appearance
    /// a signed field may get; also a new visible signature field with an appearance, signed
    /// or not, and new AcroForm `/DR` resource names that the signed revision does not name. A
    /// new appearance can cover signed content (see [`SignatureReport::is_acceptable`]).
    FormFilling,
    /// Annotation changes (not produced by the M3 classifier, which reports them as `Other`).
    Annotations,
    /// Anything else, or a change that cannot be attributed (a repaired structure).
    Other,
}

impl ModificationLevel {
    /// `"none"`, `"ltaUpdates"`, `"formFilling"`, `"annotations"` or `"other"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            ModificationLevel::None => "none",
            ModificationLevel::LtaUpdates => "ltaUpdates",
            ModificationLevel::FormFilling => "formFilling",
            ModificationLevel::Annotations => "annotations",
            ModificationLevel::Other => "other",
        }
    }
}

impl fmt::Display for ModificationLevel {
    /// Writes [`ModificationLevel::as_str`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The PAdES baseline level a signature meets (ETSI EN 319 142-1 §6; brief §4.6, §5 V8).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PadesLevel {
    /// PAdES-B-B: basic signature. With the `serde` feature, `"B-B"`.
    #[cfg_attr(feature = "serde", serde(rename = "B-B"))]
    BB,
}

impl PadesLevel {
    /// `"B-B"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            PadesLevel::BB => "B-B",
        }
    }
}

/// The verification result of one signature dictionary (brief §3.2; ARCHITECTURE §A.6.7).
///
/// [`is_valid`](Self::is_valid) is the one-line verdict; the other fields say why. `intact`,
/// `signature_valid`, `trusted`, `coverage` and `modification` use pyHanko 0.37's vocabulary
/// and are never more lenient than pyHanko (brief §0): they agree with it except in the
/// deliberate differences of the M3 brief's table, where Folioxide is stricter (a lower
/// `coverage`, a higher `modification`). `byte_range_ok`, `problems` and `pades_level` are
/// Folioxide's own and are never `true` or `B-B` where pyHanko reports the signature broken.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct SignatureReport {
    /// The fully qualified name of the signature field (§12.7.4.2); `None` for an orphan
    /// signature dictionary that no field references (problem `Orphan`).
    pub field_name: Option<String>,
    /// A signature or a document timestamp.
    pub kind: SignatureKind,
    /// The signature dictionary's object (the field's object when its `/V` is not an indirect
    /// reference).
    pub sig_object: ObjectId,
    /// The `/SubFilter` name without the slash, for example `"ETSI.CAdES.detached"`.
    pub sub_filter: Option<String>,
    /// The `/ByteRange` values as written; `None` when it is missing or not an array of
    /// integers.
    pub byte_range: Option<Vec<i64>>,
    /// The `/ByteRange` is four non-negative integers from 0 inside the file, its gap is exactly
    /// this dictionary's `/Contents` token, the dictionary is uncompressed, inside the signed
    /// bytes and not redefined later (brief §5 V3–V5).
    pub byte_range_ok: bool,
    /// The digest of the bytes the `/ByteRange` names equals the CMS message-digest attribute.
    pub intact: bool,
    /// The CMS signature verifies with the signer certificate and the CMS structure is
    /// acceptable for the SubFilter.
    pub signature_valid: bool,
    /// How much of the file the byte ranges cover.
    pub coverage: Coverage,
    /// The index (into the revisions, oldest first) of the revision the signature covers, for
    /// [`Coverage::EntireFile`] and [`Coverage::EntireRevision`].
    pub signed_revision: Option<usize>,
    /// What later revisions changed.
    pub modification: ModificationLevel,
    /// The objects later revisions list, sorted (free entries included): at most
    /// [`MAX_CHANGED_OBJECTS`](crate::verify_pdf::MAX_CHANGED_OBJECTS) of them, the first by
    /// object number, with a warning giving the full count when there are more.
    pub changed_objects: Vec<ObjectId>,
    /// The SignerInfo's digest algorithm, for example `"sha256"`.
    pub digest_algorithm: Option<String>,
    /// The signature algorithm, for example `"sha256WithRSAEncryption"`.
    pub signature_algorithm: Option<String>,
    /// The signer certificate.
    pub signer: Option<CertificateInfo>,
    /// Every certificate of the CMS, in file order.
    pub chain: Vec<CertificateInfo>,
    /// Whether the signature is trusted: a certification path from the signer to one of the
    /// trust anchors validates at the validation time, no weak algorithm is used, **and** the
    /// signature is intact and valid (as pyHanko's `trusted`: a changed document is never
    /// trusted). `None` without anchors. Why a signer is not trusted is in
    /// [`warnings`](Self::warnings); a weak certification path is also a problem.
    pub trusted: Option<bool>,
    /// The claimed signing time `/M` as RFC 3339.
    pub claimed_time: Option<String>,
    /// `/Name`.
    pub name: Option<String>,
    /// `/Reason`.
    pub reason: Option<String>,
    /// `/Location`.
    pub location: Option<String>,
    /// `/ContactInfo`.
    pub contact_info: Option<String>,
    /// The PAdES baseline level the signature meets, if any.
    pub pades_level: Option<PadesLevel>,
    /// For a certification signature, its DocMDP permissions `P` (1–3, §12.8.2.2); read only in
    /// M3.
    pub docmdp: Option<u8>,
    /// Whether the later revisions respect the DocMDP permissions; `None` until M4.
    pub docmdp_ok: Option<bool>,
    /// Why the signature is not valid; empty when nothing is wrong.
    pub problems: Vec<Problem>,
    /// Observations that do not make the signature invalid.
    pub warnings: Vec<String>,
}

impl SignatureReport {
    /// A report on `sig_object` with nothing verified yet: not intact, not valid, coverage
    /// unclear, modification other.
    pub(crate) fn new(kind: SignatureKind, sig_object: ObjectId) -> SignatureReport {
        SignatureReport {
            field_name: None,
            kind,
            sig_object,
            sub_filter: None,
            byte_range: None,
            byte_range_ok: false,
            intact: false,
            signature_valid: false,
            coverage: Coverage::Unclear,
            signed_revision: None,
            modification: ModificationLevel::Other,
            changed_objects: Vec::new(),
            digest_algorithm: None,
            signature_algorithm: None,
            signer: None,
            chain: Vec::new(),
            trusted: None,
            claimed_time: None,
            name: None,
            reason: None,
            location: None,
            contact_info: None,
            pades_level: None,
            docmdp: None,
            docmdp_ok: None,
            problems: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Whether the signature itself is sound: `byte_range_ok && intact && signature_valid &&
    /// field_name.is_some() && problems.is_empty()` and the coverage is
    /// [`Coverage::EntireFile`] or [`Coverage::EntireRevision`] (brief §3.2).
    ///
    /// **This alone does not say that the document is what was signed.** A signature over an
    /// earlier revision stays valid when later revisions replace page content, fonts or the
    /// catalog (an incremental saving or shadow attack): that is reported in
    /// [`modification`](Self::modification) ([`ModificationLevel::Other`]), not here. To accept
    /// a document, use [`is_acceptable`](Self::is_acceptable), and check
    /// [`trusted`](Self::trusted) for the signer.
    pub fn is_valid(&self) -> bool {
        self.byte_range_ok
            && self.intact
            && self.signature_valid
            && self.field_name.is_some()
            && self.problems.is_empty()
            && matches!(
                self.coverage,
                Coverage::EntireFile | Coverage::EntireRevision
            )
    }

    /// The fail-safe verdict for accepting the signed document: [`is_valid`](Self::is_valid),
    /// and what was appended after the signed revision is at most `max_modification`.
    ///
    /// [`ModificationLevel::FormFilling`] accepts later signatures and filled signature fields
    /// (sequential signing), [`ModificationLevel::LtaUpdates`] only metadata and invisible
    /// signature fields, [`ModificationLevel::None`] nothing at all. Anything Folioxide cannot
    /// attribute to an allowed change is [`ModificationLevel::Other`], which no lower maximum
    /// accepts. Trust is a separate question: also require `trusted == Some(true)` when the
    /// signer must chain to a trust anchor.
    ///
    /// **`FormFilling` includes visible signature appearances added after signing**, which can
    /// cover signed content: a new visible signature field with an appearance stream (signed or
    /// still empty), or the appearance a later signature gives the existing field it signs.
    /// That is inherent to sequential signing in PDF; pyHanko and Acrobat allow it at the same
    /// level. When no further signers are expected, accept at most
    /// [`ModificationLevel::LtaUpdates`] (or inspect the widgets of the later signatures). An
    /// existing signature field that stays unsigned may change only its field flags `/Ff`: a
    /// new appearance, appearance state or annotation flags on it is `Other`.
    ///
    /// The AcroForm is whitelisted exactly (M3 QA round 5). A later revision may only (a) add
    /// new root-level signature fields to `/Fields` (with their widgets, signature dictionaries
    /// and the pages' `/Annots` entries); (b) change `/SigFlags` as signing requires, which no
    /// signing after a signature does (Folioxide sets it only while no field is signed, and
    /// pyHanko compares the key strictly), so any `/SigFlags` change is `Other`; and (c) add
    /// new `/DR` resource names that the signed revision does not name. Everything else in the
    /// AcroForm is `Other`: any change to `/NeedAppearances` (setting it makes viewers construct
    /// the signed fields' appearances from their values, and removing a `true` makes them show
    /// stored appearances that may differ from the ones they constructed when the document was
    /// signed; that holds when a later signer removes it while signing too, as pyHanko's signer
    /// does, so the earlier signatures of such a document are `Other` where pyHanko reports
    /// `FormFilling`), any change to `/DA` (adding one too: an added `/DA` restyles every field
    /// viewers construct an appearance for), any `/Q` change, changing or removing a `/DR`
    /// resource name, and any other key.
    ///
    /// What `FormFilling` still allows besides signature appearances, and its residual risk
    /// (pyHanko allows it too, at the same level): **new `/DR` resource names** (in `/Font
    /// /XObject /ColorSpace /ExtGState /Pattern /Shading /ProcSet`) that the signed revision
    /// does not name. It names every name token of every default appearance string (`/DA`) of
    /// the AcroForm, of its fields and widgets and of every annotation on every page (with the
    /// `/DA` it inherits from its field), and of every appearance stream of those annotations
    /// and widgets that has no `/Resources` of its own; when these cannot all be read within
    /// the verifier's limits, no new name is allowed. Not read: names that a form XObject
    /// nested in an appearance stream uses, and names that a viewer looks up in `/DR` after
    /// failing to find them in an appearance stream's own `/Resources`.
    ///
    /// ```
    /// use folioxide_model::{Document, PdfDate};
    /// use folioxide_sign::report::ModificationLevel;
    /// use folioxide_sign::sign::{SignRequest, sign};
    /// use folioxide_sign::signer::LocalSigner;
    /// use folioxide_sign::verify_pdf::{VerifyOptions, verify_bytes};
    /// use folioxide_syntax::{IncrementalOptions, Object, OpenOptions};
    ///
    /// # let pki = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pki");
    /// # let p12 = std::fs::read(pki.join("signer-p256-modern.p12"))?;
    /// let signer = LocalSigner::from_pkcs12(&p12, "folioxide")?;
    /// let time = PdfDate::parse(b"D:20261010120000Z").expect("a PDF date");
    /// let source = folioxide_testkit::fixtures::syntax::minimal();
    /// let signed = sign(
    ///     &Document::open(source, &OpenOptions::default())?,
    ///     &SignRequest::new(&signer, time),
    /// )?;
    ///
    /// // Someone replaces the page content in an incremental update after signing.
    /// let mut doc = Document::open(signed, &OpenOptions::default())?;
    /// let page = doc.page_ids()?[0].0;
    /// let content = doc.store().resolve(page)?.as_dict().and_then(|p| p.get_ref(b"Contents"));
    /// let content = content.expect("a content stream");
    /// let replaced = folioxide_syntax::Stream::new(
    ///     folioxide_syntax::Dict::new(),
    ///     folioxide_syntax::StreamData::Decoded(b"BT (Pay Mallory) Tj ET".to_vec()),
    /// );
    /// doc.store_mut().set(content, Object::Stream(Box::new(replaced)))?;
    /// let changed = doc.save_incremental(&IncrementalOptions::default())?;
    ///
    /// let report = &verify_bytes(changed, &VerifyOptions::default())?[0];
    /// assert!(report.is_valid(), "the signature over its revision is still sound");
    /// assert_eq!(report.modification, ModificationLevel::Other);
    /// assert!(!report.is_acceptable(ModificationLevel::FormFilling), "but the document changed");
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn is_acceptable(&self, max_modification: ModificationLevel) -> bool {
        self.is_valid() && self.modification <= max_modification
    }

    /// Whether a problem with `code` was reported.
    pub fn has_problem(&self, code: crate::ProblemCode) -> bool {
        self.problems.iter().any(|p| p.code == code)
    }

    /// Records a problem, once per code and message.
    pub(crate) fn problem(&mut self, code: crate::ProblemCode, message: impl Into<String>) {
        let problem = Problem::new(code, message);
        if !self.problems.contains(&problem) {
            self.problems.push(problem);
        }
    }

    /// Records a warning, once.
    pub(crate) fn warn(&mut self, message: impl Into<String>) {
        let message = message.into();
        if !self.warnings.contains(&message) {
            self.warnings.push(message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProblemCode;

    fn good() -> SignatureReport {
        let mut report = SignatureReport::new(SignatureKind::Signature, ObjectId::new(7, 0));
        report.field_name = Some("Signature1".into());
        report.byte_range_ok = true;
        report.intact = true;
        report.signature_valid = true;
        report.coverage = Coverage::EntireFile;
        report.modification = ModificationLevel::None;
        report
    }

    #[test]
    fn is_valid_needs_every_condition() {
        assert!(good().is_valid());
        let variants: [fn(&mut SignatureReport); 8] = [
            |r| r.byte_range_ok = false,
            |r| r.intact = false,
            |r| r.signature_valid = false,
            |r| r.field_name = None,
            |r| r.problem(ProblemCode::WeakAlgorithm, "sha1"),
            |r| r.coverage = Coverage::ContiguousBlockFromStart,
            |r| r.coverage = Coverage::Unclear,
            |r| r.kind = SignatureKind::Signature,
        ];
        for (i, mutate) in variants.iter().enumerate() {
            let mut report = good();
            mutate(&mut report);
            assert_eq!(report.is_valid(), i == 7, "variant {i}");
        }
        let mut revision = good();
        revision.coverage = Coverage::EntireRevision;
        revision.modification = ModificationLevel::Other;
        assert!(
            revision.is_valid(),
            "the modification level is a separate verdict"
        );
        assert!(
            !revision.is_acceptable(ModificationLevel::FormFilling),
            "is_acceptable is not fooled by content changed after signing"
        );
    }

    #[test]
    fn is_acceptable_bounds_the_modification() {
        use ModificationLevel::*;
        for (level, max, acceptable) in [
            (None, None, true),
            (LtaUpdates, None, false),
            (LtaUpdates, FormFilling, true),
            (FormFilling, FormFilling, true),
            (FormFilling, LtaUpdates, false),
            (Annotations, FormFilling, false),
            (Other, FormFilling, false),
            (Other, Annotations, false),
        ] {
            let mut report = good();
            report.modification = level;
            assert_eq!(report.is_acceptable(max), acceptable, "{level} <= {max}");
        }
        // A signature that is not valid is never acceptable.
        let mut broken = good();
        broken.intact = false;
        assert!(!broken.is_acceptable(Other));
    }

    #[test]
    fn modification_levels_are_ordered() {
        use ModificationLevel::*;
        assert!(None < LtaUpdates && LtaUpdates < FormFilling);
        assert!(FormFilling < Annotations && Annotations < Other);
        assert_eq!([LtaUpdates, Other, None].into_iter().max(), Some(Other));
    }

    #[test]
    fn problems_and_warnings_are_recorded_once() {
        let mut report = good();
        report.problem(ProblemCode::Orphan, "x");
        report.problem(ProblemCode::Orphan, "x");
        report.warn("w");
        report.warn("w");
        assert_eq!(report.problems.len(), 1);
        assert_eq!(report.warnings, ["w"]);
        assert!(report.has_problem(ProblemCode::Orphan));
    }

    #[test]
    fn names() {
        assert_eq!(
            Coverage::ContiguousBlockFromStart.as_str(),
            "contiguousBlockFromStart"
        );
        assert_eq!(Coverage::EntireFile.to_string(), "entireFile");
        assert_eq!(ModificationLevel::LtaUpdates.to_string(), "ltaUpdates");
        assert_eq!(SignatureKind::DocTimeStamp.as_str(), "docTimeStamp");
        assert_eq!(PadesLevel::BB.as_str(), "B-B");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_shapes() {
        let mut report = good();
        report.pades_level = Some(PadesLevel::BB);
        report.changed_objects = vec![ObjectId::new(4, 0)];
        report.problem(ProblemCode::GapNotContents, "gap");
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["fieldName"], "Signature1");
        assert_eq!(json["kind"], "signature");
        assert_eq!(json["coverage"], "entireFile");
        assert_eq!(json["modification"], "none");
        assert_eq!(json["padesLevel"], "B-B");
        assert_eq!(json["sigObject"], serde_json::json!({"num": 7, "gen": 0}));
        assert_eq!(json["changedObjects"][0]["num"], 4);
        assert_eq!(json["problems"][0]["code"], "gapNotContents");
        for key in [
            "subFilter",
            "byteRange",
            "byteRangeOk",
            "signatureValid",
            "signedRevision",
            "digestAlgorithm",
            "signatureAlgorithm",
            "claimedTime",
            "contactInfo",
            "docmdpOk",
        ] {
            assert!(json.get(key).is_some(), "missing {key}: {json}");
        }
        let back: SignatureReport = serde_json::from_value(json).unwrap();
        assert_eq!(back, report);
        for (level, text) in [
            (ModificationLevel::LtaUpdates, "ltaUpdates"),
            (ModificationLevel::FormFilling, "formFilling"),
        ] {
            assert_eq!(serde_json::to_value(level).unwrap(), text);
        }
        assert_eq!(
            serde_json::to_value(Coverage::ContiguousBlockFromStart).unwrap(),
            "contiguousBlockFromStart"
        );
        assert_eq!(
            serde_json::to_value(SignatureKind::DocTimeStamp).unwrap(),
            "docTimeStamp"
        );
    }
}
