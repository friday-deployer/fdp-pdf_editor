//! V6–V9 and V11: the CMS of a signature dictionary (brief §5).
//!
//! - **Routes by `/SubFilter`** (V2): `ETSI.CAdES.detached` and `adbe.pkcs7.detached` are
//!   detached CMS over the byte ranges; `adbe.pkcs7.sha1` carries the SHA-1 digest of the
//!   ranges as encapsulated content (verify only, always `WeakAlgorithm`); anything else is
//!   `UnsupportedSubFilter` (the digest is still compared, the signature is not valid). A
//!   document timestamp (`ETSI.RFC3161`) is verified as a timestamp token over the byte ranges
//!   (M4 brief §5 V7c, [`timestamp::document_timestamp`]).
//! - **V6/V7** come from [`cms::verify_detached`] over the ranges as written.
//! - **V7b** (M4): the signature timestamps of `ETSI.CAdES.detached` and `adbe.pkcs7.detached`
//!   signatures ([`timestamp::signature_timestamps`]); their problems stay in the
//!   [`TimestampInfo`](crate::report::TimestampInfo)s (DECISIONS D13 D-6).
//! - **V8**: `pades_level` B-B for `ETSI.CAdES.detached` with a DER-encoded SignedData (EN 319
//!   142-1; a timestamp token inside is opaque), the B-B signed attributes, one detached
//!   SignerInfo whose certificate the CMS carries, `/M` present and no `/Cert` (brief §4.6);
//!   B-T when the selected signature timestamp is also intact and valid (M4 brief §5 V8).
//! - **V9**: the signer and every CMS certificate as [`CertificateInfo`]; with trust anchors,
//!   [`build_trust`](crate::x509info::build_trust) at the validation time, else at the `genTime` of a selected signature
//!   timestamp that is trusted (DECISIONS D13 D-7; with a warning since QA round 1 finding F8,
//!   because that time is the TSA's own claim), else at `/M` with a warning. A weak algorithm
//!   is never trusted.
//! - **V11**: `docmdp` from the dictionary's `/Reference` DocMDP transform (§12.8.2.2), or the
//!   catalog's `/Perms /DocMDP` naming this dictionary
//!   ([`declared_permissions`](crate::docmdp::declared_permissions)).

use folioxide_model::{Document, PdfDate};
use folioxide_syntax::Dict;

use super::VerifyOptions;
use super::dict::Checked;
use super::digests::Digests;
use super::timestamp;
use crate::algorithms::DigestAlgorithm;
use crate::cms::{self, ParsedCms};
use crate::problem::{Problem, ProblemCode};
use crate::report::{PadesLevel, SignatureKind, SignatureReport};
use crate::tsp::GenTime;
use crate::x509info::{self, CertificateInfo, UnixTime};

/// The warning of an `ETSI.CAdES.detached` signature that would be PAdES B-B but for a CMS that
/// is not DER (EN 319 142-1 requires a DER-encoded SignedData; a signature timestamp token
/// inside is opaque, DECISIONS D13 D-12), so its `pades_level` is `None` (QA round 3 finding 1).
pub(crate) const NOT_DER_WARNING: &str = "the CMS is not DER-encoded (outside its signature \
    timestamp tokens), so the signature has no PAdES level: EN 319 142-1 requires a DER-encoded \
    SignedData";

/// Checks the CMS of `dict` and fills the CMS fields of `report`: `intact`,
/// `signature_valid`, the algorithms, the certificates, `trusted`, `pades_level` and `docmdp`.
pub(crate) fn check(
    doc: &Document,
    dict: &Dict,
    checked: &Checked,
    opts: &VerifyOptions,
    digests: &Digests<'_>,
    report: &mut SignatureReport,
) {
    report.docmdp = crate::docmdp::declared_permissions(doc, dict, report.sig_object);
    let Some(contents) = checked.contents.as_deref() else {
        return; // V4 reported why.
    };
    let parsed = match cms::parse(contents) {
        Ok(parsed) => parsed,
        Err(err) => {
            report.problem(
                ProblemCode::CmsMalformed,
                format!("/Contents does not hold a CMS ContentInfo: {err}"),
            );
            return;
        }
    };
    if contents
        .get(parsed.raw.end..)
        .is_some_and(|padding| padding.iter().any(|&b| b != 0))
    {
        report
            .warn("/Contents has non-zero bytes after the CMS; they are ignored, as pyHanko does");
    }
    if parsed.signer_infos.iter().any(|si| {
        si.unsigned_attrs
            .as_deref()
            .is_some_and(cms::decode::unsigned_attributes_beyond_limit)
    }) {
        // Unsigned attributes are not signed, so a flood of them is no reason to call the
        // signature malformed (QA round 1 finding F10); what lies beyond the limit is not read.
        report.warn(format!(
            "the SignerInfo has more than {} unsigned attributes; only the first {} are read, so \
             a signature timestamp after them is not seen",
            cms::MAX_ATTRIBUTES,
            cms::MAX_ATTRIBUTES
        ));
    }

    let ranges = checked.ranges.clone();
    let refused_before = digests.refused();
    let digest_of = |algorithm: DigestAlgorithm| -> Option<Vec<u8>> {
        digests.digest(algorithm, ranges.as_ref()?)
    };
    check_cms(dict, contents, &parsed, &digest_of, opts, report);
    if digests.refused() > refused_before {
        report.warn(format!(
            "the signed bytes were not hashed: this verification already hashed its budget of \
             {} bytes (the file has many signatures over large ranges), so the signature is \
             not reported intact",
            Digests::budget_for(doc.store().source().len())
        ));
    }
}

/// The CMS checks of [`check`] once the CMS (`contents`, parsed as `parsed`) parsed, with
/// `digest_of` giving the digest of the signed bytes.
fn check_cms(
    dict: &Dict,
    contents: &[u8],
    parsed: &ParsedCms,
    digest_of: &dyn Fn(DigestAlgorithm) -> Option<Vec<u8>>,
    opts: &VerifyOptions,
    report: &mut SignatureReport,
) {
    let route = report.sub_filter.as_deref().unwrap_or_default().to_owned();
    if report.kind == SignatureKind::DocTimeStamp {
        certificates(parsed, None, report);
        timestamp::document_timestamp(contents, parsed, digest_of, opts, report);
        return;
    }
    let verification = match route.as_str() {
        "adbe.pkcs7.sha1" => sha1_route(parsed, digest_of, opts, report),
        other => {
            let verification = cms::verify_detached(parsed, digest_of, &opts.extra_certs_der);
            report.intact = verification.intact;
            report.signature_valid = verification.signature_valid;
            if other != "ETSI.CAdES.detached" && other != "adbe.pkcs7.detached" {
                report.signature_valid = false;
                report.problem(
                    ProblemCode::UnsupportedSubFilter,
                    if other.is_empty() {
                        "the signature dictionary has no /SubFilter".to_owned()
                    } else {
                        format!("the /SubFilter /{other} is not supported")
                    },
                );
            }
            verification
        }
    };
    for problem in &verification.problems {
        report.problem(problem.code, problem.message.clone());
    }
    for warning in &verification.warnings {
        report.warn(warning.clone());
    }
    report.digest_algorithm = verification.digest.map(|d| d.name().to_owned());
    report.signature_algorithm = verification.signature_algorithm.clone();
    let weak = verification
        .problems
        .iter()
        .any(|p| p.code == ProblemCode::WeakAlgorithm);
    certificates(parsed, verification.signer_cert.as_deref(), report);
    // V7b: the signature timestamps (M4 brief §5).
    let claimed = dict.get_str_bytes(b"M").and_then(PdfDate::parse);
    let timestamps = if route == "ETSI.CAdES.detached" || route == "adbe.pkcs7.detached" {
        timestamp::signature_timestamps(parsed, claimed.as_ref(), opts, report)
    } else {
        timestamp::Selected::default()
    };
    trust(
        parsed,
        verification.signer_cert.as_deref(),
        weak,
        claimed.as_ref(),
        timestamps.trusted_gen_time,
        opts,
        report,
    );

    // V8: the PAdES baseline B-B profile (brief §4.6); the caller drops it for a signature
    // that is not intact, valid and structurally sound.
    let signer_in_cms = verification
        .signer_cert
        .as_ref()
        .is_some_and(|cert| parsed.certificates.contains(cert));
    let b_b_but_der = route == "ETSI.CAdES.detached"
        && verification.pades_attrs.is_baseline_b()
        && parsed.signer_infos.len() == 1
        && parsed.econtent.is_none()
        && signer_in_cms
        && dict.contains_key(b"M")
        && !dict.contains_key(b"Cert");
    let b_b = b_b_but_der && crate::finish::is_der_cms(contents, parsed);
    if b_b_but_der && !b_b {
        // QA round 3 finding 1: say why a CAdES signature has no PAdES level (a damaged
        // unsigned attribute, say, makes the CMS BER).
        report.warn(NOT_DER_WARNING);
    }
    report.pades_level = match (b_b, timestamps.sound) {
        (true, true) => Some(PadesLevel::BT),
        (true, false) => Some(PadesLevel::BB),
        (false, _) => None,
    };
}

/// `adbe.pkcs7.sha1` (ISO 32000-1 §12.8.3.3.1): the encapsulated content is the SHA-1 digest of
/// the byte ranges, and the CMS signs that content.
fn sha1_route(
    parsed: &ParsedCms,
    digest_of: &dyn Fn(DigestAlgorithm) -> Option<Vec<u8>>,
    opts: &VerifyOptions,
    report: &mut SignatureReport,
) -> cms::CmsVerification {
    report.problem(
        ProblemCode::WeakAlgorithm,
        "adbe.pkcs7.sha1 signs a SHA-1 digest of the document",
    );
    let Some(content) = parsed.econtent.clone() else {
        let verification = cms::CmsVerification::failed(Problem::new(
            ProblemCode::CmsMalformed,
            "an adbe.pkcs7.sha1 signature has no encapsulated SHA-1 digest",
        ));
        report.intact = false;
        report.signature_valid = false;
        return verification;
    };
    let mut detached = parsed.clone();
    detached.econtent = None;
    let content_digest = |algorithm: DigestAlgorithm| Some(algorithm.digest(&[&content]));
    let verification = cms::verify_detached(&detached, &content_digest, &opts.extra_certs_der);
    let document_ok = digest_of(DigestAlgorithm::Sha1).is_some_and(|d| d == content);
    report.intact = document_ok && verification.intact;
    report.signature_valid = verification.signature_valid;
    if !document_ok {
        report.problem(
            ProblemCode::DigestMismatch,
            "the encapsulated SHA-1 digest is not the digest of the signed bytes",
        );
    }
    verification
}

/// The signer and every CMS certificate as [`CertificateInfo`] (brief §5 V9).
fn certificates(parsed: &ParsedCms, signer: Option<&[u8]>, report: &mut SignatureReport) {
    if let Some(signer) = signer {
        match x509info::certificate_info(signer) {
            Ok(info) => report.signer = Some(info),
            Err(err) => report.warn(format!("the signer certificate cannot be read: {err}")),
        }
    }
    let mut chain: Vec<CertificateInfo> = Vec::with_capacity(parsed.certificates.len());
    for (i, cert) in parsed.certificates.iter().enumerate() {
        match x509info::certificate_info(cert) {
            Ok(info) => chain.push(info),
            Err(err) => report.warn(format!("CMS certificate {i} cannot be read: {err}")),
        }
    }
    report.chain = chain;
}

/// V9: `trusted` with trust anchors, at the validation time; without one, at the `genTime` of
/// a trusted signature timestamp (`trusted_gen_time`, DECISIONS D13 D-7), else at the claimed
/// `/M`, each with a warning.
///
/// As pyHanko's `SignatureStatus.trusted` (`valid and intact and trust_problem_indic is None and
/// validation_path is not None`), a signature is trusted only when it is intact and its CMS
/// signature is valid, besides the certification path: a changed document is never trusted.
/// The path is still built for a broken signature, so its reasons (warnings) and typed problems
/// ([`TrustResult::problems`](crate::x509info::TrustResult::problems), for example a weak
/// certificate signature or an RSA key below 2048 bits) are always in the report.
fn trust(
    parsed: &ParsedCms,
    signer: Option<&[u8]>,
    weak: bool,
    claimed: Option<&PdfDate>,
    trusted_gen_time: Option<GenTime>,
    opts: &VerifyOptions,
    report: &mut SignatureReport,
) {
    if opts.trust_anchors_der.is_empty() {
        return;
    }
    let at = match (opts.validation_time.as_ref(), trusted_gen_time, claimed) {
        (Some(time), _, _) => UnixTime::from_pdf_date(time),
        (None, Some(gen_time), _) => {
            // D-7 (QA round 1 finding F8): the signature timestamp's genTime, at which its TSA
            // certificate was validated too; only a validation time breaks the circle.
            report.warn(
                "certificates were validated at the genTime of the signature timestamp, the TSA's \
                 own claim, because no validation time was given; pass a validation time (for \
                 example now) to validate at another time",
            );
            gen_time.unix_time()
        }
        (None, None, Some(claimed)) => {
            report.warn(
                "certificates were validated at the signer's claimed signing time (/M); pass a \
                 validation time to validate at another time",
            );
            UnixTime::from_pdf_date(claimed)
        }
        (None, None, None) => {
            report.warn("no validation time and no /M: the signer cannot be trusted");
            report.trusted = Some(false);
            return;
        }
    };
    let Some(signer) = signer else {
        report.warn("not trusted: the signer certificate was not found");
        report.trusted = Some(false);
        return;
    };
    let mut pool: Vec<Vec<u8>> = parsed.certificates.clone();
    pool.extend(opts.extra_certs_der.iter().cloned());
    let result = x509info::build_trust(signer, &pool, &opts.trust_anchors_der, at);
    report.trusted = Some(trust_verdict(&result, weak, report));
}

/// Copies a [`TrustResult`](x509info::TrustResult) into `report` (reasons and warnings as
/// warnings, typed problems as problems) and returns the `trusted` verdict: a validated path,
/// no weak algorithm, and an intact signature whose CMS signature is valid (pyHanko).
fn trust_verdict(result: &x509info::TrustResult, weak: bool, report: &mut SignatureReport) -> bool {
    for reason in &result.reasons {
        report.warn(format!("not trusted: {reason}"));
    }
    for warning in &result.warnings {
        report.warn(warning.clone());
    }
    for problem in &result.problems {
        report.problem(problem.code, problem.message.clone());
    }
    if weak && result.trusted {
        report.warn("not trusted: a weak algorithm (SHA-1) is used");
    }
    let sound = report.intact && report.signature_valid;
    if result.trusted && !sound {
        report.warn(if report.intact {
            "not trusted: the CMS signature is not valid"
        } else {
            "not trusted: the signed bytes were changed (the signature is not intact)"
        });
    }
    result.trusted && !weak && sound
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_needs_an_intact_valid_signature_and_copies_problems() {
        use folioxide_syntax::ObjectId;
        let trusted_path = x509info::TrustResult {
            trusted: true,
            path: vec![vec![1], vec![2]],
            ..Default::default()
        };
        let report_with = |intact: bool, valid: bool| {
            let mut report = SignatureReport::new(SignatureKind::Signature, ObjectId::new(1, 0));
            report.intact = intact;
            report.signature_valid = valid;
            report
        };

        let mut report = report_with(true, true);
        assert!(trust_verdict(&trusted_path, false, &mut report));
        assert!(report.warnings.is_empty() && report.problems.is_empty());

        // pyHanko: `trusted = valid and intact and ...`.
        for (intact, valid, why) in [
            (false, true, "not intact"),
            (true, false, "not valid"),
            (false, false, "not intact"),
        ] {
            let mut report = report_with(intact, valid);
            assert!(!trust_verdict(&trusted_path, false, &mut report));
            assert!(
                report.warnings.iter().any(|w| w.contains(why)),
                "{:?}",
                report.warnings
            );
        }
        let mut report = report_with(true, true);
        assert!(!trust_verdict(&trusted_path, true, &mut report));
        assert!(report.warnings.iter().any(|w| w.contains("weak")));

        // An untrusted path: its reasons become warnings, its typed problems problems.
        let untrusted = x509info::TrustResult {
            trusted: false,
            reasons: vec!["the certificate expired".into()],
            warnings: vec!["candidate ignored".into()],
            problems: vec![Problem::new(ProblemCode::WeakAlgorithm, "sha1WithRSA")],
            ..Default::default()
        };
        let mut report = report_with(true, true);
        assert!(!trust_verdict(&untrusted, false, &mut report));
        assert_eq!(
            report.warnings,
            ["not trusted: the certificate expired", "candidate ignored"]
        );
        assert!(report.has_problem(ProblemCode::WeakAlgorithm));
        assert!(!report.is_valid(), "a weak certification path is a problem");
    }
}
