//! V6–V9 and V11: the CMS of a signature dictionary (brief §5).
//!
//! - **Routes by `/SubFilter`** (V2): `ETSI.CAdES.detached` and `adbe.pkcs7.detached` are
//!   detached CMS over the byte ranges; `adbe.pkcs7.sha1` carries the SHA-1 digest of the
//!   ranges as encapsulated content (verify only, always `WeakAlgorithm`); anything else is
//!   `UnsupportedSubFilter` (the digest is still compared, the signature is not valid). A
//!   document timestamp (`ETSI.RFC3161`) has `intact` from its `messageImprint` and is listed,
//!   not verified, in M3 (`PendingTimestampVerification`).
//! - **V6/V7** come from [`cms::verify_detached`] over the ranges as written.
//! - **V8**: `pades_level` B-B for `ETSI.CAdES.detached` with a DER-encoded SignedData (EN 319
//!   142-1), the B-B signed attributes, one detached SignerInfo whose certificate the CMS
//!   carries, `/M` present and no `/Cert` (brief §4.6).
//! - **V9**: the signer and every CMS certificate as [`CertificateInfo`]; with trust anchors,
//!   [`build_trust`] at the validation time (`/M` with a warning when none is given). A weak
//!   algorithm is never trusted.
//! - **V11**: `docmdp` from the dictionary's `/Reference` DocMDP transform (§12.8.2.2), or the
//!   catalog's `/Perms /DocMDP` naming this dictionary.

use folioxide_model::{Document, PdfDate};
use folioxide_syntax::{Dict, Object};

use super::VerifyOptions;
use super::dict::Checked;
use super::digests::Digests;
use crate::algorithms::DigestAlgorithm;
use crate::cms::{self, ParsedCms, tlv};
use crate::problem::{Problem, ProblemCode};
use crate::report::{PadesLevel, SignatureKind, SignatureReport};
use crate::x509info::{self, CertificateInfo, UnixTime};

/// The deepest nesting read in a TSTInfo.
const MAX_TST_DEPTH: usize = 8;

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
    report.docmdp = docmdp(doc, dict, report);
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
        timestamp(parsed, digest_of, opts, report);
        certificates(parsed, None, report);
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
    trust(
        parsed,
        verification.signer_cert.as_deref(),
        weak,
        dict,
        opts,
        report,
    );

    // V8: the PAdES baseline B-B profile (brief §4.6); the caller drops it for a signature
    // that is not intact, valid and structurally sound.
    let signer_in_cms = verification
        .signer_cert
        .as_ref()
        .is_some_and(|cert| parsed.certificates.contains(cert));
    let b_b = route == "ETSI.CAdES.detached"
        && crate::finish::is_der_cms(contents, parsed)
        && verification.pades_attrs.is_baseline_b()
        && parsed.signer_infos.len() == 1
        && parsed.econtent.is_none()
        && signer_in_cms
        && dict.contains_key(b"M")
        && !dict.contains_key(b"Cert");
    report.pades_level = b_b.then_some(PadesLevel::BB);
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

/// A document timestamp (§12.8.5): `intact` when the TSTInfo `messageImprint` is the digest of
/// the byte ranges; verification of the token waits for M4.
fn timestamp(
    parsed: &ParsedCms,
    digest_of: &dyn Fn(DigestAlgorithm) -> Option<Vec<u8>>,
    opts: &VerifyOptions,
    report: &mut SignatureReport,
) {
    report.problem(
        ProblemCode::PendingTimestampVerification,
        "document timestamps are listed but not verified until M4",
    );
    report.signature_valid = false;
    let imprint = parsed.econtent.as_deref().and_then(message_imprint);
    if let Some((algorithm, hashed)) = &imprint {
        report.intact = digest_of(*algorithm).is_some_and(|d| &d == hashed);
        report.digest_algorithm = Some(algorithm.name().to_owned());
    }
    // The TSA certificate, for information.
    if let Some(content) = parsed.econtent.clone() {
        let mut detached = parsed.clone();
        detached.econtent = None;
        let content_digest = |algorithm: DigestAlgorithm| Some(algorithm.digest(&[&content]));
        let verification = cms::verify_detached(&detached, &content_digest, &opts.extra_certs_der);
        report.signature_algorithm = verification.signature_algorithm.clone();
        if let Some(cert) = verification.signer_cert.as_deref() {
            report.signer = x509info::certificate_info(cert).ok();
        }
    }
}

/// The `messageImprint` of a DER TSTInfo (RFC 3161 §2.4.2): its hash algorithm and value.
fn message_imprint(tst_info: &[u8]) -> Option<(DigestAlgorithm, Vec<u8>)> {
    let outer = tlv::read_exact(tst_info, MAX_TST_DEPTH).ok()?;
    if outer.tag != tlv::TAG_SEQUENCE {
        return None;
    }
    // version, policy, messageImprint, ...
    let fields = tlv::children_vec(tst_info, &outer, 0, MAX_TST_DEPTH, 16).ok()?;
    let imprint = fields.get(2).filter(|e| e.tag == tlv::TAG_SEQUENCE)?;
    let parts = tlv::children_vec(tst_info, imprint, 1, MAX_TST_DEPTH, 4).ok()?;
    let algorithm = parts.first().filter(|e| e.tag == tlv::TAG_SEQUENCE)?;
    let hashed = parts.get(1).filter(|e| e.tag == tlv::TAG_OCTET_STRING)?;
    let algorithm_parts = tlv::children_vec(tst_info, algorithm, 2, MAX_TST_DEPTH, 2).ok()?;
    let oid = algorithm_parts.first().filter(|e| e.tag == tlv::TAG_OID)?;
    let dotted = cms::oid_to_string(oid.content(tst_info))?;
    let digest = DigestAlgorithm::from_oid(&dotted)?;
    Some((digest, hashed.content(tst_info).to_vec()))
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

/// V9: `trusted` with trust anchors, at the validation time.
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
    dict: &Dict,
    opts: &VerifyOptions,
    report: &mut SignatureReport,
) {
    if opts.trust_anchors_der.is_empty() {
        return;
    }
    let claimed = dict.get_str_bytes(b"M").and_then(PdfDate::parse);
    let at = match (opts.validation_time, claimed) {
        (Some(time), _) => time,
        (None, Some(claimed)) => {
            report.warn(
                "certificates were validated at the signer's claimed signing time (/M); pass a \
                 validation time to validate at another time",
            );
            claimed
        }
        (None, None) => {
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
    let result = x509info::build_trust(
        signer,
        &pool,
        &opts.trust_anchors_der,
        UnixTime::from_pdf_date(&at),
    );
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

/// V11: the DocMDP permissions of a certification signature (§12.8.2.2): its `/Reference`
/// entry with `/TransformMethod /DocMDP`, `/TransformParams /P` (default 2).
fn docmdp(doc: &Document, dict: &Dict, report: &SignatureReport) -> Option<u8> {
    let store = doc.store();
    let deref_dict = |obj: &Object| store.deref(obj).ok().and_then(|o| o.as_dict().cloned());
    let references = dict
        .get(b"Reference")
        .and_then(|r| store.deref(r).ok())
        .and_then(|r| r.as_array().map(<[Object]>::to_vec))
        .unwrap_or_default();
    for reference in &references {
        let Some(reference) = deref_dict(reference) else {
            continue;
        };
        if reference
            .get_name(b"TransformMethod")
            .is_some_and(|m| m == b"DocMDP")
        {
            let p = reference
                .get(b"TransformParams")
                .and_then(deref_dict)
                .and_then(|params| params.get_int(b"P"))
                .unwrap_or(2);
            return u8::try_from(p).ok().filter(|p| (1..=3).contains(p));
        }
    }
    // The catalog's /Perms /DocMDP names this dictionary: certified, default permissions.
    let perms_target = doc
        .catalog()
        .ok()
        .and_then(|c| c.as_dict().and_then(|d| d.get(b"Perms").cloned()))
        .and_then(|perms| deref_dict(&perms))
        .and_then(|perms| perms.get_ref(b"DocMDP"));
    (perms_target == Some(report.sig_object)).then_some(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tst_info(oid_der: &[u8], hash: &[u8]) -> Vec<u8> {
        let algorithm = tlv::tlv(tlv::TAG_SEQUENCE, oid_der);
        let imprint = tlv::tlv_parts(
            tlv::TAG_SEQUENCE,
            &[&algorithm, &tlv::tlv(tlv::TAG_OCTET_STRING, hash)],
        );
        let version = tlv::tlv(tlv::TAG_INTEGER, &[1]);
        let policy = tlv::tlv(tlv::TAG_OID, &[0x2A, 0x03]);
        tlv::tlv_parts(tlv::TAG_SEQUENCE, &[&version, &policy, &imprint])
    }

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

    #[test]
    fn message_imprints() {
        // id-sha256 2.16.840.1.101.3.4.2.1
        let sha256 = [
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        ];
        let info = tst_info(&sha256, &[7; 32]);
        assert_eq!(
            message_imprint(&info),
            Some((DigestAlgorithm::Sha256, vec![7; 32]))
        );
        assert_eq!(message_imprint(&info[..info.len() - 1]), None);
        assert_eq!(message_imprint(b""), None);
        // An unknown hash.
        let unknown = [0x06, 0x02, 0x2A, 0x03];
        assert_eq!(message_imprint(&tst_info(&unknown, &[1])), None);
    }
}
