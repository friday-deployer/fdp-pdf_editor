//! V7b and V7c: RFC 3161 timestamps in signatures (M4 brief §5).
//!
//! - **V7b, signature timestamps** of `ETSI.CAdES.detached` and `adbe.pkcs7.detached`
//!   signatures: every `id-aa-signatureTimeStampToken` value of the SignerInfo
//!   ([`signature_timestamp_tokens`](crate::cms::signature_timestamp_tokens)), at most
//!   [`MAX_TIMESTAMP_TOKENS`], verified with [`verify_token`](crate::tsp::verify_token) over the
//!   signature value, trusted with [`build_trust_for`](crate::x509info::build_trust_for) for
//!   timestamping, and the earliest sound one selected into `SignatureReport::timestamp`
//!   (DECISIONS D13 D-5). Token problems stay in `TimestampInfo::problems` (D-6), so a broken
//!   or untrusted timestamp token never makes the signature itself invalid; an unsigned
//!   attribute that is not a well-formed `Attribute` is a CMS syntax error, though, and makes
//!   the CMS malformed before any token is read (M4 QA round 4 finding 6).
//! - **V7c, document timestamps** (`/Type /DocTimeStamp` or `/SubFilter /ETSI.RFC3161`,
//!   ISO 32000-2 §12.8.5): the token in `/Contents` over the signed byte ranges; its problems
//!   are the report's, because for a document timestamp the token *is* the signature.
//!
//! Trust (V7b step 9) uses `VerifyOptions::timestamp_trust_anchors_der`, else the signature's
//! anchors (pyHanko's default), at the validation time or else at the token's own `genTime`,
//! and requires the token to be intact and valid and free of weak algorithms. Validated at its
//! own `genTime`, a trusted token carries [`GEN_TIME_TRUST_WARNING`]: that time is the TSA's
//! claim, so a retired TSA key could backdate (QA round 1 finding F8).
//!
//! The anchors may be named by the token's later ESS identifiers, and once a path above the TSA
//! certificate is trusted, those identifiers must name certificates of that path, as OpenSSL
//! checks them against its verified chain (QA round 2 finding 3); otherwise the token is not
//! valid.

use folioxide_model::PdfDate;

use super::VerifyOptions;
use crate::algorithms::DigestAlgorithm;
use crate::cms::{self, ParsedCms};
use crate::problem::{Problem, ProblemCode};
use crate::report::{SignatureReport, TimestampInfo};
use crate::tsp::{self, GenTime, MAX_TIMESTAMP_TOKENS};
use crate::x509info::{self, TrustPurpose, UnixTime};

/// The warning of a token whose TSA certificate path was validated at the token's own
/// `genTime`, because no validation time was given (V7b step 9; QA round 1 finding F8).
pub(crate) const GEN_TIME_TRUST_WARNING: &str = "the TSA certificate was validated at the \
    token's own genTime, because no validation time was given: a token signed with a retired TSA \
    key can claim any time inside its certificate's validity; pass a validation time (for \
    example now) to validate at another time";

/// The warning of a signature whose unsigned attributes could not all be read (a value with a
/// truncated or huge declared length, nested too deep, …): a signature timestamp may be there
/// and damaged, and is then neither verified nor listed (QA round 3 finding 1).
pub(crate) const UNREADABLE_UNSIGNED_ATTRIBUTE_WARNING: &str = "an unsigned attribute of the \
    signature could not be read; a signature timestamp may be missing or damaged (unsigned \
    attributes are not signed, so anyone can change them)";

/// A verified token: its report entry and its `genTime`, when the TSTInfo decoded.
pub(crate) struct Verified {
    /// The report entry.
    pub info: TimestampInfo,
    /// The `genTime`.
    pub gen_time: Option<GenTime>,
}

impl Verified {
    /// Intact, valid and not untrusted (V7b step 10's candidates).
    fn sound(&self) -> bool {
        self.info.intact && self.info.valid && self.info.trusted != Some(false)
    }
}

/// V7b steps 1–9 on one token: `expected_imprint(alg)` is the digest of the timestamped data.
pub(crate) fn verify(
    token: &[u8],
    expected_imprint: &dyn Fn(DigestAlgorithm) -> Option<Vec<u8>>,
    opts: &VerifyOptions,
) -> Verified {
    let anchors = opts
        .timestamp_trust_anchors_der
        .as_ref()
        .unwrap_or(&opts.trust_anchors_der);
    // The anchors may be named by later ESS identifiers (OpenSSL's chain includes them).
    let verification =
        tsp::verify_token_with_anchors(token, expected_imprint, &opts.extra_certs_der, anchors);
    let mut info = TimestampInfo {
        intact: verification.intact,
        valid: verification.valid,
        signature_algorithm: verification.signature_algorithm.clone(),
        problems: verification.problems.clone(),
        warnings: verification.warnings.clone(),
        ..TimestampInfo::default()
    };
    let gen_time = verification.tst_info.as_ref().map(|tst| tst.gen_time);
    if let Some(tst) = &verification.tst_info {
        info.gen_time = tst.gen_time.to_rfc3339();
        info.tsa_name = tst.tsa_name.clone();
        info.policy = Some(tst.policy.clone());
        info.serial_hex = Some(serial_hex(&tst.serial));
        info.accuracy_micros = tst.accuracy.as_ref().and_then(|a| {
            let seconds = a.seconds.unwrap_or(0).checked_mul(1_000_000)?;
            let millis = u64::from(a.millis.unwrap_or(0)) * 1000;
            seconds
                .checked_add(millis)?
                .checked_add(u64::from(a.micros.unwrap_or(0)))
        });
        info.ordering = tst.ordering;
        info.imprint_algorithm = Some(tst.imprint.digest.name().to_owned());
    }
    if let Some(cert) = &verification.tsa_cert {
        match x509info::certificate_info(cert) {
            Ok(certificate) => info.tsa = Some(certificate),
            Err(err) => info
                .warnings
                .push(format!("the TSA certificate cannot be read: {err}")),
        }
    }

    // Step 9: trust.
    if !anchors.is_empty() {
        info.trusted = Some(match (&verification.tsa_cert, gen_time) {
            (Some(cert), Some(gen_time)) => {
                let at = opts
                    .validation_time
                    .as_ref()
                    .map_or_else(|| gen_time.unix_time(), UnixTime::from_pdf_date);
                let mut pool = verification.certificates.clone();
                pool.extend(opts.extra_certs_der.iter().cloned());
                let result =
                    x509info::build_trust_for(TrustPurpose::TimeStamping, cert, &pool, anchors, at);

                for reason in &result.reasons {
                    info.warnings.push(format!("not trusted: {reason}"));
                }
                info.warnings.extend(result.warnings.iter().cloned());
                for problem in &result.problems {
                    if !info.problems.contains(problem) {
                        info.problems.push(problem.clone());
                    }
                }
                // OpenSSL checks the later ESS identifiers against the chain it verified, so a
                // trusted path above the TSA certificate is where they must be (QA round 2
                // finding 3): a re-issued copy of a CA certificate (same name and key) that
                // the token carries instead of the anchor no longer counts.
                if result.trusted
                    && info.valid
                    && result.path.len() > 1
                    && let Err(why) = tsp::ess_on_path(token, cert, &result.path)
                {
                    info.problems
                        .push(Problem::new(ProblemCode::TimestampEssMismatch, why));
                    info.valid = false;
                }
                let weak = info
                    .problems
                    .iter()
                    .any(|p| p.code == ProblemCode::WeakAlgorithm);
                if result.trusted && weak {
                    info.warnings
                        .push("not trusted: a weak algorithm (SHA-1) is used".to_owned());
                }
                if result.trusted && !(info.intact && info.valid) {
                    info.warnings
                        .push("not trusted: the token is not intact and valid".to_owned());
                }
                let trusted = result.trusted && !weak && info.intact && info.valid;
                if trusted && opts.validation_time.is_none() {
                    // D-7 is circular for the TSA itself (QA round 1 finding F8): a retired
                    // TSA key can still sign a token whose genTime lies inside its
                    // certificate's validity.
                    info.warnings.push(GEN_TIME_TRUST_WARNING.to_owned());
                }
                trusted
            }
            _ => {
                info.warnings
                    .push("not trusted: the TSA certificate or genTime is missing".to_owned());
                false
            }
        });
    }
    Verified { info, gen_time }
}

/// The uppercase hexadecimal of a serial number's INTEGER content octets without the sign
/// padding (as `CertificateInfo::serial_hex`).
fn serial_hex(content: &[u8]) -> String {
    let skip = content.iter().take_while(|&&b| b == 0).count();
    let significant = content.get(skip..).unwrap_or_default();
    if significant.is_empty() {
        return "00".to_owned();
    }
    significant.iter().map(|b| format!("{b:02X}")).collect()
}

/// What [`signature_timestamps`] selected.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Selected {
    /// The selected token is intact and valid (V8: PAdES B-T).
    pub sound: bool,
    /// The selected token's `genTime`, when it is trusted (V9).
    pub trusted_gen_time: Option<GenTime>,
}

/// V7b on the signature timestamps of `parsed`'s single SignerInfo: fills `report.timestamps`
/// and `report.timestamp` (step 10) and says whether the selected token is sound (V8) and its
/// `genTime` when it is trusted (V9, DECISIONS D13 D-7).
pub(crate) fn signature_timestamps(
    parsed: &ParsedCms,
    claimed: Option<&PdfDate>,
    opts: &VerifyOptions,
    report: &mut SignatureReport,
) -> Selected {
    let [signer_info] = parsed.signer_infos.as_slice() else {
        return Selected::default();
    };
    let (tokens, readable) = cms::signature_timestamp_tokens_read(signer_info);
    if !readable {
        // QA round 3 finding 1: without this a damaged token reads as no token at all.
        report.warn(UNREADABLE_UNSIGNED_ATTRIBUTE_WARNING);
    }
    if tokens.len() > MAX_TIMESTAMP_TOKENS {
        report.warn(format!(
            "the signature has more than {MAX_TIMESTAMP_TOKENS} signature timestamp tokens; \
             only the first {MAX_TIMESTAMP_TOKENS} are verified"
        ));
    }
    let value = &signer_info.signature;
    let expected = |digest: DigestAlgorithm| Some(digest.digest(&[value]));
    let verified: Vec<Verified> = tokens
        .iter()
        .take(MAX_TIMESTAMP_TOKENS)
        .map(|token| verify(token, &expected, opts))
        .collect();
    let mut out = Selected::default();
    if let Some(selected) = select(&verified).and_then(|index| verified.get(index)) {
        out.sound = selected.info.intact && selected.info.valid;
        if selected.info.trusted == Some(true) {
            out.trusted_gen_time = selected.gen_time;
        }
        if let (Some(gen_time), Some(claimed)) = (selected.gen_time, claimed)
            && gen_time.unix_seconds < UnixTime::from_pdf_date(claimed).secs()
        {
            report.warn("the timestamp predates the claimed signing time");
        }
        report.timestamp = Some(selected.info.clone());
    }
    report.timestamps = verified.into_iter().map(|v| v.info).collect();
    out
}

/// V7b step 10 (DECISIONS D13 D-5): the earliest `genTime` among the tokens that are intact,
/// valid and not untrusted, else the first token.
fn select(verified: &[Verified]) -> Option<usize> {
    verified
        .iter()
        .enumerate()
        .filter(|(_, v)| v.sound() && v.gen_time.is_some())
        .min_by_key(|(index, v)| (v.gen_time, *index))
        .map(|(index, _)| index)
        .or_else(|| (!verified.is_empty()).then_some(0))
}

/// V7c: a document timestamp, whose `/Contents` (`contents`, parsed as `parsed`) is the token
/// over the signed byte ranges (`digest_of`).
pub(crate) fn document_timestamp(
    contents: &[u8],
    parsed: &ParsedCms,
    digest_of: &dyn Fn(DigestAlgorithm) -> Option<Vec<u8>>,
    opts: &VerifyOptions,
    report: &mut SignatureReport,
) {
    let token = contents.get(parsed.raw.clone()).unwrap_or_default();
    let verified = verify(token, digest_of, opts);
    let info = verified.info;
    let rfc3161 = report.sub_filter.as_deref() == Some("ETSI.RFC3161");
    if !rfc3161 {
        report.problem(
            ProblemCode::UnsupportedSubFilter,
            match report.sub_filter.as_deref() {
                Some(other) => {
                    format!("a document timestamp's /SubFilter must be /ETSI.RFC3161, not /{other}")
                }
                None => "the document timestamp has no /SubFilter".to_owned(),
            },
        );
    }
    report.intact = info.intact;
    report.signature_valid = info.valid && rfc3161;
    report.trusted = info.trusted.map(|trusted| trusted && rfc3161);
    report.signer = info.tsa.clone();
    if verified.gen_time.is_some() {
        report.claimed_time = Some(info.gen_time.clone());
    }
    report.digest_algorithm = info.imprint_algorithm.clone();
    report.signature_algorithm = info.signature_algorithm.clone();
    for problem in &info.problems {
        report.problem(problem.code, problem.message.clone());
    }
    for warning in &info.warnings {
        report.warn(warning.clone());
    }
    report.pades_level = None;
    report.timestamps = vec![info.clone()];
    report.timestamp = Some(info);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified(intact: bool, valid: bool, trusted: Option<bool>, secs: i64) -> Verified {
        let text = format!("202610101200{secs:02}Z");
        Verified {
            info: TimestampInfo {
                intact,
                valid,
                trusted,
                ..TimestampInfo::default()
            },
            gen_time: Some(GenTime::parse(text.as_bytes()).unwrap()),
        }
    }

    #[test]
    fn selection_prefers_the_earliest_sound_token() {
        assert_eq!(select(&[]), None);
        let list = [
            verified(true, true, Some(true), 30),
            verified(true, true, Some(true), 10),
            verified(true, false, Some(false), 1),
            verified(true, true, Some(false), 2),
        ];
        assert_eq!(select(&list), Some(1));
        // Without anchors (trusted None) a sound token still counts.
        let list = [
            verified(false, true, None, 5),
            verified(true, true, None, 40),
        ];
        assert_eq!(select(&list), Some(1));
        // Nothing sound: the first token.
        let list = [
            verified(false, true, None, 5),
            verified(true, false, None, 4),
        ];
        assert_eq!(select(&list), Some(0));
    }

    #[test]
    fn serials_are_uppercase_hex() {
        assert_eq!(serial_hex(&[0x00, 0xAB, 0x01]), "AB01");
        assert_eq!(serial_hex(&[0]), "00");
        assert_eq!(serial_hex(&[]), "00");
    }
}
