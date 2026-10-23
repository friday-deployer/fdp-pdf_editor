//! Response validation on the signing side ([`validate_response`], M4 brief §4.2) and token
//! verification on the verification side ([`verify_token`], §5 V7b steps 1–8).
//!
//! Both read the token with [`cms::parse`] and [`parse::tst_info`], verify the TSA's signature
//! with [`cms::verify_encapsulated`], and apply the same certificate rules (ESS binding,
//! [`check_tsa_certificate`], validity at `genTime`). They differ in what they do with a
//! failure: the signing side refuses the response at the first failed check, the verification
//! side records every defect as a [`Problem`] and never fails.

use super::parse::{self, RawTstInfo, invalid, null_or_absent};
use super::shape::token_shape;
use super::{
    GenTime, OID_CT_TST_INFO, PkiStatus, PkiStatusInfo, TimeStampReq, TimeStampResp,
    TokenVerification, ValidatedToken,
};
use crate::algorithms::DigestAlgorithm;
use crate::cms::verify::EssIssuers;
use crate::cms::{self, CmsVerification, ParsedCms, tlv};
use crate::error::Result;
use crate::problem::{Problem, ProblemCode};
use crate::x509info::{cert, check_tsa_certificate, validity_secs};

/// The names of the `PKIFailureInfo` bits (RFC 3161 §2.4.2).
const FAIL_INFO_NAMES: [(u32, &str); 8] = [
    (0, "badAlg"),
    (2, "badRequest"),
    (5, "badDataFormat"),
    (14, "timeNotAvailable"),
    (15, "unacceptedPolicy"),
    (16, "unacceptedExtension"),
    (17, "addInfoNotAvailable"),
    (25, "systemFailure"),
];

/// The `PKIFailureInfo` bits of `bits` by name, `bit<i>` for unnamed ones; `"none"` when no bit
/// is set.
pub(crate) fn fail_info_names(bits: Option<u32>) -> String {
    let Some(bits) = bits.filter(|b| *b != 0) else {
        return "none".to_owned();
    };
    let names: Vec<String> = (0..32u32)
        .filter(|i| bits & (1 << i) != 0)
        .map(|i| {
            FAIL_INFO_NAMES
                .iter()
                .find(|(bit, _)| *bit == i)
                .map_or_else(|| format!("bit{i}"), |(_, name)| (*name).to_owned())
        })
        .collect();
    names.join(", ")
}

/// The number of a `PKIStatus`.
fn status_number(status: PkiStatus) -> i64 {
    match status {
        PkiStatus::Granted => 0,
        PkiStatus::GrantedWithMods => 1,
        PkiStatus::Rejection => 2,
        PkiStatus::Waiting => 3,
        PkiStatus::RevocationWarning => 4,
        PkiStatus::RevocationNotification => 5,
        PkiStatus::Unknown(n) => n,
    }
}

/// `TSA refused: status <n>, "<statusString>", failInfo <names>` (brief §4.2 step 1).
fn refusal(status: &PkiStatusInfo) -> String {
    format!(
        "TSA refused: status {}, {:?}, failInfo {}",
        status_number(status.status),
        status.status_string.join("; "),
        fail_info_names(status.fail_info)
    )
}

/// The ESS signing-certificate binding of the token's single SignerInfo to `tsa_cert`, checked
/// as OpenSSL does (every attribute present, every identifier; finding F3). The later
/// identifiers name certificates linked to `tsa_cert` by verified issuer signatures among the
/// token's certificates and `more_certs` (QA round 2 finding 3).
fn ess_binding(
    parsed: &ParsedCms,
    tsa_cert: &[u8],
    more_certs: &[&[Vec<u8>]],
) -> std::result::Result<(), String> {
    let mut pool = parsed.certificates.clone();
    for certs in more_certs {
        pool.extend(certs.iter().cloned());
    }
    ess_check(parsed, tsa_cert, EssIssuers::Linked(&pool))
}

/// [`ess_binding`] with the later identifiers resolved against `issuers`.
fn ess_check(
    parsed: &ParsedCms,
    tsa_cert: &[u8],
    issuers: EssIssuers<'_>,
) -> std::result::Result<(), String> {
    let Some(signed_attrs) = parsed
        .signer_infos
        .first()
        .and_then(|si| si.signed_attrs.as_deref())
    else {
        return Err("the token has no signed attributes, so no ESS signing-certificate".to_owned());
    };
    cms::verify::check_signing_certificates(signed_attrs, tsa_cert, issuers)
}

/// See [`super::ess_on_path`].
pub(super) fn ess_on_path(
    token_der: &[u8],
    tsa_cert: &[u8],
    path: &[Vec<u8>],
) -> std::result::Result<(), String> {
    let parsed = cms::parse(token_der)
        .map_err(|err| format!("the timestamp token is not a CMS ContentInfo: {err}"))?;
    ess_check(&parsed, tsa_cert, EssIssuers::Path(path)).map_err(|why| ess_failure(&why))
}

/// The sentence of an [`ess_binding`] failure.
fn ess_failure(why: &str) -> String {
    format!("the token's ESS signing-certificate binding fails: {why} (RFC 3161 §2.4.1, RFC 5816)")
}

/// RFC 3161 §2.4.2: the TSTInfo `tsa` field, when present, names the TSA certificate (finding
/// F2); `Err` with the sentence when it does not.
fn tsa_name_check(raw: &RawTstInfo, tsa_cert: &[u8]) -> std::result::Result<(), String> {
    let Some(general_name) = raw.tsa_general_name.as_deref() else {
        return Ok(());
    };
    if cert::has_subject_name(tsa_cert, general_name) {
        return Ok(());
    }
    let named = raw
        .tsa_name
        .as_deref()
        .map_or_else(|| "a name".to_owned(), |name| format!("\"{name}\""));
    Err(format!(
        "the TSTInfo tsa field names {named}, which is not a subject name of the TSA \
         certificate (RFC 3161 §2.4.2)"
    ))
}

/// Whether `gen_time` lies within the validity of `cert_der` (inclusive, at second
/// granularity: a fraction after `notAfter`'s second is after it).
fn valid_at(cert_der: &[u8], gen_time: &GenTime) -> bool {
    validity_secs(cert_der).is_some_and(|(not_before, not_after)| {
        gen_time.unix_seconds >= not_before
            && (gen_time.unix_seconds < not_after
                || (gen_time.unix_seconds == not_after && gen_time.nanos == 0))
    })
}

/// Whether the token is DER as a whole (BER tokens are embedded verbatim with a warning,
/// DECISIONS D13 D-12).
fn token_is_der(token: &[u8], parsed: &ParsedCms) -> bool {
    crate::finish::is_der_cms(token, parsed)
}

/// The warnings a token's TSTInfo gives in every case.
fn tst_warnings(raw: &RawTstInfo, warnings: &mut Vec<String>) {
    if raw.gen_time.has_trailing_zeros() {
        warnings.push(format!(
            "the token's genTime {} has a fraction with trailing zeros, which RFC 3161 §2.4.2 \
             forbids",
            raw.gen_time.to_rfc3339()
        ));
    }
    if raw.tsa_name_unreadable {
        warnings.push(
            "the TSTInfo tsa name is not a directoryName Folioxide can read; it is not reported"
                .to_owned(),
        );
    }
}

/// The CMS problems of a token's TSA signature, as one sentence.
fn cms_failure(verification: &CmsVerification) -> String {
    let problems: Vec<String> = verification
        .problems
        .iter()
        .filter(|p| p.code != ProblemCode::WeakAlgorithm)
        .map(|p| p.message.clone())
        .collect();
    if problems.is_empty() {
        "the TSA's signature over the TSTInfo does not verify".to_owned()
    } else {
        format!(
            "the TSA's signature over the TSTInfo does not verify: {}",
            problems.join("; ")
        )
    }
}

// ---- the signing side --------------------------------------------------------------------------

/// See [`super::validate_response`].
pub(super) fn validate_response(
    request: &TimeStampReq,
    response_der: &[u8],
) -> Result<ValidatedToken> {
    // 1. The response parses, with status granted or grantedWithMods (D-9).
    let response = TimeStampResp::from_der(response_der).map_err(|err| {
        invalid(format!(
            "the TSA's response does not parse: {}",
            message(&err)
        ))
    })?;
    if !matches!(
        response.status.status,
        PkiStatus::Granted | PkiStatus::GrantedWithMods
    ) {
        return Err(invalid(refusal(&response.status)));
    }
    // 2. A token is present.
    let token = response.token.ok_or_else(|| {
        invalid("the TSA granted the request, but its response holds no timestamp token")
    })?;
    // 3. SignedData, one SignerInfo, id-ct-TSTInfo, eContent.
    let parsed = cms::parse(&token).map_err(|err| {
        invalid(format!(
            "the timestamp token is not a CMS ContentInfo: {}",
            message(&err)
        ))
    })?;
    let econtent = token_shape(&token, &parsed).map_err(invalid)?;
    // 4. The TSTInfo: version 1, the request's imprint, nonce and policy, a genTime.
    let raw = parse::tst_info(econtent)?;
    if raw.version != 1 {
        return Err(invalid(format!(
            "the TSTInfo version is {}, not 1",
            raw.version
        )));
    }
    let same_algorithm = DigestAlgorithm::from_oid(&raw.imprint_algorithm.oid)
        == Some(request.imprint.digest)
        && null_or_absent(raw.imprint_algorithm.parameters.as_deref());
    if !same_algorithm {
        return Err(invalid(format!(
            "the token's messageImprint uses {}, but the request used {}",
            raw.imprint_algorithm.oid, request.imprint.digest
        )));
    }
    if raw.hashed_message != request.imprint.hashed_message {
        return Err(invalid(
            "the token's messageImprint differs from the request's: it timestamps other data",
        ));
    }
    match (&request.nonce, &raw.nonce) {
        (Some(asked), Some(got))
            if tlv::integer_canonical(asked) == tlv::integer_canonical(got) => {}
        (Some(_), Some(_)) => {
            return Err(invalid(
                "the token's nonce differs from the request's (a replayed or foreign response)",
            ));
        }
        (Some(_), None) => {
            return Err(invalid(
                "the request had a nonce, but the token has none (a replayed response)",
            ));
        }
        (None, Some(_)) => {
            return Err(invalid("the request had no nonce, but the token has one"));
        }
        (None, None) => {}
    }
    if let Some(policy) = &request.policy
        && *policy != raw.policy
    {
        return Err(invalid(format!(
            "the token's policy is {}, but the request asked for {policy}",
            raw.policy
        )));
    }
    let tst_info = raw.to_tst_info().ok_or_else(|| {
        invalid(format!(
            "the token's imprint algorithm {} is not supported",
            raw.imprint_algorithm.oid
        ))
    })?;
    // 5. The TSA signature, with the certificate the token carries (certReq was true).
    let verification = cms::verify_encapsulated(&parsed, OID_CT_TST_INFO, &[]);
    if verification
        .problems
        .iter()
        .any(|p| p.code == ProblemCode::SignerCertNotFound)
    {
        return Err(invalid(
            "the token does not carry the TSA certificate, which RFC 3161 §2.4.1 requires \
             when certReq is true",
        ));
    }
    if !(verification.intact && verification.signature_valid) {
        return Err(invalid(cms_failure(&verification)));
    }
    if verification
        .problems
        .iter()
        .any(|p| p.code == ProblemCode::WeakAlgorithm)
    {
        return Err(invalid(
            "the TSA signs the token with SHA-1, a weak algorithm; such a token is never trusted",
        ));
    }
    let tsa_cert = verification
        .signer_cert
        .clone()
        .filter(|cert| parsed.certificates.contains(cert))
        .ok_or_else(|| {
            invalid(
                "the token does not carry the TSA certificate, which RFC 3161 §2.4.1 requires \
                 when certReq is true",
            )
        })?;
    // 6. The ESS signing-certificate binding, and the TSTInfo tsa name (RFC 3161 §2.4.2).
    ess_binding(&parsed, &tsa_cert, &[]).map_err(|why| invalid(ess_failure(&why)))?;
    tsa_name_check(&raw, &tsa_cert).map_err(invalid)?;
    // 7. The TSA certificate's purpose (D-4).
    check_tsa_certificate(&tsa_cert).map_err(|reason| {
        invalid(format!(
            "the TSA certificate is not suitable for timestamping: {reason}"
        ))
    })?;
    // 8. genTime within the TSA certificate's validity.
    if !valid_at(&tsa_cert, &raw.gen_time) {
        return Err(invalid(format!(
            "the token's genTime {} is outside the TSA certificate's validity",
            raw.gen_time.to_rfc3339()
        )));
    }

    let mut warnings = Vec::new();
    if !token_is_der(&token, &parsed) {
        warnings.push(
            "the TSA's timestamp token is BER-encoded; it is embedded verbatim (DECISIONS D13 \
             D-12)"
                .to_owned(),
        );
    }
    tst_warnings(&raw, &mut warnings);
    warnings.extend(verification.warnings.iter().cloned());
    Ok(ValidatedToken {
        token_der: token,
        tst_info,
        tsa_cert_der: tsa_cert,
        warnings,
    })
}

/// The message of a [`TimestampInvalid`](crate::Error::TimestampInvalid) without its prefix,
/// or the error's text.
fn message(err: &crate::Error) -> String {
    match err {
        crate::Error::TimestampInvalid(message) => message.clone(),
        other => other.to_string(),
    }
}

// ---- the verification side ---------------------------------------------------------------------

/// See [`super::verify_token`]; `issuer_certs` (trust anchors, say) join the certificates the
/// later ESS identifiers may name, but are never taken as the TSA certificate.
pub(super) fn verify_token(
    token_der: &[u8],
    expected_imprint: &dyn Fn(DigestAlgorithm) -> Option<Vec<u8>>,
    extra_certs: &[Vec<u8>],
    issuer_certs: &[Vec<u8>],
) -> TokenVerification {
    let mut out = TokenVerification::default();
    let malformed = |out: &mut TokenVerification, message: String| {
        out.problems
            .push(Problem::new(ProblemCode::TimestampMalformed, message));
    };

    // 1. A SignedData with one SignerInfo, eContentType id-ct-TSTInfo and eContent.
    let parsed = match cms::parse(token_der) {
        Ok(parsed) => parsed,
        Err(err) => {
            malformed(
                &mut out,
                format!("the timestamp token is not a CMS ContentInfo: {err}"),
            );
            return out;
        }
    };
    out.certificates = parsed.certificates.clone();
    if token_der
        .get(parsed.raw.end..)
        .is_some_and(|rest| rest.iter().any(|&b| b != 0))
    {
        malformed(
            &mut out,
            "the timestamp token is followed by bytes that are not zero".to_owned(),
        );
        return out;
    }
    let econtent = match token_shape(token_der, &parsed) {
        Ok(econtent) => econtent,
        Err(message) => {
            malformed(&mut out, message);
            return out;
        }
    };
    if !token_is_der(token_der, &parsed) {
        out.warnings
            .push("the timestamp token is BER-encoded; it is verified as found".to_owned());
    }

    // 2. The TSTInfo, version 1.
    let raw = match parse::tst_info(econtent) {
        Ok(raw) => raw,
        Err(err) => {
            malformed(&mut out, message(&err));
            return out;
        }
    };
    if raw.version != 1 {
        malformed(
            &mut out,
            format!("the TSTInfo version is {}, not 1", raw.version),
        );
        return out;
    }
    out.tst_info = raw.to_tst_info();
    tst_warnings(&raw, &mut out.warnings);

    // 3. intact: the imprint is the digest of the timestamped data.
    match DigestAlgorithm::from_oid(&raw.imprint_algorithm.oid) {
        None => out.problems.push(Problem::new(
            ProblemCode::UnsupportedAlgorithm,
            format!(
                "the token's imprint algorithm {} is not supported",
                raw.imprint_algorithm.oid
            ),
        )),
        Some(algorithm) => {
            if algorithm.is_weak() {
                out.problems.push(Problem::new(
                    ProblemCode::WeakAlgorithm,
                    "the token's imprint uses SHA-1, a weak algorithm; it is never trusted",
                ));
            }
            if !null_or_absent(raw.imprint_algorithm.parameters.as_deref()) {
                // RFC 5754 §2: SHA-2 parameters are absent or NULL; OpenSSL ts_check_imprints
                // refuses anything else as a mismatch (finding F4).
                out.problems.push(Problem::new(
                    ProblemCode::TimestampImprintMismatch,
                    "the token's messageImprint hash algorithm has parameters other than NULL, \
                     so it is not the algorithm of the timestamped data",
                ));
            } else {
                match expected_imprint(algorithm) {
                    Some(expected) if expected == raw.hashed_message => out.intact = true,
                    _ => out.problems.push(Problem::new(
                        ProblemCode::TimestampImprintMismatch,
                        "the token's messageImprint is not the digest of the timestamped data",
                    )),
                }
            }
        }
    }

    // 4. The TSA's signature over the TSTInfo.
    let verification = cms::verify_encapsulated(&parsed, OID_CT_TST_INFO, extra_certs);
    out.signature_algorithm = verification.signature_algorithm.clone();
    out.tsa_cert = verification.signer_cert.clone();
    out.warnings.extend(verification.warnings.iter().cloned());
    if verification
        .problems
        .iter()
        .any(|p| p.code == ProblemCode::WeakAlgorithm)
        && !out
            .problems
            .iter()
            .any(|p| p.code == ProblemCode::WeakAlgorithm)
    {
        out.problems.push(Problem::new(
            ProblemCode::WeakAlgorithm,
            "the TSA signs the token with SHA-1, a weak algorithm; it is never trusted",
        ));
    }
    let signature_ok = verification.intact && verification.signature_valid;
    if !signature_ok {
        out.problems.push(Problem::new(
            ProblemCode::TimestampSignatureInvalid,
            cms_failure(&verification),
        ));
    }

    // 5–7. The certificate rules, when the TSA certificate was found.
    let mut certificate_ok = false;
    if let Some(cert) = out.tsa_cert.clone() {
        let ess_ok = match ess_binding(&parsed, &cert, &[extra_certs, issuer_certs]) {
            Ok(()) => true,
            Err(why) => {
                out.problems.push(Problem::new(
                    ProblemCode::TimestampEssMismatch,
                    ess_failure(&why),
                ));
                false
            }
        };
        let name_ok = match tsa_name_check(&raw, &cert) {
            Ok(()) => true,
            Err(why) => {
                out.problems
                    .push(Problem::new(ProblemCode::TsaNameMismatch, why));
                false
            }
        };
        let suitable = match check_tsa_certificate(&cert) {
            Ok(()) => true,
            Err(reason) => {
                out.problems.push(Problem::new(
                    ProblemCode::TsaCertificateUnsuitable,
                    format!("the TSA certificate is not suitable for timestamping: {reason}"),
                ));
                false
            }
        };
        let in_validity = valid_at(&cert, &raw.gen_time);
        if !in_validity {
            out.problems.push(Problem::new(
                ProblemCode::TsaCertificateNotValidAtGenTime,
                format!(
                    "the token's genTime {} is outside the TSA certificate's validity (a \
                     backdated or postdated token)",
                    raw.gen_time.to_rfc3339()
                ),
            ));
        }
        certificate_ok = ess_ok && name_ok && suitable && in_validity;
    }

    // 8. valid.
    out.valid = signature_ok && certificate_ok;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_info_names_list_set_bits() {
        assert_eq!(fail_info_names(None), "none");
        assert_eq!(fail_info_names(Some(0)), "none");
        assert_eq!(fail_info_names(Some(0b101)), "badAlg, badRequest");
        assert_eq!(
            fail_info_names(Some(1 << 25 | 1 << 3)),
            "bit3, systemFailure"
        );
    }

    #[test]
    fn refusal_text() {
        let status = PkiStatusInfo {
            status: PkiStatus::Rejection,
            status_string: vec!["bad".into(), "worse".into()],
            fail_info: Some(1),
        };
        assert_eq!(
            refusal(&status),
            "TSA refused: status 2, \"bad; worse\", failInfo badAlg"
        );
        let status = PkiStatusInfo {
            status: PkiStatus::Unknown(-7),
            status_string: Vec::new(),
            fail_info: None,
        };
        assert_eq!(
            refusal(&status),
            "TSA refused: status -7, \"\", failInfo none"
        );
    }

    #[test]
    fn garbage_tokens_are_malformed() {
        for token in [&b""[..], b"\x30\x00", b"\x30\x03\x06\x01\x2A"] {
            let v = verify_token(token, &|_| None, &[], &[]);
            assert!(!v.intact && !v.valid);
            assert_eq!(
                v.problems[0].code,
                ProblemCode::TimestampMalformed,
                "{token:?}"
            );
        }
    }
}
