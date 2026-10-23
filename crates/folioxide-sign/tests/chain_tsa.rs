#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Trust for a purpose (M4 brief §3.1, §5 V7b step 9): `build_trust_for` with
//! `TrustPurpose::TimeStamping` is `build_trust` plus OpenSSL's TSA certificate purpose check on
//! the leaf (DECISIONS D13 D-4), and `TrustPurpose::DocumentSigning` is exactly `build_trust`.

mod bt_support;

use bt_support::*;
use folioxide_sign::x509info::{TrustPurpose, UnixTime, build_trust, build_trust_for};

/// 2026-10-10T12:00:00Z.
const AT: UnixTime = UnixTime(1_791_633_600);

#[test]
fn tsa_trust_purpose_time_stamping() {
    let anchors = anchors();
    let tsa = cert("tsa.pem");
    let trusted = build_trust_for(TrustPurpose::TimeStamping, &tsa, &[], &anchors, AT);
    assert!(trusted.trusted, "{:?}", trusted.reasons);
    assert_eq!(trusted.path, [tsa.clone(), cert("root.pem")]);

    // Every variant is suitable for document signing rules (M3), but not for timestamping.
    for (variant, reason) in [
        ("tsa-eku-noncritical.pem", "not critical"),
        ("tsa-no-eku.pem", "no extended key usage"),
        ("tsa-eku-extra.pem", "not exactly"),
        ("tsa-ku-keyenc.pem", "more than digitalSignature"),
    ] {
        let leaf = cert(variant);
        let signing = build_trust_for(TrustPurpose::DocumentSigning, &leaf, &[], &anchors, AT);
        assert_eq!(signing, build_trust(&leaf, &[], &anchors, AT), "{variant}");
        assert!(signing.trusted, "{variant}: {:?}", signing.reasons);
        let stamping = build_trust_for(TrustPurpose::TimeStamping, &leaf, &[], &anchors, AT);
        assert!(!stamping.trusted, "{variant}");
        assert!(
            stamping
                .reasons
                .iter()
                .any(|r| r.contains("not suitable for timestamping") && r.contains(reason)),
            "{variant}: {:?}",
            stamping.reasons
        );
        // The path is still reported.
        assert_eq!(stamping.path.len(), 2, "{variant}");
    }

    // Not yet valid: suitable, but outside its validity at the validation time.
    let early = cert("tsa-not-yet-valid.pem");
    let result = build_trust_for(TrustPurpose::TimeStamping, &early, &[], &anchors, AT);
    assert!(!result.trusted);
    assert!(
        result
            .reasons
            .iter()
            .any(|r| r.contains("not valid before")),
        "{:?}",
        result.reasons
    );
    let later = UnixTime(3_200_000_000); // 2071
    assert!(build_trust_for(TrustPurpose::TimeStamping, &early, &[], &anchors, later).trusted);

    // A document signer is no TSA: no timestamping EKU.
    let signer = cert("signer-p256.pem");
    let pool = [cert("intermediate.pem")];
    assert!(build_trust_for(TrustPurpose::DocumentSigning, &signer, &pool, &anchors, AT).trusted);
    assert!(!build_trust_for(TrustPurpose::TimeStamping, &signer, &pool, &anchors, AT).trusted);

    // Without anchors nothing is trusted, for either purpose.
    for purpose in [TrustPurpose::DocumentSigning, TrustPurpose::TimeStamping] {
        assert!(!build_trust_for(purpose, &tsa, &[], &[], AT).trusted);
    }
}
