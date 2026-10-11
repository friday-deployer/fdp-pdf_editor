//! Fuzz target `fuzz_cms_parse`: the CMS side of signature verification (RFC 5652; M3 brief
//! §4.3, R-18): the raw-slice TLV parser `folioxide_sign::cms::parse` (BER and DER, depth 32, at
//! most 64 certificates and 64 attributes), then `cms::verify_detached` over a fixed document
//! digest, then certificate information and trust path building for every certificate the CMS
//! carries.
//!
//! The input is a CMS `ContentInfo` as it appears in a signature's `/Contents`, so the committed
//! `fixtures/sign/*.p7s` files are a useful seed corpus as they are. On any input:
//! - nothing panics, overflows the stack or hangs (a run still going after [`HANG`] is aborted
//!   by `folioxide_testkit::budget::Watchdog`, which libFuzzer saves as a crash);
//! - a parsed CMS respects the documented bounds: its outer element lies inside the input, at
//!   most `MAX_CERTIFICATES` certificates, and every SignerInfo's raw slice is inside it;
//! - `verify_detached` keeps its invariants: a valid signature names its signer certificate and
//!   digest algorithm, and an intact one has a message-digest attribute (or no signed
//!   attributes at all);
//! - trust building never trusts a path without the anchor it was given.
//!
//! Run with `cargo +nightly fuzz run fuzz_cms_parse` from the repository root.

#![no_main]

use std::time::Duration;

use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::cms;
use folioxide_sign::x509info::{self, UnixTime};
use folioxide_testkit::budget::Watchdog;
use libfuzzer_sys::fuzz_target;

/// The most one input may take before the watchdog aborts: parsing is linear, and the crypto is
/// at most one RSA-8192 or ECDSA verification per SignerInfo and per path link.
const HANG: Duration = Duration::from_secs(60);

/// The document bytes whose digest every SignerInfo is checked against.
const DOCUMENT: &[u8] = b"%PDF-1.7 fuzz_cms_parse document bytes";

/// 2026-10-10T12:00:00Z, the test PKI's signing time.
const AT: UnixTime = UnixTime(1_791_633_600);

fuzz_target!(|data: &[u8]| {
    let _armed = Watchdog::global(HANG).arm("fuzz_cms_parse input");
    let Ok(parsed) = cms::parse(data) else {
        return;
    };
    assert!(parsed.raw.start <= parsed.raw.end && parsed.raw.end <= data.len());
    assert!(parsed.certificates.len() <= cms::MAX_CERTIFICATES);
    for info in &parsed.signer_infos {
        assert!(info.raw.start <= info.raw.end && info.raw.end <= parsed.raw.end);
    }

    let digest_of = |algorithm: DigestAlgorithm| Some(algorithm.digest(&[DOCUMENT]));
    let verification = cms::verify_detached(&parsed, &digest_of, &[]);
    if verification.signature_valid {
        assert!(verification.signer_cert.is_some(), "{verification:?}");
        assert!(verification.digest.is_some(), "{verification:?}");
        assert_eq!(parsed.signer_infos.len(), 1, "{verification:?}");
    }
    if verification.intact {
        let has_attrs = parsed
            .signer_infos
            .first()
            .is_some_and(|info| info.signed_attrs.is_some());
        assert!(
            !has_attrs || verification.pades_attrs.message_digest.is_some(),
            "{verification:?}"
        );
    }

    // Certificate information and trust over whatever the CMS carries.
    for cert in &parsed.certificates {
        let _ = x509info::certificate_info(cert);
    }
    if let Some(signer) = parsed.certificates.first() {
        // Trusted only through an anchor: with none, never.
        let none = x509info::build_trust(signer, &parsed.certificates, &[], AT);
        assert!(!none.trusted);
        // With the CMS's last certificate as the anchor, a trusted path ends at it.
        if let Some(anchor) = parsed.certificates.last() {
            let result = x509info::build_trust(
                signer,
                &parsed.certificates,
                std::slice::from_ref(anchor),
                AT,
            );
            if result.trusted {
                assert!(result.reasons.is_empty() && !result.path.is_empty());
            }
        }
    }
});
