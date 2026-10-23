//! Fuzz target `fuzz_tsp_parse`: the RFC 3161 side of B-T signing and verification (M4 brief
//! §4.1, §4.2, §5 V7b; R-19): every TSP decoder and both validators on the same input.
//!
//! The input is read as each of a `TimeStampReq`, a `TimeStampResp`, a `TSTInfo`, a `genTime`
//! and a timestamp token, so the committed `fixtures/sign/tsa/*.tsq` and `*.tsr` files are a
//! useful seed corpus as they are. On any input:
//! - nothing panics, overflows the stack or hangs (a run still going after [`HANG`] is aborted
//!   by `folioxide_testkit::budget::Watchdog`, which libFuzzer saves as a crash);
//! - a decoded request survives a round trip through `to_der`, and a decoded `genTime` through
//!   its RFC 3339 text;
//! - `validate_response` accepts only a version-1 TSTInfo with the request's imprint and nonce,
//!   and returns the TSA certificate;
//! - `verify_token` keeps its invariants: an intact token has a decoded TSTInfo, a valid one a
//!   TSA certificate, and a token that is not both intact and valid names a problem.
//!
//! Run with `cargo +nightly fuzz run fuzz_tsp_parse` from the repository root.

#![no_main]

use std::time::Duration;

use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::tsp::{self, GenTime, MessageImprint, TimeStampReq, TimeStampResp, TstInfo};
use folioxide_testkit::budget::Watchdog;
use libfuzzer_sys::fuzz_target;

/// The most one input may take before the watchdog aborts: parsing is linear, and the crypto is
/// at most two RSA-8192 or ECDSA verifications.
const HANG: Duration = Duration::from_secs(60);

/// The data every request and token is checked against.
const DATA: &[u8] = b"fuzz_tsp_parse signature value";

/// The nonce of the fixed request.
const NONCE: u64 = 0x0102_0304_0506_0708;

/// `genTime` content octets back from RFC 3339 text: `YYYY-MM-DDThh:mm:ss[.f]Z` without the
/// separators.
fn generalized(rfc3339: &str) -> Vec<u8> {
    rfc3339
        .bytes()
        .filter(|b| !matches!(b, b'-' | b'T' | b':'))
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let _armed = Watchdog::global(HANG).arm("fuzz_tsp_parse input");

    if let Ok(request) = TimeStampReq::from_der(data) {
        let again = TimeStampReq::from_der(&request.to_der()).expect("a written request parses");
        assert_eq!(again, request);
    }

    if let Ok(response) = TimeStampResp::from_der(data) {
        if let Some(token) = &response.token {
            assert!(token.len() <= data.len());
        }
    }

    if let Ok(tst) = TstInfo::from_der(data) {
        assert!(tst.gen_time.nanos < 1_000_000_000);
        assert!(tst.gen_time.fraction_digits <= 9);
    }

    if let Ok(time) = GenTime::parse(data) {
        let text = time.to_rfc3339();
        let again = GenTime::parse(&generalized(&text)).expect("a written genTime parses");
        assert_eq!(again, time, "{text}");
    }

    let digest = DigestAlgorithm::Sha256;
    let request = TimeStampReq::new(
        MessageImprint::new(digest, digest.digest(&[DATA])),
        Some(NONCE),
        None,
    );
    if let Ok(token) = tsp::validate_response(&request, data) {
        assert_eq!(token.tst_info.version, 1);
        assert_eq!(token.tst_info.imprint, request.imprint);
        assert!(token.tst_info.nonce.is_some());
        assert!(!token.tsa_cert_der.is_empty() && !token.token_der.is_empty());
    }

    let expected = |algorithm: DigestAlgorithm| Some(algorithm.digest(&[DATA]));
    let verification = tsp::verify_token(data, &expected, &[]);
    if verification.intact {
        assert!(verification.tst_info.is_some(), "{verification:?}");
    }
    if verification.valid {
        assert!(verification.tsa_cert.is_some(), "{verification:?}");
    }
    if !(verification.intact && verification.valid) {
        assert!(!verification.problems.is_empty(), "{verification:?}");
    }
});
