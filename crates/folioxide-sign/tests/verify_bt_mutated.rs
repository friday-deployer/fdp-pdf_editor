#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! `no_panic_verify_mutated_bt` (M4 brief §6.2 "Verification", R-19): B-T files mutated with a
//! fixed seed, half anywhere ([`folioxide_testkit::mutate`]) and half inside the timestamp
//! token's hexadecimal digits in `/Contents` (so that the verifier reaches the token), at least
//! 5,000 in all, each verified within the budget of [`folioxide_testkit::budget::within`].
//!
//! Every report keeps the invariants: `is_valid` implies a sound signature; `pades_level` B-T
//! implies a selected timestamp that is intact and valid; a trusted timestamp is intact and
//! valid; at most [`MAX_TIMESTAMP_TOKENS`] tokens are listed; and **no forgery**: a timestamp
//! that is still intact and valid after its token was mutated has the base token's `genTime`
//! (the TSTInfo is signed, so only unsigned parts of the token can change).

mod bt_support;

use std::time::Duration;

use bt_support::*;
use folioxide_sign::bt::TimestampParams;
use folioxide_sign::cms;
use folioxide_sign::prepare::{PrepareRequest, SignatureOptions, prepare};
use folioxide_sign::report::{PadesLevel, SignatureReport};
use folioxide_sign::signer::Signer;
use folioxide_sign::tsp::{DEFAULT_TSA_RESERVE, MAX_TIMESTAMP_TOKENS};
use folioxide_sign::verify_pdf::{VerifyOptions, verify_bytes};
use folioxide_testkit::budget;
use folioxide_testkit::mutate::Mutator;
use folioxide_testkit::tsa::MockTsaOptions;

/// Mutations per base: 4 bases × 1,500 = 6,000.
const MUTATIONS_PER_BASE: usize = 1_500;

/// The budget of the whole run (a debug-build verification takes a few tens of milliseconds).
const RUN_BUDGET: Duration = Duration::from_secs(900);

/// The budget of one verification.
const ONE_BUDGET: Duration = Duration::from_secs(5);

/// The B-T files that are mutated.
fn bases() -> Vec<(&'static str, Vec<u8>)> {
    let named = Tsa(mock_tsa_with(
        "tsa.pem",
        MockTsaOptions {
            tsa_name: true,
            signing_time_attr: true,
            gen_time: "20261010120030.125Z".into(),
            ..MockTsaOptions::default()
        },
    ));
    let openssl = {
        let signer = rsa2048();
        let request = PrepareRequest::new(
            signer.certificate_chain().to_vec(),
            signer.algorithm(),
            time(),
        )
        .with_options(SignatureOptions::new(time()).with_tsa_reserve(Some(DEFAULT_TSA_RESERVE)));
        let prepared = prepare(&open(&minimal()), &request).unwrap();
        let value = signer
            .sign(prepared.digest_algorithm(), prepared.to_be_signed())
            .unwrap();
        let tsq = prepared
            .timestamp_request(&value, &TimestampParams::new().with_nonce(Some(NONCE)))
            .unwrap();
        prepared
            .finish_with_timestamp(&value, &tsq, &tsa_fixture("openssl-reply.tsr"))
            .unwrap()
    };
    vec![
        ("bt-rsa2048-mock", sign_bt(&minimal(), &rsa2048())),
        (
            "bt-p256-mock-named",
            sign_bt_with(&minimal(), &p256(), SignatureOptions::new(time()), &named).unwrap(),
        ),
        ("bt-rsa2048-openssl", openssl),
        ("pyhanko-bt-rsa2048", pdf_fixture("pyhanko-bt-rsa2048.pdf")),
    ]
}

/// The byte range, in the file, of the hexadecimal digits of the first signature's token.
fn token_digits(pdf: &[u8]) -> (std::ops::Range<usize>, String) {
    let report = &verify(pdf)[0];
    let ts = report.timestamp.as_ref().expect("a B-T base");
    assert!(ts.intact && ts.valid, "the base's token is sound");
    let br = report.byte_range.as_deref().unwrap();
    let gap = (br[0] + br[1]) as usize..br[2] as usize;
    let digits = &pdf[gap.start + 1..gap.end - 1];
    let cms_bytes: Vec<u8> = digits
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    let parsed = cms::parse(&cms_bytes).unwrap();
    let token = cms::signature_timestamp_tokens(&parsed.signer_infos[0]).remove(0);
    let wanted = hex(&token);
    let haystack = String::from_utf8_lossy(digits).to_uppercase();
    let at = haystack.find(&wanted).expect("the token's digits");
    let start = gap.start + 1 + at;
    (start..start + wanted.len(), ts.gen_time.clone())
}

/// Replaces one to four hexadecimal digits of `range` with other digits.
fn mutate_token(mutator: &mut Mutator, base: &[u8], range: &std::ops::Range<usize>) -> Vec<u8> {
    const DIGITS: &[u8] = b"0123456789ABCDEF";
    let mut out = base.to_vec();
    for _ in 0..=mutator.below(4) {
        let at = range.start + mutator.below(range.len());
        out[at] = DIGITS[mutator.below(16)];
    }
    out
}

/// The broken invariants of `reports`; `base_gen_time` is the base token's `genTime`, checked
/// when `token_mutated`.
fn violations(
    reports: &[SignatureReport],
    base_gen_time: &str,
    token_mutated: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    for r in reports {
        let what = summary(r);
        if r.is_valid()
            && !(r.byte_range_ok && r.intact && r.signature_valid && r.problems.is_empty())
        {
            out.push(format!("is_valid without its conditions: {what}"));
        }
        if r.pades_level == Some(PadesLevel::BT)
            && !r.timestamp.as_ref().is_some_and(|t| t.intact && t.valid)
        {
            out.push(format!("B-T without a sound selected timestamp: {what}"));
        }
        if r.pades_level.is_some() && !(r.intact && r.signature_valid && r.byte_range_ok) {
            out.push(format!("PAdES level on a broken signature: {what}"));
        }
        if r.timestamps.len() > MAX_TIMESTAMP_TOKENS {
            out.push(format!("{} timestamps listed: {what}", r.timestamps.len()));
        }
        if let Some(selected) = &r.timestamp
            && !r.timestamps.contains(selected)
        {
            out.push(format!("the selected timestamp is not listed: {what}"));
        }
        for t in &r.timestamps {
            if t.trusted == Some(true) && !(t.intact && t.valid) {
                out.push(format!("a trusted timestamp that is not sound: {what}"));
            }
            if token_mutated && t.intact && t.valid && t.gen_time != base_gen_time {
                out.push(format!(
                    "forgery: a mutated token is sound with genTime {}: {what}",
                    t.gen_time
                ));
            }
        }
    }
    out
}

#[test]
fn no_panic_verify_mutated_bt() {
    let (mutations, failures) = budget::within(RUN_BUDGET, || {
        let bases = bases();
        let results: Vec<(usize, Vec<String>)> = std::thread::scope(|scope| {
            let handles: Vec<_> = bases
                .iter()
                .enumerate()
                .map(|(number, (name, bytes))| {
                    scope.spawn(move || {
                        let (range, gen_time) = token_digits(bytes);
                        let mut mutator = Mutator::new(0xB7_0000 + number as u64);
                        let mut failures = Vec::new();
                        for index in 0..MUTATIONS_PER_BASE {
                            let token_mutated = index % 2 == 1;
                            let input = if token_mutated {
                                mutate_token(&mut mutator, bytes, &range)
                            } else {
                                mutator.mutate(bytes)
                            };
                            let options = if index % 4 < 2 {
                                VerifyOptions::new().with_trust_anchors_der(anchors())
                            } else {
                                VerifyOptions::default()
                            };
                            let started = std::time::Instant::now();
                            let outcome =
                                std::panic::catch_unwind(|| verify_bytes(input.clone(), &options));
                            let elapsed = started.elapsed();
                            let mut problems = match outcome {
                                Ok(Ok(reports)) => violations(&reports, &gen_time, token_mutated),
                                Ok(Err(_)) => Vec::new(),
                                Err(_) => vec!["panicked".to_owned()],
                            };
                            if elapsed > ONE_BUDGET {
                                problems.push(format!("took {elapsed:.2?}"));
                            }
                            for problem in problems {
                                failures.push(format!("{name} #{index}: {problem}"));
                            }
                        }
                        (MUTATIONS_PER_BASE, failures)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let mutations: usize = results.iter().map(|(n, _)| n).sum();
        let failures: Vec<String> = results.into_iter().flat_map(|(_, f)| f).collect();
        (mutations, failures)
    })
    .unwrap_or_else(|overrun| panic!("no_panic_verify_mutated_bt: {overrun}"))
    .0;
    assert!(mutations >= 5_000, "{mutations} mutations");
    assert!(
        failures.is_empty(),
        "{} of {mutations} mutations broke an invariant:\n{}",
        failures.len(),
        failures
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
