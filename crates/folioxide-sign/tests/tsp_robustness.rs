#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! RFC 3161 parsing never panics (M4 brief §6.2 "Robustness", R-19): requests, responses,
//! TSTInfos, `genTime`s and tokens, mutated from valid seeds or random, through every decoder
//! and both validators.

mod bt_support;

use bt_support::*;
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::tsp::{self, GenTime, MessageImprint, TimeStampReq, TimeStampResp, TstInfo};
use proptest::prelude::*;

/// The request every seed answers.
fn request() -> TimeStampReq {
    let digest = DigestAlgorithm::Sha256;
    TimeStampReq::new(
        MessageImprint::new(digest, digest.digest(&[b"seed"])),
        Some(NONCE),
        Some("1.2.3.4.1".into()),
    )
}

/// Valid inputs to mutate: a request, mock responses (granted with a token, refused), the
/// committed OpenSSL and pyHanko replies, a bare token, a TSTInfo and a genTime.
fn seeds() -> Vec<Vec<u8>> {
    let request_der = request().to_der();
    let tsa = mock_tsa();
    let token = tsa.token_for(&request_der).unwrap();
    let tst = folioxide_sign::cms::parse(&token)
        .unwrap()
        .econtent
        .unwrap();
    vec![
        request_der.clone(),
        tsa.respond(&request_der),
        tsa.respond(b"refused"),
        tsa_fixture("openssl-reply.tsr"),
        tsa_fixture("pyhanko-dummy.tsr"),
        token,
        tst,
        b"20261011035141.825589Z".to_vec(),
    ]
}

thread_local! {
    static SEEDS: Vec<Vec<u8>> = seeds();
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, failure_persistence: None, ..ProptestConfig::default() })]

    /// Mutated and random inputs never panic `TimeStampReq::from_der`,
    /// `TimeStampResp::from_der`, `TstInfo::from_der`, `GenTime::parse`, `validate_response`
    /// or `verify_token` (brief §6.2 `tsp_parse_never_panics`).
    #[test]
    fn tsp_parse_never_panics(
        seed in 0usize..9,
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>(), 0u8..4), 1..8),
        random in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let seeds = SEEDS.with(Clone::clone);
        let mut bytes = if seed < seeds.len() { seeds[seed].clone() } else { random };
        for (index, value, kind) in edits {
            if bytes.is_empty() {
                bytes.push(value);
                continue;
            }
            let at = index.index(bytes.len());
            match kind {
                0 => bytes[at] = value,
                1 => bytes[at] ^= 0x80,
                2 => { bytes.truncate(at); }
                _ => { bytes.insert(at, value); }
            }
        }
        let _ = TimeStampReq::from_der(&bytes);
        let _ = TstInfo::from_der(&bytes);
        let _ = GenTime::parse(&bytes);
        if let Ok(response) = TimeStampResp::from_der(&bytes)
            && let Some(token) = response.token
        {
            let _ = tsp::verify_token(&token, &|d| Some(d.digest(&[b"seed"])), &[]);
        }
        let _ = tsp::validate_response(&request(), &bytes);
        let _ = tsp::verify_token(&bytes, &|d| Some(d.digest(&[b"seed"])), &[]);
    }
}

#[test]
fn seeds_are_valid() {
    let seeds = seeds();
    assert!(TimeStampReq::from_der(&seeds[0]).is_ok());
    tsp::validate_response(&request(), &seeds[1]).unwrap();
    assert!(TimeStampResp::from_der(&seeds[2]).is_ok());
    assert!(TimeStampResp::from_der(&seeds[3]).is_ok());
    assert!(TimeStampResp::from_der(&seeds[4]).is_ok());
    let v = tsp::verify_token(&seeds[5], &|d| Some(d.digest(&[b"seed"])), &[]);
    assert!(v.intact && v.valid, "{v:?}");
    assert!(TstInfo::from_der(&seeds[6]).is_ok());
    assert!(GenTime::parse(&seeds[7]).is_ok());
}

#[test]
fn deep_and_huge_inputs_are_bounded() {
    // 40 nested indefinite-length SEQUENCEs: beyond the depth limit, an error.
    let mut deep = Vec::new();
    for _ in 0..40 {
        deep.extend([0x30, 0x80]);
    }
    deep.extend([0u8; 80]);
    assert!(TimeStampResp::from_der(&deep).is_err());
    assert!(TstInfo::from_der(&deep).is_err());
    let v = tsp::verify_token(&deep, &|_| None, &[]);
    assert!(!v.intact && !v.valid);
    // A PKIFreeText with 1,000 strings is refused, not collected.
    let text = [0x0C, 0x01, b'x'].repeat(1000);
    let mut free_text = vec![0x30, 0x82, 0x0B, 0xB8];
    free_text.extend(text);
    let mut status = vec![0x02, 0x01, 0x02];
    status.extend(free_text);
    let mut info = vec![0x30, 0x82, 0x0B, 0xBF];
    info.extend(status);
    let mut response = vec![0x30, 0x82, 0x0B, 0xC3];
    response.extend(info);
    let err = TimeStampResp::from_der(&response).unwrap_err();
    assert!(err.to_string().contains("more than 16 strings"), "{err}");
}
