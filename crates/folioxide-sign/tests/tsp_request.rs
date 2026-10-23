#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! RFC 3161 `TimeStampReq` encoding (M4 brief §4.1, §6.2 "TSP, Requests").
//!
//! The golden bytes are the brief's (the layout of `openssl ts -query -cert`), and the
//! nonce-free vectors were written by OpenSSL 3.0.13:
//! `openssl ts -query -data folioxide.txt -sha256 -cert -no_nonce [-tspolicy 1.2.3.4.1]`, where
//! `folioxide.txt` holds the 9 bytes `folioxide`.

use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::tsp::{MessageImprint, TimeStampReq};

/// SHA-256 of the 9 bytes `folioxide` (`openssl dgst -sha256`).
const FOLIOXIDE_SHA256: &str = "069936fe77e3f082732c2bfc9bc3865ce01ca9621fd1e9b1ad09dacf2a0b8a6b";

fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn imprint() -> MessageImprint {
    let digest = DigestAlgorithm::Sha256.digest(&[b"folioxide"]);
    assert_eq!(digest, hex(FOLIOXIDE_SHA256));
    MessageImprint::new(DigestAlgorithm::Sha256, digest)
}

/// The DER `messageImprint` of [`imprint`].
const IMPRINT_DER: &str = "3031 300D 0609 608648016503040201 0500
                           0420 069936FE77E3F082732C2BFC9BC3865CE01CA9621FD1E9B1AD09DACF2A0B8A6B";

#[test]
fn tst_request_der_golden() {
    // Brief §4.1: nonce 0x0102030405060708, no policy.
    let request = TimeStampReq::new(imprint(), Some(0x0102_0304_0506_0708), None);
    let golden = hex(&format!(
        "3043 020101 {IMPRINT_DER} 0208 0102030405060708 0101FF"
    ));
    assert_eq!(request.to_der(), golden);

    // A nonce with its top bit set gains a 00 octet: positive INTEGER, outer length 0x44.
    let request = TimeStampReq::new(imprint(), Some(0x8000_0000_0000_0000), None);
    let golden = hex(&format!(
        "3044 020101 {IMPRINT_DER} 0209 008000000000000000 0101FF"
    ));
    assert_eq!(request.to_der(), golden);

    // A policy goes between the messageImprint and the nonce.
    let request = TimeStampReq::new(
        imprint(),
        Some(0x0102_0304_0506_0708),
        Some("1.2.3.4.1".into()),
    );
    let golden = hex(&format!(
        "3049 020101 {IMPRINT_DER} 06042A030401 0208 0102030405060708 0101FF"
    ));
    assert_eq!(request.to_der(), golden);

    // Byte for byte what OpenSSL writes without a nonce, with and without a policy.
    let openssl = hex(
        "30390201013031300d060960864801650304020105000420069936fe77e3f082732c2bfc9bc3865ce01ca962\
         1fd1e9b1ad09dacf2a0b8a6b0101ff",
    );
    assert_eq!(TimeStampReq::new(imprint(), None, None).to_der(), openssl);
    let openssl_policy = hex(
        "303f0201013031300d060960864801650304020105000420069936fe77e3f082732c2bfc9bc3865ce01ca962\
         1fd1e9b1ad09dacf2a0b8a6b06042a0304010101ff",
    );
    let request = TimeStampReq::new(imprint(), None, Some("1.2.3.4.1".into()));
    assert_eq!(request.to_der(), openssl_policy);
}

#[test]
fn tst_request_nonce_is_positive_integer() {
    let mut nonces = vec![0, 1, 0x7F, 0x80, 0xFF, 0x0100, 0x7FFF, 0x8000, u64::MAX];
    nonces.extend((0..64).map(|bit| 1u64 << bit));
    nonces.extend((0..64).map(|bit| (1u64 << bit) - 1));
    for nonce in nonces {
        let request = TimeStampReq::new(imprint(), Some(nonce), None);
        assert!(request.cert_req);
        let octets = request.nonce.clone().unwrap();
        // Positive: the top bit of the first octet is clear.
        assert!(octets[0] & 0x80 == 0, "{nonce:#x}: {octets:02x?}");
        // Minimal: a leading 00 only before an octet with its top bit set (X.690 §8.3.2).
        if octets.len() > 1 && octets[0] == 0 {
            assert!(octets[1] & 0x80 != 0, "{nonce:#x}: {octets:02x?}");
        }
        assert!(octets.len() <= 9);
        // The same value.
        let value = octets.iter().fold(0u128, |v, &b| (v << 8) | u128::from(b));
        assert_eq!(value, u128::from(nonce));
        // And the DER carries exactly these octets as an INTEGER, before certReq.
        let der = request.to_der();
        let mut tail = vec![0x02, octets.len() as u8];
        tail.extend_from_slice(&octets);
        tail.extend_from_slice(&[0x01, 0x01, 0xFF]);
        assert!(der.ends_with(&tail), "{nonce:#x}");
    }
}

#[test]
fn tst_request_from_der_roundtrip() {
    for digest in [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ] {
        let imprint = MessageImprint::new(digest, digest.digest(&[b"folioxide"]));
        for nonce in [
            None,
            Some(0),
            Some(0x80),
            Some(NONCE_GOLDEN),
            Some(u64::MAX),
        ] {
            for policy in [None, Some("1.2.3.4.1".to_owned())] {
                let request = TimeStampReq::new(imprint.clone(), nonce, policy);
                let der = request.to_der();
                assert_eq!(TimeStampReq::from_der(&der).unwrap(), request);
                // certReq false is the DEFAULT and is omitted; it round-trips too.
                let mut no_cert = request.clone();
                no_cert.cert_req = false;
                assert_eq!(TimeStampReq::from_der(&no_cert.to_der()).unwrap(), no_cert);
            }
        }
    }
    // OpenSSL's own request (no nonce) parses to the same value.
    let openssl = hex(
        "30390201013031300d060960864801650304020105000420069936fe77e3f082732c2bfc9bc3865ce01ca962\
         1fd1e9b1ad09dacf2a0b8a6b0101ff",
    );
    assert_eq!(
        TimeStampReq::from_der(&openssl).unwrap(),
        TimeStampReq::new(imprint(), None, None)
    );
    // Absent hash parameters are accepted (RFC 5754 §2).
    let absent = hex("3037020101302f300b0609608648016503040201\
         0420069936fe77e3f082732c2bfc9bc3865ce01ca9621fd1e9b1ad09dacf2a0b8a6b0101ff");
    assert_eq!(
        TimeStampReq::from_der(&absent).unwrap(),
        TimeStampReq::new(imprint(), None, None)
    );
}

#[test]
fn tst_request_from_der_is_strict() {
    let good = TimeStampReq::new(imprint(), Some(NONCE_GOLDEN), None).to_der();
    let reject = |der: &[u8], why: &str| {
        let err = TimeStampReq::from_der(der).unwrap_err();
        assert_eq!(
            err.code(),
            folioxide_syntax::ErrorCode::TimestampInvalid,
            "{why}: {err}"
        );
    };
    reject(&[], "empty");
    reject(&good[..good.len() - 1], "truncated");
    reject(&[good.as_slice(), &[0]].concat(), "trailing byte");
    // Version 2.
    let mut v2 = good.clone();
    v2[4] = 2;
    reject(&v2, "version 2");
    // certReq FALSE written explicitly is not DER.
    let mut false_cert = good.clone();
    *false_cert.last_mut().unwrap() = 0x00;
    reject(&false_cert, "explicit FALSE");
    // A nonce with a redundant leading zero.
    let padded = hex(&format!(
        "3044 020101 {IMPRINT_DER} 0209 000102030405060708 0101FF"
    ));
    reject(&padded, "non-minimal nonce");
    // A negative nonce.
    let negative = hex(&format!("303C 020101 {IMPRINT_DER} 0201 FF 0101FF"));
    reject(&negative, "negative nonce");
    // A hash of the wrong length, and an unknown algorithm (SHA3-256).
    let short = hex("30380201013030300d0609608648016503040201050004 1f\
         069936fe77e3f082732c2bfc9bc3865ce01ca9621fd1e9b1ad09dacf2a0b8a0101ff");
    reject(&short, "short hash");
    let sha3 = hex(
        "30390201013031300d060960864801650304020805000420069936fe77e3f082732c2bfc9bc3865ce01ca962\
         1fd1e9b1ad09dacf2a0b8a6b0101ff",
    );
    reject(&sha3, "SHA3-256");
    // Extensions [0].
    let extended = hex(&format!("3041 020101 {IMPRINT_DER} 0101FF A000"));
    reject(&extended, "extensions");
}

/// The golden nonce of brief §4.1.
const NONCE_GOLDEN: u64 = 0x0102_0304_0506_0708;
