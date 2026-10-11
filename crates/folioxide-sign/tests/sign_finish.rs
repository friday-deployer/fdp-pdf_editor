#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The second phase of the two-phase flow (M3 brief §4.4, §6.2 "finish and embed"):
//! `PreparedSignature::finish` and `PreparedSignature::embed_cms` with real keys and real CMS.

mod sign_support;

use folioxide_sign::Error;
use folioxide_sign::cms;
use folioxide_sign::field::SubFilter;
use folioxide_sign::prepare::{PrepareRequest, PreparedSignature, SignatureOptions, prepare};
use folioxide_sign::report::{Coverage, PadesLevel};
use folioxide_sign::signer::{LocalSigner, Signer};
use folioxide_syntax::ErrorCode;
use folioxide_testkit::fixtures::syntax;
use sign_support::*;

/// Prepares `source` for `signer` with `options`.
fn prepared_with(
    source: &[u8],
    signer: &LocalSigner,
    options: SignatureOptions,
) -> PreparedSignature {
    let request = PrepareRequest::new(
        signer.certificate_chain().to_vec(),
        signer.algorithm(),
        time(),
    )
    .with_options(options);
    prepare(&open(source), &request).unwrap()
}

fn prepared(source: &[u8], signer: &LocalSigner) -> PreparedSignature {
    prepared_with(source, signer, SignatureOptions::new(time()))
}

/// The CMS `finish` would embed, assembled from `signed_attrs` and a signature over them made
/// by `signer`, with `chain`.
fn cms_over(
    signed_attrs: &[u8],
    signer: &LocalSigner,
    chain: &[Vec<u8>],
    p: &PreparedSignature,
) -> Vec<u8> {
    let value = signer.sign(p.digest_algorithm(), signed_attrs).unwrap();
    cms::assemble(
        signed_attrs,
        &value,
        chain,
        signer.algorithm(),
        signer.key_kind(),
        p.digest_algorithm(),
    )
    .unwrap()
}

/// A DER element.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let octets: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | octets.len() as u8);
        out.extend(octets);
    }
    out.extend_from_slice(content);
    out
}

/// The elements inside the DER element `der` (definite lengths).
fn children(der: &[u8]) -> Vec<Vec<u8>> {
    let header = |at: usize| -> (usize, usize) {
        let first = der[at + 1];
        if first < 0x80 {
            (2, first as usize)
        } else {
            let n = (first & 0x7F) as usize;
            let len = der[at + 2..at + 2 + n]
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | b as usize);
            (2 + n, len)
        }
    };
    let (outer_header, outer_len) = header(0);
    let mut pos = outer_header;
    let mut out = Vec::new();
    while pos < outer_header + outer_len {
        let (h, len) = header(pos);
        out.push(der[pos..pos + h + len].to_vec());
        pos += h + len;
    }
    out
}

/// `signed_attrs` (a DER `SET OF Attribute`, tag 0x31) plus a signing-time attribute (RFC 5652
/// §11.3), DER-sorted: what a plain CMS signer such as OpenSSL writes.
fn with_signing_time(signed_attrs: &[u8]) -> Vec<u8> {
    let signing_time_oid = [
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05,
    ];
    let utc = tlv(0x17, b"261010120000Z");
    let attribute = tlv(
        0x30,
        &[signing_time_oid.as_slice(), &tlv(0x31, &utc)].concat(),
    );
    let mut attributes = children(signed_attrs);
    attributes.push(attribute);
    attributes.sort();
    tlv(0x31, &attributes.concat())
}

#[test]
fn finish_rejects_signature_by_other_key() {
    // RSA: another 2048-bit key.
    let p = prepared(&syntax::minimal(), &rsa2048());
    let other = pem_signer("expired.key.pem", "expired.pem");
    let value = other.sign(p.digest_algorithm(), p.to_be_signed()).unwrap();
    let err = p.clone().finish(&value).unwrap_err();
    assert!(matches!(err, Error::SignatureInvalid(_)), "{err:?}");
    // ECDSA: another P-256 key.
    let p = prepared(&syntax::minimal(), &p256());
    let long_serial =
        |name: &str| std::fs::read_to_string(repo().join("fixtures/sign").join(name)).unwrap();
    let other = LocalSigner::from_pem(
        &long_serial("long-serial.key.pem"),
        &long_serial("long-serial.pem"),
        None,
    )
    .unwrap();
    let value = other.sign(p.digest_algorithm(), p.to_be_signed()).unwrap();
    assert_eq!(
        p.clone().finish(&value).unwrap_err().code(),
        ErrorCode::SignatureInvalid
    );
    // The right key over other bytes, a truncated value, garbage.
    let signer = p256();
    let wrong_bytes = signer.sign(p.digest_algorithm(), b"other bytes").unwrap();
    for value in [wrong_bytes, vec![0x30, 0x00], vec![0u8; 64], Vec::new()] {
        assert_eq!(
            p.clone().finish(&value).unwrap_err().code(),
            ErrorCode::SignatureInvalid
        );
    }
    // The right value works.
    let value = signer.sign(p.digest_algorithm(), p.to_be_signed()).unwrap();
    let signed = p.finish(&value).unwrap();
    assert!(verify(&signed)[0].is_valid());
}

#[test]
fn finish_accepts_p1363() {
    for signer in [p256(), p384()] {
        let p = prepared(&syntax::minimal(), &signer);
        let der = signer.sign(p.digest_algorithm(), p.to_be_signed()).unwrap();
        let half = signer.key_kind().p1363_len().unwrap() / 2;
        // DER -> r || s.
        let ints = children(&der);
        let mut p1363 = Vec::new();
        for int in &ints {
            let value: Vec<u8> = int[2..].iter().copied().skip_while(|&b| b == 0).collect();
            p1363.extend(std::iter::repeat_n(0, half - value.len()));
            p1363.extend(value);
        }
        assert_eq!(p1363.len(), 2 * half);
        let from_der = p.clone().finish(&der).unwrap();
        let from_p1363 = p.finish(&p1363).unwrap();
        assert_eq!(from_der, from_p1363, "{:?}", signer.key_kind());
        let report = &verify(&from_p1363)[0];
        assert!(report.is_valid(), "{}", summary(report));
    }
}

#[test]
fn embed_cms_matches_finish() {
    let signer = rsa2048();
    let p = prepared(&syntax::minimal(), &signer);
    let cms_der = cms_over(p.to_be_signed(), &signer, signer.certificate_chain(), &p);
    let value = signer.sign(p.digest_algorithm(), p.to_be_signed()).unwrap();
    let finished = p.clone().finish(&value).unwrap();
    // Zero bytes after the CMS are accepted (padding), others are not.
    let mut padded = cms_der.clone();
    padded.extend([0, 0, 0]);
    assert_eq!(p.clone().embed_cms(&padded).unwrap(), finished);
    let mut trailing = cms_der.clone();
    trailing.push(1);
    assert_eq!(
        p.clone().embed_cms(&trailing).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        p.clone().embed_cms(b"garbage").unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
    assert_eq!(p.embed_cms(&cms_der).unwrap(), finished);
}

#[test]
fn embed_cms_digest_mismatch_rejected() {
    let signer = p256();
    let a = prepared(&syntax::minimal(), &signer);
    let b = prepared(&syntax::xref_stream(), &signer);
    assert_ne!(a.document_digest(), b.document_digest());
    // A good CMS for document B, embedded into document A.
    let for_b = cms_over(b.to_be_signed(), &signer, signer.certificate_chain(), &b);
    let err = a.clone().embed_cms(&for_b).unwrap_err();
    assert!(matches!(err, Error::SignatureInvalid(_)), "{err:?}");
    assert!(
        err.to_string().contains("CMS signs different bytes"),
        "{err}"
    );
    // B itself accepts it.
    let signed = b.embed_cms(&for_b).unwrap();
    assert!(verify(&signed)[0].is_valid());
}

#[test]
fn embed_cms_overflow_reports_needed() {
    let signer = rsa2048();
    // Prepare for the signer certificate alone, with exactly the size that chain needs.
    let alone = vec![signer.certificate_chain()[0].clone()];
    let request = |reserve| {
        PrepareRequest::new(alone.clone(), signer.algorithm(), time())
            .with_options(SignatureOptions::new(time()).with_contents_reserve(Some(reserve)))
    };
    let doc = open(&syntax::minimal());
    let needed = match prepare(&doc, &request(1)) {
        Err(Error::PlaceholderTooSmall { needed, .. }) => needed,
        other => panic!("{other:?}"),
    };
    let p = prepare(&doc, &request(needed)).unwrap();
    assert_eq!(p.contents_capacity(), needed);
    // A remote service returns a CMS with the whole chain: larger than the reserve.
    let bigger = cms_over(p.to_be_signed(), &signer, signer.certificate_chain(), &p);
    assert!(bigger.len() > needed);
    match p.clone().embed_cms(&bigger) {
        Err(Error::PlaceholderTooSmall {
            needed: n,
            reserved,
        }) => {
            assert_eq!(n, bigger.len());
            assert_eq!(reserved, needed);
        }
        other => panic!("{other:?}"),
    }
    // With the chain it was prepared for, it fits.
    let fitting = cms_over(p.to_be_signed(), &signer, &alone, &p);
    assert!(fitting.len() <= needed);
    let signed = p.embed_cms(&fitting).unwrap();
    let report = &verify(&signed)[0];
    assert!(report.is_valid(), "{}", summary(report));
    assert_eq!(report.chain.len(), 1);
}

#[test]
fn embed_cms_signing_time_rejected_for_etsi() {
    let signer = p256();
    let p = prepared(&syntax::minimal(), &signer);
    let attrs = with_signing_time(p.to_be_signed());
    let cms_der = cms_over(&attrs, &signer, signer.certificate_chain(), &p);
    let err = p.embed_cms(&cms_der).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    assert!(err.to_string().contains("signing-time"), "{err}");

    // The same kind of CMS is fine for adbe.pkcs7.detached, which is not PAdES.
    let p = prepared_with(
        &syntax::minimal(),
        &signer,
        SignatureOptions::new(time()).with_sub_filter(SubFilter::AdbePkcs7Detached),
    );
    let attrs = with_signing_time(p.to_be_signed());
    let cms_der = cms_over(&attrs, &signer, signer.certificate_chain(), &p);
    let signed = p.embed_cms(&cms_der).unwrap();
    let report = &verify(&signed)[0];
    assert!(report.is_valid(), "{}", summary(report));
    assert_eq!(report.coverage, Coverage::EntireFile);
    assert_ne!(report.pades_level, Some(PadesLevel::BB));
}

#[cfg(feature = "serde")]
#[test]
fn prepared_signature_serde_roundtrip_then_finish() {
    let signer = p384();
    let p = prepared(&syntax::objstm(), &signer);
    let json = serde_json::to_string(&p).unwrap();
    let back: PreparedSignature = serde_json::from_str(&json).unwrap();
    assert_eq!(back, p);
    let value = signer.sign(p.digest_algorithm(), p.to_be_signed()).unwrap();
    assert_eq!(back.finish(&value).unwrap(), p.finish(&value).unwrap());
}

#[test]
fn prepared_signature_bytes_roundtrip_with_real_certificates() {
    let signer = rsa3072();
    let p = prepared(&syntax::hybrid(), &signer);
    let back = PreparedSignature::from_bytes(&p.to_bytes()).unwrap();
    assert_eq!(back, p);
    // A stored signature whose file was changed is refused when loaded.
    let mut bytes = p.to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(
        PreparedSignature::from_bytes(&bytes).unwrap_err().code(),
        ErrorCode::InvalidArgument
    );
}

/// The offset of the SubFilter code in [`PreparedSignature::to_bytes`]: after `FXPS` and the
/// version.
const SUB_FILTER_CODE_AT: usize = 8;

#[test]
fn prepared_signature_tamper_rejected_with_real_certificates() {
    // QA1 finding 1 / QA2 finding 7: every persisted field is cross-checked when loading.
    let signer = rsa2048();
    let p = prepared(&syntax::minimal(), &signer);
    let bytes = p.to_bytes();
    let load_err = |bytes: &[u8]| PreparedSignature::from_bytes(bytes).unwrap_err();

    // (a) The SubFilter code: the file still says /ETSI.CAdES.detached.
    assert_eq!(bytes[SUB_FILTER_CODE_AT], 0);
    let mut relabelled = bytes.clone();
    relabelled[SUB_FILTER_CODE_AT] = 1;
    let err = load_err(&relabelled);
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    assert!(err.to_string().contains("/SubFilter"), "{err}");

    // (b) One bit of the signer certificate away from its key (a subject character): the key
    // still parses, but the signed attributes name another certificate's hash.
    let cert = &signer.certificate_chain()[0];
    let at_in_cert = cert
        .windows(b"Folioxide Test Signer".len())
        .position(|w| w == b"Folioxide Test Signer")
        .unwrap();
    let cert_at = bytes
        .windows(cert.len())
        .position(|w| w == &cert[..])
        .unwrap();
    let mut flipped = bytes.clone();
    flipped[cert_at + at_in_cert] ^= 0x20;
    let err = load_err(&flipped);
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    assert!(err.to_string().contains("signed attributes"), "{err}");

    // (c) A bit of the signed attributes outside the message digest (the content-type OID).
    let attrs = p.to_be_signed();
    let attrs_at = bytes.windows(attrs.len()).position(|w| w == attrs).unwrap();
    let id_data = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
    let in_attrs = attrs.windows(9).position(|w| w == id_data).unwrap();
    let mut content_type = bytes.clone();
    content_type[attrs_at + in_attrs + 8] ^= 0x02;
    assert_eq!(load_err(&content_type).code(), ErrorCode::InvalidArgument);

    // A sweep of single-bit flips over the whole stored form outside the file: every one is
    // refused. The intermediate certificates are the exception: nothing the signature covers
    // names them (a verifier finds a damaged one when it builds the certification path, so the
    // signer is then not trusted), so their bytes are not swept.
    let pdf_at = bytes.len() - p.pdf().len();
    let intermediates: Vec<std::ops::Range<usize>> = signer.certificate_chain()[1..]
        .iter()
        .map(|cert| {
            let at = bytes
                .windows(cert.len())
                .position(|w| w == &cert[..])
                .unwrap();
            at..at + cert.len()
        })
        .collect();
    for at in (0..pdf_at).filter(|at| !intermediates.iter().any(|r| r.contains(at))) {
        let mut tampered = bytes.clone();
        tampered[at] ^= 0x01;
        if let Ok(loaded) = PreparedSignature::from_bytes(&tampered) {
            panic!("a flip at {at} was accepted: {loaded:?}");
        }
    }
}

#[test]
fn prepared_signature_with_extra_signed_attribute_rejected() {
    // A stored state whose signed attributes carry a signing-time (as a tampered blob would, for
    // a KMS that signs whatever toBeSigned is): the signed attributes are not the ones prepare
    // builds, so loading refuses it before anything is signed.
    let signer = p256();
    let p = prepared(&syntax::minimal(), &signer);
    let attrs = p.to_be_signed().to_vec();
    let extra = with_signing_time(&attrs);
    assert_ne!(extra.len(), attrs.len());
    let bytes = p.to_bytes();
    let at = bytes.windows(attrs.len()).position(|w| w == attrs).unwrap();
    // `bytes32`: a big-endian u32 length, then the bytes.
    let mut tampered = bytes[..at - 4].to_vec();
    tampered.extend_from_slice(&(extra.len() as u32).to_be_bytes());
    tampered.extend_from_slice(&extra);
    tampered.extend_from_slice(&bytes[at + attrs.len()..]);
    let err = PreparedSignature::from_bytes(&tampered).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    assert!(err.to_string().contains("signed attributes"), "{err}");
}

/// `der` (a DER ContentInfo) with its outer SEQUENCE in the BER indefinite-length form, the same
/// total length when the outer header used two length octets (`30 82 LL LL` becomes `30 80` and
/// the end-of-contents octets `00 00` are appended).
fn outer_indefinite(der: &[u8]) -> Vec<u8> {
    assert_eq!(&der[..2], &[0x30, 0x82]);
    let mut ber = vec![0x30, 0x80];
    ber.extend_from_slice(&der[4..]);
    ber.extend_from_slice(&[0, 0]);
    assert_eq!(ber.len(), der.len());
    ber
}

#[test]
fn embed_cms_ber_rejected_for_etsi() {
    // Expert finding 14: EN 319 142-1 requires a DER SignedData. The same CMS with an
    // indefinite-length outer element is BER: refused for ETSI.CAdES.detached, accepted (and
    // never B-B) for adbe.pkcs7.detached.
    let signer = rsa2048();
    let p = prepared(&syntax::minimal(), &signer);
    let der = cms_over(p.to_be_signed(), &signer, signer.certificate_chain(), &p);
    let ber = outer_indefinite(&der);
    assert!(cms::parse(&ber).is_ok(), "the parser reads BER");
    let err = p.clone().embed_cms(&ber).unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument, "{err}");
    assert!(err.to_string().contains("DER"), "{err}");
    // The DER form of the same CMS is B-B.
    let signed = p.embed_cms(&der).unwrap();
    assert_eq!(verify(&signed)[0].pades_level, Some(PadesLevel::BB));

    let adbe = prepared_with(
        &syntax::minimal(),
        &signer,
        SignatureOptions::new(time()).with_sub_filter(SubFilter::AdbePkcs7Detached),
    );
    let der = cms_over(
        adbe.to_be_signed(),
        &signer,
        signer.certificate_chain(),
        &adbe,
    );
    let signed = adbe.embed_cms(&outer_indefinite(&der)).unwrap();
    let report = &verify(&signed)[0];
    assert!(report.is_valid(), "{}", summary(report));
    assert_eq!(report.pades_level, None);
}

#[test]
fn verify_ber_cms_is_not_baseline_b() {
    // V8: a CMS labelled ETSI.CAdES.detached that is valid but BER is not PAdES B-B. The BER
    // form is written over our own DER CMS, in place (same length).
    let signer = rsa2048();
    let signed = sign_default(&syntax::minimal(), &signer);
    let report = &verify(&signed)[0];
    assert_eq!(report.pades_level, Some(PadesLevel::BB));
    let range = report.byte_range.clone().unwrap();
    let (a, b) = (range[1] as usize, range[2] as usize);
    let hex = std::str::from_utf8(&signed[a + 1..b - 1])
        .unwrap()
        .to_owned();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let len = 4 + (((bytes[2] as usize) << 8) | bytes[3] as usize);
    let ber = outer_indefinite(&bytes[..len]);
    let mut rewritten = signed.clone();
    let digits: String = ber.iter().map(|b| format!("{b:02X}")).collect();
    rewritten[a + 1..a + 1 + digits.len()].copy_from_slice(digits.as_bytes());
    let report = &verify(&rewritten)[0];
    assert!(
        report.intact && report.signature_valid,
        "{}",
        summary(report)
    );
    assert_eq!(report.pades_level, None, "BER is not B-B");
}

/// `try_finish` and `try_embed_cms` give the prepared signature back, unchanged, with every
/// kind of refusal, and a corrected value then finishes the same file `finish` and
/// `embed_cms` produce.
#[test]
fn try_finish_and_try_embed_cms_give_the_prepared_signature_back() {
    let signer = p256();
    let original = prepared(&syntax::minimal(), &signer);
    let good = signer
        .sign(original.digest_algorithm(), original.to_be_signed())
        .unwrap();
    let expected = original.clone().finish(&good).unwrap();

    let other_key = pem_signer("signer-p384.key.pem", "signer-p384.pem");
    let refused_values = [
        signer
            .sign(original.digest_algorithm(), b"other bytes")
            .unwrap(),
        other_key
            .sign(original.digest_algorithm(), original.to_be_signed())
            .unwrap(),
        vec![0x30, 0x00],
        Vec::new(),
    ];
    let mut p = original.clone();
    for value in &refused_values {
        let refused = p.try_finish(value).unwrap_err();
        assert_eq!(refused.error().code(), ErrorCode::SignatureInvalid);
        assert_eq!(refused.to_string(), refused.error().to_string());
        assert!(std::error::Error::source(&refused).is_some());
        let (_, back) = refused.into_parts();
        assert_eq!(back, original, "the prepared signature is unchanged");
        p = back;
    }
    assert_eq!(p.try_finish(&good).unwrap(), expected);

    // embed_cms: other bytes, garbage, and a CMS larger than the reserve.
    let b = prepared(&syntax::xref_stream(), &signer);
    let for_b = cms_over(b.to_be_signed(), &signer, signer.certificate_chain(), &b);
    let fitting = cms_over(
        original.to_be_signed(),
        &signer,
        signer.certificate_chain(),
        &original,
    );
    // A CMS that carries the chain several times outgrows the reserve.
    let mut chain = signer.certificate_chain().to_vec();
    while cms_over(original.to_be_signed(), &signer, &chain, &original).len()
        <= original.contents_capacity()
    {
        chain.extend(signer.certificate_chain().iter().cloned());
    }
    let oversized = cms_over(original.to_be_signed(), &signer, &chain, &original);
    let mut p = original.clone();
    for (cms_der, code) in [
        (for_b, ErrorCode::SignatureInvalid),
        (b"garbage".to_vec(), ErrorCode::InvalidArgument),
        (oversized, ErrorCode::SignaturePlaceholderTooSmall),
    ] {
        let refused = p.try_embed_cms(&cms_der).unwrap_err();
        assert_eq!(refused.error().code(), code, "{refused}");
        let (_, back) = refused.into_parts();
        assert_eq!(back, original);
        p = back;
    }
    assert_eq!(p.clone().try_embed_cms(&fitting).unwrap(), expected);
    // `finish` and `embed_cms` report the same error as the `try_` forms.
    let err = original.clone().embed_cms(b"garbage").unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    let err: Error = p.try_finish(&[]).unwrap_err().into();
    assert_eq!(err.code(), ErrorCode::SignatureInvalid);
}
