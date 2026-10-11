#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! One-step and two-phase signing with real keys (M3 brief §6.2 "sign"): every key type and
//! digest, the external flow, the reserve retry, sequential signatures, every syntax fixture,
//! pending edits, the refusals and the output properties.

mod sign_support;

use folioxide_model::{Document, InfoUpdate};
use folioxide_sign::Error;
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::field::{FieldSpec, SubFilter};
use folioxide_sign::placeholder::check_signable;
use folioxide_sign::prepare::{PrepareRequest, PreparedSignature, SignatureOptions, prepare};
use folioxide_sign::report::{
    Coverage, ModificationLevel, PadesLevel, SignatureKind, SignatureReport,
};
use folioxide_sign::sign::{SignRequest, sign};
use folioxide_sign::signer::{LocalSigner, Signer};
use folioxide_syntax::{ErrorCode, OpenOptions};
use folioxide_testkit::fixtures::{id_array, syntax};
use folioxide_testkit::{PdfBuilder, XrefOpts};
use sign_support::*;

/// The checks every good single signature passes.
fn assert_good(report: &SignatureReport, field: &str) {
    assert!(report.is_valid(), "{}", summary(report));
    assert_eq!(report.field_name.as_deref(), Some(field));
    assert!(report.byte_range_ok && report.intact && report.signature_valid);
    assert_eq!(
        report.pades_level,
        Some(PadesLevel::BB),
        "{}",
        summary(report)
    );
    assert_eq!(report.sub_filter.as_deref(), Some("ETSI.CAdES.detached"));
    assert_eq!(report.claimed_time.as_deref(), Some("2026-10-10T12:00:00Z"));
    assert!(report.signer.is_some());
    assert!(report.trusted.is_some());
    if trust_implemented() {
        assert_eq!(report.trusted, Some(true), "{:?}", report.warnings);
    }
}

/// Signs `minimal` with `signer` and `options`, checks the single report and returns it.
fn sign_single(signer: &LocalSigner, options: SignatureOptions) -> SignatureReport {
    let source = syntax::minimal();
    let signed = sign_with(&source, signer, options);
    assert!(signed.starts_with(&source));
    let reports = verify(&signed);
    assert_eq!(reports.len(), 1);
    let report = reports.into_iter().next().unwrap();
    assert_good(&report, "Signature1");
    assert_eq!(report.coverage, Coverage::EntireFile);
    assert_eq!(report.modification, ModificationLevel::None);
    assert!(report.changed_objects.is_empty());
    report
}

#[test]
fn sign_invisible_rsa2048() {
    let report = sign_single(&rsa2048(), SignatureOptions::new(time()));
    assert_eq!(report.digest_algorithm.as_deref(), Some("sha256"));
    assert_eq!(
        report.signature_algorithm.as_deref(),
        Some("sha256WithRSAEncryption")
    );
    assert_eq!(
        report.signer.as_ref().unwrap().subject,
        "CN=Folioxide Test Signer RSA-2048,OU=TEST ONLY - DO NOT TRUST,O=Folioxide Test PKI"
    );
    // The p12 carries signer, intermediate and root.
    assert_eq!(report.chain.len(), 3);
}

#[test]
fn sign_invisible_p256() {
    let report = sign_single(&p256(), SignatureOptions::new(time()));
    assert_eq!(report.digest_algorithm.as_deref(), Some("sha256"));
    assert_eq!(
        report.signature_algorithm.as_deref(),
        Some("ecdsa-with-SHA256")
    );
    assert_eq!(
        report.signer.as_ref().unwrap().key.curve.as_deref(),
        Some("P-256")
    );
}

#[test]
fn sign_invisible_p384_sha384() {
    let report = sign_single(&p384(), SignatureOptions::new(time()));
    assert_eq!(report.digest_algorithm.as_deref(), Some("sha384"));
    assert_eq!(
        report.signature_algorithm.as_deref(),
        Some("ecdsa-with-SHA384")
    );
}

#[test]
fn sign_rsa3072_sha512() {
    let options = SignatureOptions::new(time()).with_digest(Some(DigestAlgorithm::Sha512));
    let report = sign_single(&rsa3072(), options);
    assert_eq!(report.digest_algorithm.as_deref(), Some("sha512"));
    assert_eq!(
        report.signature_algorithm.as_deref(),
        Some("sha512WithRSAEncryption")
    );
    assert_eq!(report.signer.as_ref().unwrap().key.bits, 3072);
}

#[test]
fn sign_text_entries_and_adbe_sub_filter() {
    let options = SignatureOptions::new(time())
        .with_reason(Some("Genehmigt \u{2713}".into()))
        .with_location(Some("Z\u{fc}rich".into()))
        .with_name(Some("Test Signer".into()))
        .with_contact_info(Some("signer@example.test".into()));
    let report = sign_single(&p256(), options);
    assert_eq!(report.reason.as_deref(), Some("Genehmigt \u{2713}"));
    assert_eq!(report.location.as_deref(), Some("Z\u{fc}rich"));
    assert_eq!(report.name.as_deref(), Some("Test Signer"));
    assert_eq!(report.contact_info.as_deref(), Some("signer@example.test"));

    let options = SignatureOptions::new(time()).with_sub_filter(SubFilter::AdbePkcs7Detached);
    let signed = sign_with(&syntax::minimal(), &rsa2048(), options);
    let report = &verify(&signed)[0];
    assert!(report.is_valid(), "{}", summary(report));
    assert_eq!(report.sub_filter.as_deref(), Some("adbe.pkcs7.detached"));
    assert_eq!(report.pades_level, None, "B-B needs ETSI.CAdES.detached");
}

/// IEEE P1363 `r || s` of a DER `ECDSA-Sig-Value`, each half `half` bytes.
fn der_to_p1363(der: &[u8], half: usize) -> Vec<u8> {
    assert_eq!(der[0], 0x30);
    let (mut pos, end) = if der[1] < 0x80 {
        (2, 2 + der[1] as usize)
    } else {
        (3, 3 + der[2] as usize)
    };
    assert_eq!(end, der.len());
    let mut out = Vec::new();
    for _ in 0..2 {
        assert_eq!(der[pos], 0x02);
        let len = der[pos + 1] as usize;
        let int = &der[pos + 2..pos + 2 + len];
        let int: Vec<u8> = int.iter().copied().skip_while(|&b| b == 0).collect();
        out.extend(std::iter::repeat_n(0, half - int.len()));
        out.extend(int);
        pos += 2 + len;
    }
    out
}

#[test]
fn external_two_phase_matches_local() {
    for (signer, source) in [
        (rsa2048(), syntax::minimal()),
        (p256(), syntax::xref_stream()),
        (p384(), syntax::hybrid()),
    ] {
        let local = sign(&open(&source), &SignRequest::new(&signer, time())).unwrap();

        // The two-phase flow, as an HSM or KMS adapter drives it.
        let request = PrepareRequest::new(
            signer.certificate_chain().to_vec(),
            signer.algorithm(),
            time(),
        );
        let prepared = prepare(&open(&source), &request).unwrap();
        let value = signer
            .sign(prepared.digest_algorithm(), prepared.to_be_signed())
            .unwrap();
        // Persisted between the phases.
        let stored = prepared.to_bytes();
        let restored = PreparedSignature::from_bytes(&stored).unwrap();
        assert_eq!(restored, prepared);
        let external = restored.finish(&value).unwrap();
        assert_eq!(external, local, "{:?}", signer.key_kind());

        // ECDSA values in IEEE P1363 form give the same bytes (normalised to minimal DER).
        if let Some(len) = signer.key_kind().p1363_len() {
            let p1363 = der_to_p1363(&value, len / 2);
            assert_eq!(p1363.len(), len);
            assert_eq!(prepared.clone().finish(&p1363).unwrap(), local);
        }
        // The digest forms are what "sign digest" and raw RSA interfaces need.
        let digest = prepared.digest_algorithm();
        assert_eq!(
            prepared.to_be_signed_digest(),
            digest.digest(&[prepared.to_be_signed()])
        );
        assert!(
            prepared
                .to_be_signed_digest_info()
                .ends_with(&prepared.to_be_signed_digest())
        );
    }
}

#[test]
fn placeholder_overflow_retries() {
    let signer = rsa2048();
    let doc = open(&syntax::minimal());
    let options = SignatureOptions::new(time()).with_contents_reserve(Some(100));
    // prepare alone refuses, naming the size needed ...
    let request = PrepareRequest::new(
        signer.certificate_chain().to_vec(),
        signer.algorithm(),
        time(),
    )
    .with_options(options.clone());
    let needed = match prepare(&doc, &request) {
        Err(Error::PlaceholderTooSmall { needed, reserved }) => {
            assert_eq!(reserved, 100);
            needed
        }
        other => panic!("expected PlaceholderTooSmall, got {other:?}"),
    };
    assert!(needed > 100);
    // ... and sign retries once with exactly that size.
    let signed = sign(
        &doc,
        &SignRequest::new(&signer, time()).with_options(options),
    )
    .unwrap();
    let report = &verify(&signed)[0];
    assert!(report.is_valid(), "{}", summary(report));
    let range = report.byte_range.as_ref().unwrap();
    let digits = (range[2] - range[1] - 2) as usize;
    assert_eq!(digits, 2 * needed, "the reserve is exactly the size needed");
    // The retry is only for an explicit reserve: the default is always large enough.
    let default = sign(&doc, &SignRequest::new(&signer, time())).unwrap();
    let default_range = verify(&default)[0].byte_range.clone().unwrap();
    assert!(default_range[2] - default_range[1] - 2 >= 2 * 8192);
}

#[test]
fn sequential_two_signatures() {
    let first = sign_default(&syntax::minimal(), &rsa2048());
    let second = sign_default(&first, &p256());
    assert!(second.starts_with(&first));
    let reports = verify(&second);
    assert_eq!(reports.len(), 2);
    let (one, two) = (&reports[0], &reports[1]);
    assert_good(one, "Signature1");
    assert_good(two, "Signature2");
    assert_eq!(one.coverage, Coverage::EntireRevision);
    assert_eq!(one.signed_revision, Some(1));
    assert_eq!(
        one.modification,
        ModificationLevel::FormFilling,
        "{:?}",
        one.warnings
    );
    assert!(!one.changed_objects.is_empty());
    assert_eq!(two.coverage, Coverage::EntireFile);
    assert_eq!(two.signed_revision, Some(2));
    assert_eq!(two.modification, ModificationLevel::None);
}

#[test]
fn sequential_three_signatures_mixed() {
    for source in [syntax::xref_stream(), syntax::objstm(), syntax::hybrid()] {
        let one = sign_default(&source, &rsa2048());
        let two = sign_with(
            &one,
            &p384(),
            SignatureOptions::new(time())
                .with_field(FieldSpec::new().with_name(Some("Approval".into()))),
        );
        let three = sign_with(
            &two,
            &rsa3072(),
            SignatureOptions::new(time()).with_digest(Some(DigestAlgorithm::Sha512)),
        );
        let reports = verify(&three);
        let names: Vec<_> = reports
            .iter()
            .map(|r| r.field_name.clone().unwrap())
            .collect();
        assert_eq!(names, ["Signature1", "Approval", "Signature2"]);
        for report in &reports[..2] {
            assert_good(report, report.field_name.as_deref().unwrap());
            assert_eq!(report.coverage, Coverage::EntireRevision);
            assert_eq!(
                report.modification,
                ModificationLevel::FormFilling,
                "{:?}",
                report.warnings
            );
        }
        assert_good(&reports[2], "Signature2");
        assert_eq!(reports[2].coverage, Coverage::EntireFile);
        assert_eq!(reports[2].digest_algorithm.as_deref(), Some("sha512"));
    }
}

#[test]
fn sign_after_pyhanko_signature() {
    let mut signed_count = 0;
    for (name, source) in pyhanko_fixtures() {
        let doc = open(&source);
        if check_signable(&doc).is_err() {
            // The certified P=1 document; sign_refuses_certified_p1 covers it.
            assert_eq!(name, "pyhanko-certified-p1.pdf");
            continue;
        }
        let before = verify(&source).len();
        let signed = sign_default(&source, &p256());
        let reports = verify(&signed);
        assert_eq!(reports.len(), before + 1, "{name}");
        for report in &reports[..before] {
            // A document timestamp is listed, not verified, in M3.
            let verified = report.kind == SignatureKind::DocTimeStamp || report.signature_valid;
            assert!(report.intact && verified, "{name}: {}", summary(report));
            assert_eq!(report.coverage, Coverage::EntireRevision, "{name}");
            assert_eq!(
                report.modification,
                ModificationLevel::FormFilling,
                "{name}: {:?}",
                report.warnings
            );
        }
        let ours = reports.last().unwrap();
        assert!(ours.is_valid(), "{name}: {}", summary(ours));
        assert_eq!(ours.coverage, Coverage::EntireFile);
        signed_count += 1;
    }
    assert!(signed_count >= 6, "{signed_count} pyHanko fixtures signed");
}

#[test]
fn sign_every_syntax_fixture() {
    let signer = p256();
    let mut signed_count = 0;
    for (name, source) in syntax::all() {
        let Ok(doc) = Document::open(source.clone(), &OpenOptions::default()) else {
            continue; // encrypted fixtures do not open in M3
        };
        let result = sign(&doc, &SignRequest::new(&signer, time()));
        match check_signable(&doc) {
            Err(refusal) => {
                let err = result.expect_err(name);
                assert_eq!(err.code(), refusal.code(), "{name}: {err}");
            }
            Ok(()) => {
                let Ok(signed) = result else {
                    // A document the field placement cannot handle (no pages).
                    assert_eq!(doc.page_count().unwrap_or(0), 0, "{name}");
                    continue;
                };
                assert!(signed.starts_with(&source), "{name}");
                let reports = verify(&signed);
                let ours = reports.last().expect(name);
                assert!(ours.is_valid(), "{name}: {}", summary(ours));
                assert_eq!(ours.coverage, Coverage::EntireFile, "{name}");
                assert_eq!(ours.modification, ModificationLevel::None, "{name}");
                signed_count += 1;
            }
        }
    }
    assert!(
        signed_count >= 8,
        "only {signed_count} fixtures were signed"
    );
}

#[test]
fn sign_with_pending_edits_same_revision() {
    let source = syntax::minimal();
    let mut doc = open(&source);
    let mut update = InfoUpdate::default();
    update.title = Some(Some("Pending title".into()));
    doc.set_info(&update).unwrap();
    let signed = sign(&doc, &SignRequest::new(&p256(), time())).unwrap();
    assert!(doc.is_modified(), "the document is not changed");
    let reopened = open(&signed);
    assert_eq!(
        reopened.info().unwrap().title.as_deref(),
        Some("Pending title")
    );
    assert_eq!(
        reopened.store().revisions().len(),
        open(&source).store().revisions().len() + 1,
        "the edit and the signature share one revision"
    );
    let report = &verify(&signed)[0];
    assert!(report.is_valid(), "{}", summary(report));
    assert_eq!(report.coverage, Coverage::EntireFile);
}

#[test]
fn sign_refuses_repaired_structure() {
    let (name, source) = syntax::all()
        .into_iter()
        .find(|(_, pdf)| {
            Document::open(pdf.clone(), &OpenOptions::default())
                .is_ok_and(|d| d.store().structure_repaired() && d.store().header_offset() == 0)
        })
        .expect("a repaired syntax fixture");
    let err = sign(&open(&source), &SignRequest::new(&p256(), time())).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported, "{name}: {err}");
    assert!(
        err.to_string().contains("full save required"),
        "{name}: {err}"
    );
}

#[test]
fn sign_refuses_junk_before_header() {
    let (name, source) = syntax::all()
        .into_iter()
        .find(|(_, pdf)| {
            Document::open(pdf.clone(), &OpenOptions::default())
                .is_ok_and(|d| d.store().header_offset() > 0)
        })
        .expect("a fixture with bytes before %PDF-");
    let err = sign(&open(&source), &SignRequest::new(&p256(), time())).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Unsupported, "{name}: {err}");
    assert!(
        err.to_string().contains("save a full copy first"),
        "{name}: {err}"
    );
}

#[test]
fn sign_refuses_certified_p1() {
    let certified = |p: &str| {
        let mut b = PdfBuilder::new();
        b.header("1.7");
        b.obj(
            1,
            0,
            "<< /Type /Catalog /Pages 2 0 R /Perms << /DocMDP 5 0 R >> >>",
        );
        b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        b.obj(
            3,
            0,
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
        );
        b.obj(4, 0, "<< >>");
        b.obj(
            5,
            0,
            format!(
                "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached \
                 /ByteRange [0 1 2 3] /Contents <00> /Reference [<< /Type /SigRef \
                 /TransformMethod /DocMDP /TransformParams << /Type /TransformParams {p} \
                 /V /1.2 >> >>] >>"
            ),
        );
        b.xref_table(XrefOpts::default());
        let trailer = format!(
            "/Size {} /Root 1 0 R /ID {}",
            b.size(),
            id_array("certified")
        );
        b.trailer(trailer).startxref(None).eof();
        b.build()
    };
    let err = sign(
        &open(&certified("/P 1")),
        &SignRequest::new(&p256(), time()),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::DocMdpForbids, "{err}");
    // P = 2 allows an approval signature.
    let signed = sign(
        &open(&certified("/P 2")),
        &SignRequest::new(&p256(), time()),
    )
    .unwrap();
    let ours = verify(&signed)
        .into_iter()
        .find(|r| r.field_name.is_some())
        .unwrap();
    assert!(ours.is_valid(), "{}", summary(&ours));

    // The pyHanko-certified P=1 fixture is refused too, and only that one.
    let mut refused = Vec::new();
    for (name, source) in pyhanko_fixtures() {
        let doc = open(&source);
        if let Err(Error::DocMdpForbids(_)) = check_signable(&doc) {
            let err = sign(&doc, &SignRequest::new(&p256(), time())).unwrap_err();
            assert_eq!(err.code(), ErrorCode::DocMdpForbids, "{name}");
            refused.push(name);
        }
    }
    assert_eq!(refused, ["pyhanko-certified-p1.pdf"]);
}

#[test]
fn sign_is_deterministic() {
    for signer in [rsa2048(), p256(), p384()] {
        let a = sign_default(&syntax::minimal(), &signer);
        let b = sign_default(&syntax::minimal(), &signer);
        assert_eq!(a, b, "{:?}", signer.key_kind());
    }
}

#[test]
fn signed_output_prefix_preserved() {
    for source in [
        syntax::minimal(),
        syntax::xref_stream(),
        syntax::hybrid(),
        syntax::objstm(),
        syntax::multi_revision(),
    ] {
        let signed = sign_default(&source, &rsa2048());
        assert!(signed.len() > source.len());
        assert_eq!(&signed[..source.len()], source.as_slice());
        // The update starts on its own line.
        let tail = &signed[source.len()..];
        assert!(source.ends_with(b"\n") || source.ends_with(b"\r") || tail.starts_with(b"\n"));
    }
}

#[test]
fn sign_refuses_a_signer_whose_key_is_not_its_certificate() {
    struct Mismatch(LocalSigner, LocalSigner);
    impl Signer for Mismatch {
        fn certificate_chain(&self) -> &[Vec<u8>] {
            self.0.certificate_chain()
        }
        fn algorithm(&self) -> folioxide_sign::algorithms::SignatureAlgorithm {
            self.0.algorithm()
        }
        fn key_kind(&self) -> folioxide_sign::algorithms::KeyKind {
            self.0.key_kind()
        }
        fn sign(&self, digest: DigestAlgorithm, tbs: &[u8]) -> folioxide_sign::Result<Vec<u8>> {
            self.1.sign(digest, tbs)
        }
    }
    // Same algorithm and size, another key: finish refuses the value.
    let other = pem_signer("expired.key.pem", "expired.pem");
    let err = sign(
        &open(&syntax::minimal()),
        &SignRequest::new(&Mismatch(rsa2048(), other), time()),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::SignatureInvalid, "{err}");
}
