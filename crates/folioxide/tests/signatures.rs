//! The facade's signature API (M3 brief §3.2 "Facade"): the re-exports, the default features
//! (`signatures` with `sys-rng`, and `pkcs12-legacy`) and the unified error, used the way an
//! application would, with the committed test PKI.
#![cfg(feature = "signatures")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;

use folioxide::sign::x509info::{UnixTime, build_trust};
use folioxide::{
    Coverage, DigestAlgorithm, Document, Error, ErrorCode, KeyKind, LocalSigner, ModificationLevel,
    OpenOptions, PdfDate, PrepareRequest, SignRequest, SignatureAlgorithm, SignatureOptions,
    Signer, VerifyOptions, certificates_from_pem, prepare, verify_bytes,
};

fn fixture(path: &str) -> Vec<u8> {
    let full = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(path);
    std::fs::read(&full).unwrap_or_else(|e| panic!("reading {}: {e}", full.display()))
}

fn signing_time() -> PdfDate {
    PdfDate::parse(b"D:20261010120000Z").unwrap()
}

/// Loads a signer the way an application does: errors are `folioxide::Error`.
fn load(p12: &str, password: &str) -> folioxide::Result<LocalSigner> {
    Ok(LocalSigner::from_pkcs12(&fixture(p12), password)?)
}

/// Prepares a signature on `minimal.pdf`, signs it with `signer` and checks the value.
fn prepare_and_sign(signer: &dyn Signer) -> folioxide::Result<()> {
    let doc = Document::open(fixture("syntax/minimal.pdf"), &OpenOptions::default())?;
    let request = PrepareRequest::new(
        signer.certificate_chain().to_vec(),
        signer.algorithm(),
        signing_time(),
    )
    .with_options(
        SignatureOptions::new(signing_time()).with_reason(Some("facade test".to_owned())),
    );
    let prepared = prepare(&doc, &request)?;
    let digest = prepared.digest_algorithm();
    let value = signer.sign(digest, prepared.to_be_signed())?;
    folioxide::sign::cms::verify_raw(
        &signer.certificate_chain()[0],
        signer.algorithm(),
        digest,
        prepared.to_be_signed(),
        &value,
    )?;
    assert!(prepared.contents_capacity() >= 8192);
    Ok(())
}

#[test]
fn ecdsa_signer_prepares_and_signs() {
    let signer = load("pki/signer-p256-modern.p12", "folioxide").unwrap();
    assert_eq!(signer.algorithm(), SignatureAlgorithm::Ecdsa);
    assert_eq!(signer.key_kind(), KeyKind::EcP256);
    prepare_and_sign(&signer).unwrap();
}

#[test]
fn rsa_signer_uses_the_default_rng() {
    // RSA signing blinds with the operating-system RNG: `signatures` turns on `sys-rng`, so no
    // `with_rng` is needed. The 3DES file loads because `pkcs12-legacy` is a default feature.
    for p12 in [
        "pki/signer-rsa2048-modern.p12",
        "pki/signer-rsa2048-3des.p12",
        "pki/signer-rsa2048-rc2-40.p12",
    ] {
        let signer = load(p12, "folioxide").unwrap();
        assert_eq!(signer.key_kind(), KeyKind::Rsa { bits: 2048 });
        prepare_and_sign(&signer).unwrap();
    }
}

#[test]
fn certificate_info_and_trust_through_the_facade() {
    let signer = load("pki/signer-p256-modern.p12", "folioxide").unwrap();
    let chain = signer.certificate_chain();
    let info: folioxide::CertificateInfo =
        folioxide::sign::x509info::certificate_info(&chain[0]).unwrap();
    assert_eq!(
        info.subject,
        "CN=Folioxide Test Signer P-256,OU=TEST ONLY - DO NOT TRUST,O=Folioxide Test PKI"
    );
    assert_eq!(
        info.key,
        folioxide::KeyDescription::new("ec", 256, Some("P-256"))
    );
    // The .p12 carries the intermediate and the root; the root is the anchor.
    let root = folioxide::sign::keys::certificates_from_pem(
        std::str::from_utf8(&fixture("pki/root.pem")).unwrap(),
    )
    .unwrap();
    let at = UnixTime::from_pdf_date(&signing_time());
    let trust = build_trust(&chain[0], chain, &root, at);
    assert!(trust.trusted, "{:?}", trust.reasons);
    assert_eq!(trust.path.len(), 3);
}

/// Appends an incremental update to `signed` that adds a **visible** signature field, still
/// unsigned, at the root of `/AcroForm /Fields` and on page 1: a widget whose appearance paints
/// over the whole page (QA2 finding: a new visible signature widget added after signing). The
/// edit goes through the syntax layer, as an attacker's tool would; applications do not need it.
fn with_visible_signature_field(signed: Vec<u8>) -> Vec<u8> {
    use folioxide::{Dict, Object};
    use folioxide_syntax::{Stream, StreamData};

    let mut doc = Document::open(signed, &OpenOptions::default()).unwrap();
    let page = doc.page_ids().unwrap()[0].0;
    let store = doc.store_mut();
    let full_page = || Object::Array([0, 0, 612, 792].into_iter().map(Object::Int).collect());

    let mut form = Dict::new();
    form.insert("Type", Object::name("XObject"));
    form.insert("Subtype", Object::name("Form"));
    form.insert("BBox", full_page());
    let paint = StreamData::Decoded(b"1 1 1 rg 0 0 612 792 re f".to_vec());
    let appearance = store
        .add(Object::Stream(Box::new(Stream::new(form, paint))))
        .unwrap();
    let mut normal = Dict::new();
    normal.insert("N", Object::Ref(appearance));
    let mut widget = Dict::new();
    widget.insert("Type", Object::name("Annot"));
    widget.insert("Subtype", Object::name("Widget"));
    widget.insert("FT", Object::name("Sig"));
    widget.insert("T", Object::literal_string("Overlay"));
    widget.insert("F", Object::Int(4));
    widget.insert("P", Object::Ref(page));
    widget.insert("Rect", full_page());
    widget.insert("AP", Object::Dict(normal));
    let widget = store.add(Object::Dict(widget)).unwrap();

    // Folioxide's signature gave the page a direct /Annots array and the catalog an indirect
    // /AcroForm with a direct /Fields array.
    let mut page_dict = store.resolve(page).unwrap().as_dict().unwrap().clone();
    let mut annots = page_dict
        .get(b"Annots")
        .unwrap()
        .as_array()
        .unwrap()
        .to_vec();
    annots.push(Object::Ref(widget));
    page_dict.insert("Annots", Object::Array(annots));
    store.set(page, Object::Dict(page_dict)).unwrap();
    let root = store.root_id().unwrap();
    let catalog = store.resolve(root).unwrap();
    let acroform = catalog.as_dict().unwrap().get_ref(b"AcroForm").unwrap();
    let mut form_dict = store.resolve(acroform).unwrap().as_dict().unwrap().clone();
    let mut fields = form_dict
        .get(b"Fields")
        .unwrap()
        .as_array()
        .unwrap()
        .to_vec();
    fields.push(Object::Ref(widget));
    form_dict.insert("Fields", Object::Array(fields));
    store.set(acroform, Object::Dict(form_dict)).unwrap();

    doc.save_incremental(&folioxide::IncrementalOptions::default())
        .unwrap()
}

#[test]
fn acceptance_gate_and_a_later_visible_signature_field() {
    // The gate the facade documents: `is_acceptable(FormFilling)` and trust. `FormFilling`
    // includes a visible signature field added after signing (pyHanko: FORM_FILLING too), whose
    // appearance can cover signed content; `LtaUpdates` is the strict choice.
    let signer = load("pki/signer-p256-modern.p12", "folioxide").unwrap();
    let doc = Document::open(fixture("syntax/minimal.pdf"), &OpenOptions::default()).unwrap();
    let signed = folioxide::sign(&doc, &SignRequest::new(&signer, signing_time())).unwrap();
    let root =
        certificates_from_pem(std::str::from_utf8(&fixture("pki/root.pem")).unwrap()).unwrap();
    let options = VerifyOptions::default()
        .with_trust_anchors_der(root)
        .with_validation_time(Some(signing_time()));

    let reports = verify_bytes(signed.clone(), &options).unwrap();
    assert_eq!(reports.len(), 1);
    assert!(reports[0].is_acceptable(ModificationLevel::None));
    assert_eq!(reports[0].trusted, Some(true));

    let overlaid = with_visible_signature_field(signed.clone());
    assert!(overlaid.starts_with(&signed));
    let reports = verify_bytes(overlaid, &options).unwrap();
    // The new field has no value, so it has no report of its own.
    assert_eq!(reports.len(), 1, "{reports:#?}");
    let report = &reports[0];
    assert!(report.is_valid(), "{report:#?}");
    assert_eq!(report.trusted, Some(true));
    assert_eq!(report.coverage, Coverage::EntireRevision);
    assert_eq!(
        report.modification,
        ModificationLevel::FormFilling,
        "{report:#?}"
    );
    assert!(report.is_acceptable(ModificationLevel::FormFilling));
    assert!(!report.is_acceptable(ModificationLevel::LtaUpdates));
}

#[test]
fn errors_are_one_type_with_stable_codes() {
    let password = "Secret-4711";
    let err = load("pki/signer-p256-modern.p12", password).unwrap_err();
    assert!(matches!(err, Error::Sign(_)), "{err:?}");
    assert_eq!(err.code(), ErrorCode::WrongPassword);
    assert!(!err.to_string().contains(password));
    assert!(!format!("{err:?}").contains(password));

    let err = load("syntax/minimal.pdf", "folioxide").unwrap_err();
    assert_eq!(err.code(), ErrorCode::KeyLoad);

    // A syntax error raised inside the signature layer is reported as a syntax error.
    let err: Error = folioxide::sign::Error::from(folioxide::SyntaxError::new(
        ErrorCode::Xref,
        "no cross-reference table",
    ))
    .into();
    assert!(matches!(err, Error::Syntax(_)));
    assert_eq!(err.code(), ErrorCode::Xref);

    // An invalid request: a chain whose certificate does not match the algorithm.
    let signer = load("pki/signer-p256-modern.p12", "folioxide").unwrap();
    let doc = Document::open(fixture("syntax/minimal.pdf"), &OpenOptions::default()).unwrap();
    let request = PrepareRequest::new(
        signer.certificate_chain().to_vec(),
        SignatureAlgorithm::RsaPkcs1v15,
        signing_time(),
    );
    let err: Error = prepare(&doc, &request).unwrap_err().into();
    assert_eq!(err.code(), ErrorCode::InvalidArgument);
    assert_eq!(
        folioxide::sign::algorithms::default_digest(KeyKind::EcP384),
        DigestAlgorithm::Sha384
    );
}
