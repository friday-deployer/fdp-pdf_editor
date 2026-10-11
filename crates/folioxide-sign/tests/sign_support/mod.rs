//! Shared helpers of the signing and verification integration tests (M3 WP3.2A): the test PKI
//! signers, a fixed signing time, signing and verifying shortcuts, and the pyHanko-signed
//! interop fixtures when they are present.

#![allow(dead_code)]

pub mod corpus;
pub mod oracle;

use std::path::{Path, PathBuf};

use folioxide_model::{Document, PdfDate};
use folioxide_sign::prepare::SignatureOptions;
use folioxide_sign::report::SignatureReport;
use folioxide_sign::sign::{SignRequest, sign};
use folioxide_sign::signer::{LocalSigner, Signer};
use folioxide_sign::verify_pdf::{VerifyOptions, verify_bytes};
use folioxide_sign::x509info::{UnixTime, build_trust};
use folioxide_syntax::OpenOptions;

/// The test PKI password (fixtures/pki/README.md).
pub const PASSWORD: &str = "folioxide";

/// The repository root.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A file of `fixtures/pki`.
pub fn pki(name: &str) -> PathBuf {
    repo().join("fixtures/pki").join(name)
}

/// The text of a file of `fixtures/pki`.
pub fn pki_text(name: &str) -> String {
    std::fs::read_to_string(pki(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// The signing time of every test signature.
pub fn time() -> PdfDate {
    PdfDate::parse(b"D:20261010120000Z").unwrap()
}

/// A PEM signer: `<stem>.key.pem` (or `key`) with `<stem>.pem` and the intermediate.
pub fn pem_signer(key: &str, cert: &str) -> LocalSigner {
    let certs = pki_text(cert) + &pki_text("intermediate.pem");
    LocalSigner::from_pem(&pki_text(key), &certs, None).unwrap_or_else(|e| panic!("{key}: {e}"))
}

/// RSA-2048 from the modern PKCS#12.
pub fn rsa2048() -> LocalSigner {
    p12("signer-rsa2048-modern.p12")
}

/// A PKCS#12 signer.
pub fn p12(name: &str) -> LocalSigner {
    let bytes = std::fs::read(pki(name)).unwrap();
    LocalSigner::from_pkcs12(&bytes, PASSWORD).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// RSA-3072 from PEM.
pub fn rsa3072() -> LocalSigner {
    pem_signer("signer-rsa3072.key.pem", "signer-rsa3072.pem")
}

/// P-256 from PEM (PKCS#8).
pub fn p256() -> LocalSigner {
    pem_signer("signer-p256.key.pem", "signer-p256.pem")
}

/// P-384 from PEM (PKCS#8).
pub fn p384() -> LocalSigner {
    pem_signer("signer-p384.key.pem", "signer-p384.pem")
}

/// Opens a document leniently.
pub fn open(bytes: &[u8]) -> Document {
    Document::open(bytes.to_vec(), &OpenOptions::default()).unwrap()
}

/// Signs `source` with `signer` and `options`.
pub fn sign_with(source: &[u8], signer: &dyn Signer, options: SignatureOptions) -> Vec<u8> {
    let doc = open(source);
    sign(
        &doc,
        &SignRequest::new(signer, time()).with_options(options),
    )
    .unwrap_or_else(|e| panic!("signing failed: {e}"))
}

/// Signs `source` with `signer` and the default options.
pub fn sign_default(source: &[u8], signer: &dyn Signer) -> Vec<u8> {
    sign_with(source, signer, SignatureOptions::new(time()))
}

/// The test PKI root as DER.
pub fn anchors() -> Vec<Vec<u8>> {
    folioxide_sign::keys::certificates_from_pem(&pki_text("root.pem")).unwrap()
}

/// Verifies with the test root as trust anchor, at the signing time.
pub fn verify(bytes: &[u8]) -> Vec<SignatureReport> {
    verify_bytes(
        bytes.to_vec(),
        &VerifyOptions::new()
            .with_trust_anchors_der(anchors())
            .with_validation_time(Some(time())),
    )
    .unwrap_or_else(|e| panic!("verify failed: {e}"))
}

/// Verifies without trust anchors.
pub fn verify_plain(bytes: &[u8]) -> Vec<SignatureReport> {
    verify_bytes(bytes.to_vec(), &VerifyOptions::default())
        .unwrap_or_else(|e| panic!("verify failed: {e}"))
}

/// Whether trust evaluation is implemented (WP3.2B): the stage-0 `build_trust` reports every
/// signer untrusted, so trust assertions only run once it validates the test PKI's good chain.
pub fn trust_implemented() -> bool {
    let signer = rsa2048();
    let chain = signer.certificate_chain().to_vec();
    let Some(leaf) = chain.first() else {
        return false;
    };
    build_trust(leaf, &chain, &anchors(), UnixTime::from_pdf_date(&time())).trusted
}

/// The PDF files signed by other signers in `fixtures/sign/pdf` (WP3.2B: pyHanko 0.37, and
/// OpenSSL CMS over pyHanko placeholders), by file name, sorted.
pub fn interop_fixtures() -> Vec<(String, Vec<u8>)> {
    let dir = repo().join("fixtures/sign/pdf");
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.ends_with(".pdf")
                .then(|| (name, std::fs::read(entry.path()).unwrap()))
        })
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no PDF in {}", dir.display());
    out
}

/// The pyHanko-made PDF fixtures of `fixtures/sign/pdf` (WP3.2B), by file name, sorted.
pub fn pyhanko_fixtures() -> Vec<(String, Vec<u8>)> {
    interop_fixtures()
        .into_iter()
        .filter(|(name, _)| name.starts_with("pyhanko-"))
        .collect()
}

/// A one-line summary of a report, for assertion messages.
pub fn summary(r: &SignatureReport) -> String {
    let codes: Vec<String> = r.problems.iter().map(|p| p.code.to_string()).collect();
    format!(
        "field={:?} byteRangeOk={} intact={} valid={} coverage={} modification={} problems={codes:?}",
        r.field_name, r.byte_range_ok, r.intact, r.signature_valid, r.coverage, r.modification
    )
}
