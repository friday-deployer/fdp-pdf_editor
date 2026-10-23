//! Shared helpers of the signing and verification integration tests (M3 WP3.2A): the test PKI
//! signers, a fixed signing time, signing and verifying shortcuts, and the pyHanko-signed
//! interop fixtures when they are present.

#![allow(dead_code)]

pub mod corpus;
pub mod oracle;
pub mod visible;

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

/// A signature [`sign_raw`] writes without the signing API's placement rules: the field's
/// name, `/Rect` and appearance, and extra entries for the field, the signature dictionary and
/// the catalog (M4 corpus cases that Folioxide refuses to sign: FieldMDP, a new visible approval
/// on a certified document, invalid or late DocMDP declarations).
#[derive(Clone, Debug, Default)]
pub struct RawSignature {
    /// The field's partial name (default `Raw1`).
    pub name: String,
    /// The widget's `/Rect` (default `[0 0 0 0]`, invisible).
    pub rect: [i64; 4],
    /// The content of a new `/AP /N` form XObject for the widget.
    pub appearance: Option<Vec<u8>>,
    /// Extra entries of the merged field and widget.
    pub field: Vec<(&'static str, folioxide_syntax::Object)>,
    /// Extra entries of the signature dictionary (before `/ByteRange`).
    pub sig: Vec<(&'static str, folioxide_syntax::Object)>,
    /// Name the signature dictionary in the catalog's `/Perms /DocMDP` (a direct `/Perms`).
    pub perms: bool,
    /// Sign the existing field named [`RawSignature::name`] (a merged field and widget of the
    /// source): its `/V`, appearance and extra entries are set, nothing else is created.
    pub existing: bool,
    /// The dictionary of the appearance stream instead of `/Type /XObject /Subtype /Form
    /// /BBox [0 0 w h]` (M4 QA round 1, finding R5: appearances that are no form XObject).
    pub appearance_dict: Option<folioxide_syntax::Dict>,
    /// Byte replacements of equal length applied to the signing revision's bytes before they are
    /// signed, each at its last occurrence: a key written under a stand-in name (`/Referencf`)
    /// renamed to a key the dictionary has already (`/Reference`), which writes that key twice
    /// (M4 QA round 2, finding 8: duplicate keys in what the signature itself signs).
    pub renames: Vec<(&'static [u8], &'static [u8])>,
}

/// Signs `source` with `signer` (SHA-256, PAdES B-B attributes) in a new merged signature field
/// and widget built from `raw`, appended to the first page's `/Annots` and the AcroForm's
/// `/Fields` (an AcroForm is created when there is none, with `/SigFlags 3`): a genuine,
/// verifiable signature, written with `folioxide-syntax` edits and `folioxide_sign::cms` only.
pub fn sign_raw(source: &[u8], signer: &LocalSigner, raw: &RawSignature) -> Vec<u8> {
    use folioxide_sign::algorithms::DigestAlgorithm;
    use folioxide_sign::cms::{self, SignedAttrsInput};
    use folioxide_syntax::{Dict, IncrementalOptions, Object, Store, Stream, StreamData};
    use folioxide_testkit::fixtures::forms;

    const RESERVE: usize = 8192;
    let placeholder = b"[0 9999999999 9999999999 9999999999]";
    let mut store = Store::open_bytes(source.to_vec(), &OpenOptions::default()).unwrap();
    let page = forms::page_id(&store, 0).unwrap();
    let mut sig = Dict::new();
    sig.insert("Type", Object::name("Sig"));
    sig.insert("Filter", Object::name("Adobe.PPKLite"));
    sig.insert("SubFilter", Object::name("ETSI.CAdES.detached"));
    sig.insert("M", Object::literal_string("D:20261010120000Z"));
    for (key, value) in &raw.sig {
        sig.insert(*key, value.clone());
    }
    sig.insert(
        "ByteRange",
        Object::Array(vec![
            Object::Int(0),
            Object::Int(9_999_999_999),
            Object::Int(9_999_999_999),
            Object::Int(9_999_999_999),
        ]),
    );
    sig.insert("Contents", Object::hex_string(vec![0u8; RESERVE]));
    let sig = store.add(Object::Dict(sig)).unwrap();
    let rect = Object::Array(raw.rect.iter().copied().map(Object::Int).collect());
    let name = if raw.name.is_empty() {
        "Raw1"
    } else {
        &raw.name
    };
    let existing = raw.existing.then(|| {
        store
            .object_ids()
            .into_iter()
            .find(|&id| {
                store.resolve(id).ok().is_some_and(|o| {
                    o.as_dict()
                        .is_some_and(|d| d.get_str_bytes(b"T") == Some(name.as_bytes()))
                })
            })
            .unwrap_or_else(|| panic!("no field {name}"))
    });
    let mut widget = match existing {
        Some(id) => store.resolve(id).unwrap().as_dict().unwrap().clone(),
        None => {
            let mut widget = Dict::new();
            widget.insert("Type", Object::name("Annot"));
            widget.insert("Subtype", Object::name("Widget"));
            widget.insert("FT", Object::name("Sig"));
            widget.insert("T", Object::literal_string(name));
            widget.insert("F", Object::Int(132));
            widget.insert("Rect", rect);
            widget.insert("P", Object::Ref(page));
            widget
        }
    };
    widget.insert("V", Object::Ref(sig));
    if let Some(content) = &raw.appearance {
        let [x1, y1, x2, y2] = raw.rect;
        let form = raw.appearance_dict.clone().unwrap_or_else(|| {
            let mut form = Dict::new();
            form.insert("Type", Object::name("XObject"));
            form.insert("Subtype", Object::name("Form"));
            form.insert(
                "BBox",
                Object::Array(vec![
                    Object::Int(0),
                    Object::Int(0),
                    Object::Int((x2 - x1).abs()),
                    Object::Int((y2 - y1).abs()),
                ]),
            );
            form
        });
        let stream = Stream::new(form, StreamData::Decoded(content.clone()));
        let ap = store.add(Object::Stream(Box::new(stream))).unwrap();
        let mut dict = Dict::new();
        dict.insert("N", Object::Ref(ap));
        widget.insert("AP", Object::Dict(dict));
    }
    for (key, value) in &raw.field {
        widget.insert(*key, value.clone());
    }
    let root = store.root_id().unwrap();
    let mut catalog = store.resolve(root).unwrap().as_dict().unwrap().clone();
    if let Some(id) = existing {
        store.set(id, Object::Dict(widget)).unwrap();
    } else {
        let widget = store.add(Object::Dict(widget)).unwrap();
        forms::append_to_annots(&mut store, page, widget).unwrap();
        match catalog.get(b"AcroForm").cloned() {
            Some(Object::Ref(acroform)) => {
                let mut dict = store.resolve(acroform).unwrap().as_dict().unwrap().clone();
                let mut fields = dict.get_array(b"Fields").unwrap_or_default().to_vec();
                fields.push(Object::Ref(widget));
                dict.insert("Fields", Object::Array(fields));
                store.set(acroform, Object::Dict(dict)).unwrap();
            }
            _ => {
                let mut dict = Dict::new();
                dict.insert("Fields", Object::Array(vec![Object::Ref(widget)]));
                dict.insert("SigFlags", Object::Int(3));
                let acroform = store.add(Object::Dict(dict)).unwrap();
                catalog.insert("AcroForm", Object::Ref(acroform));
            }
        }
    }
    if raw.perms {
        let mut perms = Dict::new();
        perms.insert("DocMDP", Object::Ref(sig));
        catalog.insert("Perms", Object::Dict(perms));
    }
    store.set(root, Object::Dict(catalog)).unwrap();
    let mut pdf = store
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    for (from, to) in &raw.renames {
        assert_eq!(from.len(), to.len(), "a rename keeps the offsets");
        let at = pdf
            .windows(from.len())
            .rposition(|w| w == *from)
            .unwrap_or_else(|| panic!("{} is not written", String::from_utf8_lossy(from)));
        pdf[at..at + to.len()].copy_from_slice(to);
    }

    // §12.8.1: patch /ByteRange around the /Contents token, then digest and sign.
    let token = format!("<{}>", "0".repeat(RESERVE * 2));
    let a = pdf
        .windows(token.len())
        .rposition(|w| w == token.as_bytes())
        .unwrap();
    let b = a + token.len();
    let at = pdf
        .windows(placeholder.len())
        .rposition(|w| w == placeholder)
        .unwrap();
    let text = format!("[0 {a} {b} {}", pdf.len() - b);
    let mut patched = text.into_bytes();
    patched.resize(placeholder.len() - 1, b' ');
    patched.push(b']');
    pdf[at..at + placeholder.len()].copy_from_slice(&patched);
    let digest = DigestAlgorithm::Sha256;
    let document_digest = digest.digest(&[&pdf[..a], &pdf[b..]]);
    let chain = signer.certificate_chain().to_vec();
    let signed_attrs = cms::build_signed_attrs(&SignedAttrsInput {
        digest,
        document_digest: &document_digest,
        signer_cert_der: &chain[0],
    })
    .unwrap();
    let value = signer.sign(digest, &signed_attrs).unwrap();
    let der = cms::assemble(
        &signed_attrs,
        &value,
        &chain,
        signer.algorithm(),
        signer.key_kind(),
        digest,
    )
    .unwrap();
    let hex: String = der.iter().map(|byte| format!("{byte:02X}")).collect();
    pdf[a + 1..a + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    pdf
}
