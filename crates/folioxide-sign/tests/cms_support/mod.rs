//! Helpers shared by the `keys_*`, `cms_*` and `chain_*` integration tests: fixture loading,
//! a small DER builder for hand-made CMS structures, and the OpenSSL cross-check.
//!
//! Each test crate uses a different subset, hence the `dead_code` allowance.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use folioxide_sign::algorithms::{DigestAlgorithm, oid};
use folioxide_sign::cms::{self, SignedAttrsInput};
use folioxide_sign::signer::{LocalSigner, Signer};

/// The password of every encrypted fixture key and `.p12`.
pub const PASSWORD: &str = "folioxide";

/// `fixtures/` at the repository root.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

/// The bytes of `fixtures/<path>`.
pub fn fixture(path: &str) -> Vec<u8> {
    let full = fixtures_dir().join(path);
    std::fs::read(&full).unwrap_or_else(|e| panic!("reading {}: {e}", full.display()))
}

/// The text of `fixtures/<path>`.
pub fn fixture_str(path: &str) -> String {
    String::from_utf8(fixture(path)).unwrap()
}

/// The single certificate of a PEM fixture, as DER.
pub fn cert_der(path: &str) -> Vec<u8> {
    let mut certs = folioxide_sign::keys::certificates_from_pem(&fixture_str(path)).unwrap();
    assert_eq!(certs.len(), 1, "{path}");
    certs.remove(0)
}

/// The signer names of the test PKI.
pub const SIGNERS: [&str; 4] = ["rsa2048", "rsa3072", "p256", "p384"];

/// `pki/signer-<name>` as a [`LocalSigner`] from its unencrypted PKCS#8 key, with the
/// intermediate after it.
pub fn pem_signer(name: &str) -> LocalSigner {
    let certs =
        fixture_str(&format!("pki/signer-{name}.pem")) + &fixture_str("pki/intermediate.pem");
    LocalSigner::from_pem(
        &fixture_str(&format!("pki/signer-{name}.key.pem")),
        &certs,
        None,
    )
    .unwrap()
}

/// The content every `fixtures/sign/*.p7s` vector signs.
pub fn vector_data() -> Vec<u8> {
    fixture("sign/data.bin")
}

/// A complete detached CMS over `content` from `signer`, through the public building API.
pub fn sign_cms(signer: &dyn Signer, digest: DigestAlgorithm, content: &[u8]) -> Vec<u8> {
    let document_digest = digest.digest(&[content]);
    let chain = signer.certificate_chain();
    let attrs = cms::build_signed_attrs(&SignedAttrsInput {
        digest,
        document_digest: &document_digest,
        signer_cert_der: &chain[0],
    })
    .unwrap();
    let signature = signer.sign(digest, &attrs).unwrap();
    cms::assemble(
        &attrs,
        &signature,
        chain,
        signer.algorithm(),
        signer.key_kind(),
        digest,
    )
    .unwrap()
}

/// Verifies a parsed detached CMS over `content`.
pub fn verify_over(cms_der: &[u8], content: &[u8]) -> cms::CmsVerification {
    let parsed = cms::parse(cms_der).unwrap();
    let content = content.to_vec();
    cms::verify_detached(&parsed, &move |d| Some(d.digest(&[&content])), &[])
}

// ---------------------------------------------------------------------------------------------
// DER builder (X.690), for hand-made attributes and CMS variants
// ---------------------------------------------------------------------------------------------

/// The DER TLV `tag || length || content`.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// A SEQUENCE of the concatenated parts.
pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

/// A SET of the concatenated parts, in the given order (not sorted).
pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x31, &parts.concat())
}

/// An OBJECT IDENTIFIER.
pub fn oid_der(dotted: &str) -> Vec<u8> {
    tlv(
        0x06,
        const_oid::ObjectIdentifier::new(dotted).unwrap().as_bytes(),
    )
}

/// An OCTET STRING.
pub fn octets(bytes: &[u8]) -> Vec<u8> {
    tlv(0x04, bytes)
}

/// An `AlgorithmIdentifier` without parameters.
pub fn alg_id(dotted: &str) -> Vec<u8> {
    seq(&[&oid_der(dotted)])
}

/// An `Attribute ::= SEQUENCE { attrType, SET { values } }`.
pub fn attribute(dotted: &str, values: &[&[u8]]) -> Vec<u8> {
    seq(&[&oid_der(dotted), &set(values)])
}

/// The content-type and message-digest attributes of `content`.
pub fn basic_attributes(digest: DigestAlgorithm, content: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (
        attribute(oid::CONTENT_TYPE, &[&oid_der(oid::ID_DATA)]),
        attribute(oid::MESSAGE_DIGEST, &[&octets(&digest.digest(&[content]))]),
    )
}

/// Signs hand-made signed attributes (a 0x31 SET, any order) and assembles the CMS.
pub fn cms_with_attributes(
    signer: &dyn Signer,
    digest: DigestAlgorithm,
    attrs: &[&[u8]],
) -> Vec<u8> {
    let signed_attrs = set(attrs);
    let signature = signer.sign(digest, &signed_attrs).unwrap();
    cms::assemble(
        &signed_attrs,
        &signature,
        signer.certificate_chain(),
        signer.algorithm(),
        signer.key_kind(),
        digest,
    )
    .unwrap()
}

/// The children of a DER element (definite lengths only): `(tag, whole element)`.
pub fn der_children(element: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let (_, content) = der_split(element);
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let len = der_total_len(rest);
        out.push((rest[0], rest[..len].to_vec()));
        rest = &rest[len..];
    }
    out
}

/// `(header length, content)` of a definite-length DER element.
pub fn der_split(element: &[u8]) -> (usize, &[u8]) {
    let first = element[1];
    let (header, len) = if first < 0x80 {
        (2, usize::from(first))
    } else {
        let count = usize::from(first & 0x7F);
        let len = element[2..2 + count]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (2 + count, len)
    };
    (header, &element[header..header + len])
}

/// The total length of the definite-length DER element at the start of `bytes`.
pub fn der_total_len(bytes: &[u8]) -> usize {
    let (header, content) = der_split(bytes);
    header + content.len()
}

/// Rebuilds a DER element with a new content (the header is re-encoded).
pub fn der_with_content(element: &[u8], content: &[u8]) -> Vec<u8> {
    tlv(element[0], content)
}

/// Applies `edit` to the SignerInfo of a DER CMS made by `cms::assemble` and rebuilds every
/// enclosing length. `edit` gets and returns the SignerInfo's children.
pub fn edit_signer_info(cms_der: &[u8], edit: impl FnOnce(&mut Vec<(u8, Vec<u8>)>)) -> Vec<u8> {
    let ci = der_children(cms_der);
    let explicit = &ci[1].1;
    let sd = der_children(explicit)[0].1.clone();
    let mut sd_children = der_children(&sd);
    let sis = sd_children.last().unwrap().1.clone();
    let si = der_children(&sis)[0].1.clone();
    let mut si_children = der_children(&si);
    edit(&mut si_children);
    let si_new = der_with_content(&si, &concat(&si_children));
    let sis_new = der_with_content(&sis, &si_new);
    let last = sd_children.len() - 1;
    sd_children[last].1 = sis_new;
    let sd_new = der_with_content(&sd, &concat(&sd_children));
    let explicit_new = der_with_content(explicit, &sd_new);
    seq(&[&ci[0].1, &explicit_new])
}

/// Applies `edit` to the children of the SignedData of a DER CMS and rebuilds the lengths.
pub fn edit_signed_data(cms_der: &[u8], edit: impl FnOnce(&mut Vec<(u8, Vec<u8>)>)) -> Vec<u8> {
    let ci = der_children(cms_der);
    let explicit = &ci[1].1;
    let sd = der_children(explicit)[0].1.clone();
    let mut sd_children = der_children(&sd);
    edit(&mut sd_children);
    let sd_new = der_with_content(&sd, &concat(&sd_children));
    let explicit_new = der_with_content(explicit, &sd_new);
    seq(&[&ci[0].1, &explicit_new])
}

fn concat(children: &[(u8, Vec<u8>)]) -> Vec<u8> {
    children
        .iter()
        .flat_map(|(_, bytes)| bytes.clone())
        .collect()
}

// ---------------------------------------------------------------------------------------------
// OpenSSL cross-check
// ---------------------------------------------------------------------------------------------

/// Whether the `openssl` command line tool runs. When `FOLIOXIDE_REQUIRE_OPENSSL=1`, a missing
/// OpenSSL fails the test instead of skipping the cross-check.
pub fn openssl_available() -> bool {
    let available = Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !available {
        assert!(
            std::env::var("FOLIOXIDE_REQUIRE_OPENSSL").as_deref() != Ok("1"),
            "FOLIOXIDE_REQUIRE_OPENSSL=1 but `openssl` does not run"
        );
        eprintln!("openssl is not available: skipping the OpenSSL cross-check");
    }
    available
}

/// A fresh scratch directory under the target directory for files handed to OpenSSL.
pub fn scratch_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs `openssl cms -verify -binary -inform DER -content <data> -CAfile root.pem -purpose any`
/// and returns `(success, stderr)`.
pub fn openssl_cms_verify(
    dir: &Path,
    name: &str,
    cms_der: &[u8],
    content: &[u8],
) -> (bool, String) {
    let cms_path = dir.join(format!("{name}.p7s"));
    let data_path = dir.join(format!("{name}.bin"));
    std::fs::write(&cms_path, cms_der).unwrap();
    std::fs::write(&data_path, content).unwrap();
    let output = Command::new("openssl")
        .args(["cms", "-verify", "-binary", "-inform", "DER", "-in"])
        .arg(&cms_path)
        .arg("-content")
        .arg(&data_path)
        .arg("-CAfile")
        .arg(fixtures_dir().join("pki/root.pem"))
        .args(["-purpose", "any", "-out"])
        .arg(dir.join(format!("{name}.out")))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (
        output.status.success() && stderr.contains("Verification successful"),
        stderr,
    )
}
