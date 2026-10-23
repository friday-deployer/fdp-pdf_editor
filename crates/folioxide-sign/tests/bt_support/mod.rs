//! Shared helpers of the timestamp tests (M4 WP4.1B, WP4.2B): the test PKI's signers and TSA
//! certificates, the mock TSA as a [`Timestamper`], B-T signing and verification shortcuts,
//! and the committed TSA fixtures of `fixtures/sign/tsa`.

#![allow(dead_code)]

pub mod decoys;
pub mod tokens;

use std::path::{Path, PathBuf};

use folioxide_model::{Document, PdfDate};
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::bt::TimestampParams;
use folioxide_sign::prepare::SignatureOptions;
use folioxide_sign::report::SignatureReport;
use folioxide_sign::sign::{SignRequest, sign};
use folioxide_sign::signer::{LocalSigner, Signer};
use folioxide_sign::tsp::Timestamper;
use folioxide_sign::verify_pdf::{VerifyOptions, verify_bytes};
use folioxide_syntax::OpenOptions;
use folioxide_testkit::tsa::{MockTsa, MockTsaOptions};

/// The test PKI password (fixtures/pki/README.md).
pub const PASSWORD: &str = "folioxide";

/// The nonce of the deterministic requests (brief §4.1 golden).
pub const NONCE: u64 = 0x0102_0304_0506_0708;

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

/// The first certificate of a PEM file of `fixtures/pki`, as DER.
pub fn cert(name: &str) -> Vec<u8> {
    folioxide_sign::keys::certificates_from_pem(&pki_text(name))
        .unwrap()
        .remove(0)
}

/// A file of `fixtures/sign/tsa`.
pub fn tsa_fixture(name: &str) -> Vec<u8> {
    let path = repo().join("fixtures/sign/tsa").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A file of `fixtures/sign/pdf`.
pub fn pdf_fixture(name: &str) -> Vec<u8> {
    let path = repo().join("fixtures/sign/pdf").join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The signing time of every test signature.
pub fn time() -> PdfDate {
    PdfDate::parse(b"D:20261010120000Z").unwrap()
}

/// A PEM signer: `<key>` with `<cert>` and the intermediate.
pub fn pem_signer(key: &str, cert: &str) -> LocalSigner {
    let certs = pki_text(cert) + &pki_text("intermediate.pem");
    LocalSigner::from_pem(&pki_text(key), &certs, None).unwrap_or_else(|e| panic!("{key}: {e}"))
}

/// RSA-2048 from PEM.
pub fn rsa2048() -> LocalSigner {
    pem_signer("signer-rsa2048.key.pem", "signer-rsa2048.pem")
}

/// P-256 from PEM.
pub fn p256() -> LocalSigner {
    pem_signer("signer-p256.key.pem", "signer-p256.pem")
}

/// P-384 from PEM.
pub fn p384() -> LocalSigner {
    pem_signer("signer-p384.key.pem", "signer-p384.pem")
}

/// The TSA's key (`tsa.key.pem`) with `cert` (`tsa.pem` or a variant).
pub fn tsa_key(cert: &str) -> LocalSigner {
    LocalSigner::from_pem(&pki_text("tsa.key.pem"), &pki_text(cert), None)
        .unwrap_or_else(|e| panic!("{cert}: {e}"))
}

/// A mock TSA with the certificate `cert` (`tsa.pem` or a variant, all for `tsa.key.pem`),
/// carrying the root as extra certificate, and `options`.
pub fn mock_tsa_with(cert_name: &str, options: MockTsaOptions) -> MockTsa {
    let key = tsa_key(cert_name);
    MockTsa::new(
        cert(cert_name),
        vec![cert("root.pem")],
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    )
    .with_options(options)
}

/// The default mock TSA (`tsa.pem`).
pub fn mock_tsa() -> MockTsa {
    mock_tsa_with("tsa.pem", MockTsaOptions::default())
}

/// A [`MockTsa`] as a [`Timestamper`].
pub struct Tsa(pub MockTsa);

impl Timestamper for Tsa {
    fn timestamp(&self, request_der: &[u8]) -> folioxide_sign::Result<Vec<u8>> {
        Ok(self.0.respond(request_der))
    }
}

/// Opens a document leniently.
pub fn open(bytes: &[u8]) -> Document {
    Document::open(bytes.to_vec(), &OpenOptions::default()).unwrap()
}

/// `syntax/minimal.pdf`.
pub fn minimal() -> Vec<u8> {
    folioxide_testkit::fixtures::syntax::minimal()
}

/// Signs `source` B-T with `signer`, `options` and the timestamper, nonce [`NONCE`].
pub fn sign_bt_with(
    source: &[u8],
    signer: &dyn Signer,
    options: SignatureOptions,
    timestamper: &dyn Timestamper,
) -> folioxide_sign::Result<Vec<u8>> {
    let params = TimestampParams::new().with_nonce(Some(NONCE));
    sign(
        &open(source),
        &SignRequest::new(signer, time())
            .with_options(options)
            .with_timestamper(timestamper, params),
    )
}

/// Signs `source` B-T with `signer` and the default mock TSA.
pub fn sign_bt(source: &[u8], signer: &dyn Signer) -> Vec<u8> {
    sign_bt_with(
        source,
        signer,
        SignatureOptions::new(time()),
        &Tsa(mock_tsa()),
    )
    .unwrap_or_else(|e| panic!("B-T signing failed: {e}"))
}

/// The test PKI root as DER.
pub fn anchors() -> Vec<Vec<u8>> {
    vec![cert("root.pem")]
}

/// Verifies with the test root as trust anchor and no validation time (V9: a trusted
/// signature timestamp's `genTime`, else `/M`).
pub fn verify(bytes: &[u8]) -> Vec<SignatureReport> {
    verify_with(
        bytes,
        &VerifyOptions::new().with_trust_anchors_der(anchors()),
    )
}

/// Verifies with `options`.
pub fn verify_with(bytes: &[u8], options: &VerifyOptions) -> Vec<SignatureReport> {
    verify_bytes(bytes.to_vec(), options).unwrap_or_else(|e| panic!("verify failed: {e}"))
}

/// A one-line summary of a report, for assertion messages.
pub fn summary(r: &SignatureReport) -> String {
    format!(
        "{:?} intact={} valid={} trusted={:?} pades={:?} timestamp={:?} problems={:?} \
         warnings={:?}",
        r.field_name,
        r.intact,
        r.signature_valid,
        r.trusted,
        r.pades_level,
        r.timestamp
            .as_ref()
            .map(|t| (t.intact, t.valid, t.trusted, &t.gen_time, &t.problems)),
        r.problems,
        r.warnings
    )
}

/// Hex digits of `bytes`, uppercase.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Writes `cms` into the `/Contents` of a prepared file (no check at all): for attack files
/// that Folioxide's own `finish` refuses to write.
pub fn embed_raw(prepared: &folioxide_sign::prepare::PreparedSignature, cms: &[u8]) -> Vec<u8> {
    let mut pdf = prepared.pdf().to_vec();
    let (a, b) = prepared.contents_range();
    let (a, b) = (usize::try_from(a).unwrap(), usize::try_from(b).unwrap());
    let digits = hex(cms).into_bytes();
    assert!(digits.len() <= b - a - 2, "the CMS does not fit");
    pdf[a + 1..a + 1 + digits.len()].copy_from_slice(&digits);
    pdf
}

/// Base64 (RFC 4648) of `bytes`, for PEM.
pub fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(TABLE[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The PEM text of DER certificates.
pub fn pem(certs: &[Vec<u8>]) -> String {
    certs
        .iter()
        .map(|der| {
            let body: Vec<String> = base64(der)
                .as_bytes()
                .chunks(64)
                .map(|line| String::from_utf8(line.to_vec()).unwrap())
                .collect();
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                body.join("\n")
            )
        })
        .collect()
}

/// A deterministic RNG (splitmix64) for the salt of RSASSA-PSS test signatures.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl rand_core::TryRng for SplitMix {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for SplitMix {}

/// The AlgorithmIdentifier of RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a 32-byte salt
/// (RFC 4055 §3.1, RFC 5754; the trailer field is the default).
pub fn rsassa_pss_sha256() -> Vec<u8> {
    rsassa_pss_sha256_salt(32)
}

/// [`rsassa_pss_sha256`] with a `salt`-byte salt.
pub fn rsassa_pss_sha256_salt(salt: u8) -> Vec<u8> {
    use decoys::der;
    let sha256 = der(
        0x30,
        &[
            der(
                0x06,
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            ),
            vec![0x05, 0x00],
        ]
        .concat(),
    );
    let mgf1 = der(
        0x30,
        &[
            der(
                0x06,
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08],
            ),
            sha256.clone(),
        ]
        .concat(),
    );
    let params = der(
        0x30,
        &[
            der(0xA0, &sha256),
            der(0xA1, &mgf1),
            der(0xA2, &der(0x02, &[salt])),
        ]
        .concat(),
    );
    der(
        0x30,
        &[
            der(
                0x06,
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A],
            ),
            params,
        ]
        .concat(),
    )
}

/// The RSASSA-PSS signature (SHA-256, MGF1-SHA-256, a `salt`-byte salt from a fixed-seed RNG,
/// so it is the same on every run; RFC 8017 §8.1) of `data` by the RSA key `key` of
/// `fixtures/pki` (unencrypted PKCS #8).
pub fn pss_signature(key: &str, salt: u8, data: &[u8]) -> Vec<u8> {
    use rsa::pkcs8::DecodePrivateKey as _;
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(&pki_text(key)).unwrap();
    let hashed = DigestAlgorithm::Sha256.digest(&[data]);
    key.sign_with_rng(
        &mut SplitMix(0x5EED_CE27),
        rsa::Pss::<sha2::Sha256>::new_with_salt(usize::from(salt)),
        &hashed,
    )
    .unwrap()
}

/// A mock TSA (`tsa.pem`, carrying the root) that signs its tokens with RSASSA-PSS (SHA-256,
/// MGF1-SHA-256, salt 32; RFC 4056), with `options` (whose `signature_algorithm`, when set,
/// replaces [`rsassa_pss_sha256`]): a construct RFC 5652 allows and OpenSSL 3.0's `ts -verify`
/// cannot verify (its PKCS #7 layer knows PKCS #1 v1.5 only).
pub fn mock_tsa_pss(options: MockTsaOptions) -> MockTsa {
    mock_tsa_pss_for(cert("tsa.pem"), 32, options)
}

/// [`mock_tsa_pss`] for `tsa_cert` (a certificate of `tsa.key.pem`) with a `salt`-byte salt,
/// also in the default `signature_algorithm`.
pub fn mock_tsa_pss_for(tsa_cert: Vec<u8>, salt: u8, options: MockTsaOptions) -> MockTsa {
    use rsa::pkcs8::DecodePrivateKey as _;
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(&pki_text("tsa.key.pem")).unwrap();
    let rng = std::sync::Mutex::new(SplitMix(0x5EED));
    MockTsa::new(
        tsa_cert,
        vec![cert("root.pem")],
        Box::new(move |attrs| {
            let hashed = DigestAlgorithm::Sha256.digest(&[attrs]);
            let mut rng = rng.lock().unwrap();
            key.sign_with_rng(
                &mut *rng,
                rsa::Pss::<sha2::Sha256>::new_with_salt(usize::from(salt)),
                &hashed,
            )
            .unwrap()
        }),
    )
    .with_options(MockTsaOptions {
        signature_algorithm: options
            .signature_algorithm
            .clone()
            .or_else(|| Some(rsassa_pss_sha256_salt(salt))),
        ..options
    })
}
