//! Certificates for the ESS decoy cases (M4 QA round 2 finding 3), issued at test time from the
//! committed test keys of `fixtures/pki`, so no certificate is committed for them. Every
//! signature is deterministic (RSA PKCS#1 v1.5, RFC 6979 ECDSA), so the files the oracle
//! suite writes are the same on every run.
//!
//! A *decoy* carries the subject name of a real CA certificate of the test PKI but is not
//! the certificate the verifier's chain holds: another key (`fake_root`,
//! `fake_intermediate`), or the same name and key under another serial (`reissued_root`).
//! OpenSSL's `ts -verify` looks for later ESS identifiers in the chain it verified, so an
//! identifier that names a decoy is `ess cert id not found` there.

use std::sync::OnceLock;

use folioxide_sign::algorithms::{DigestAlgorithm, KeyKind};
use folioxide_sign::signer::{LocalSigner, Signer};

use super::{cert, pki_text};

/// The decoys and the extra TSA certificate.
pub struct Decoys {
    /// The root's subject, self-signed with the P-256 signer's key: an attacker's root.
    pub fake_root: Vec<u8>,
    /// The root's subject **and** key, self-signed again under another serial: another DER
    /// encoding of the same CA, which is not the trust anchor.
    pub reissued_root: Vec<u8>,
    /// The intermediate's subject, self-signed with the P-256 signer's key.
    pub fake_intermediate: Vec<u8>,
    /// The TSA certificate's subject and key, issued by the root under another serial.
    pub tsa_twin: Vec<u8>,
    /// A TSA certificate for `tsa.key.pem` issued by the intermediate (ecdsa-with-SHA384),
    /// subject `CN=Folioxide Test TSA via Intermediate`.
    pub tsa_via_intermediate: Vec<u8>,
}

/// The decoys, made once per test binary.
pub fn decoys() -> &'static Decoys {
    static DECOYS: OnceLock<Decoys> = OnceLock::new();
    DECOYS.get_or_init(make)
}

/// `(header length, content length)` of the DER element at the start of `d`.
fn header(d: &[u8]) -> (usize, usize) {
    if d[1] < 0x80 {
        (2, usize::from(d[1]))
    } else {
        let n = usize::from(d[1] & 0x7F);
        (
            2 + n,
            d[2..2 + n]
                .iter()
                .fold(0, |a, &b| (a << 8) | usize::from(b)),
        )
    }
}

/// The content octets of the DER element `d`.
pub fn content(d: &[u8]) -> &[u8] {
    let (h, l) = header(d);
    &d[h..h + l]
}

/// The consecutive DER elements of `c`.
pub fn children(mut c: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while !c.is_empty() {
        let (h, l) = header(c);
        out.push(&c[..h + l]);
        c = &c[h + l..];
    }
    out
}

/// A DER element.
pub fn der(tag: u8, c: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match c.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(c);
    out
}

/// The tbsCertificate fields of `cert_der` (version, serial, signature, issuer, validity,
/// subject, subjectPublicKeyInfo, …) without the version.
fn tbs_fields(cert_der: &[u8]) -> Vec<&[u8]> {
    let tbs = children(content(cert_der))[0];
    let fields = children(content(tbs));
    let skip = usize::from(fields[0][0] == 0xA0);
    fields[skip..].to_vec()
}

/// The issuer `Name` of a DER certificate.
pub fn issuer_of(cert_der: &[u8]) -> Vec<u8> {
    tbs_fields(cert_der)[2].to_vec()
}

/// The subject `Name` of a DER certificate.
pub fn subject_of(cert_der: &[u8]) -> Vec<u8> {
    tbs_fields(cert_der)[4].to_vec()
}

/// The subjectPublicKeyInfo of a DER certificate.
pub fn spki_of(cert_der: &[u8]) -> Vec<u8> {
    tbs_fields(cert_der)[5].to_vec()
}

/// The serial number content octets of a DER certificate.
pub fn serial_of(cert_der: &[u8]) -> Vec<u8> {
    content(tbs_fields(cert_der)[0]).to_vec()
}

/// `id-RSASSA-PSS` (1.2.840.113549.1.1.10), content octets.
pub const RSASSA_PSS: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];

/// The RSA SubjectPublicKeyInfo `spki` (rsaEncryption) with its algorithm replaced by
/// `id-RSASSA-PSS` and the whole parameters element `parameters` (none when `None`): the same
/// key, restricted to RSASSA-PSS (RFC 4055 §1.2, §3.1).
pub fn pss_spki(spki: &[u8], parameters: Option<&[u8]>) -> Vec<u8> {
    let parts = children(content(spki));
    let mut algorithm = der(0x06, RSASSA_PSS);
    if let Some(parameters) = parameters {
        algorithm.extend_from_slice(parameters);
    }
    der(0x30, &[der(0x30, &algorithm), parts[1].to_vec()].concat())
}

/// The subjectKeyIdentifier octets of a DER certificate (RFC 5280 §4.2.1.2), if it has one.
pub fn ski_of(cert_der: &[u8]) -> Option<Vec<u8>> {
    let extensions = tbs_fields(cert_der)
        .into_iter()
        .find(|field| field[0] == 0xA3)?;
    children(content(content(extensions)))
        .into_iter()
        .find_map(|extension| {
            let parts = children(content(extension));
            (content(parts[0]) == [0x55, 0x1D, 0x0E])
                .then(|| content(content(parts[parts.len() - 1])).to_vec())
        })
}

/// `name` with every UTF8String value re-tagged as `tag` and, with `lowercase`, its ASCII
/// lowercased: another encoding of the same name for RFC 5280 §7.1 (QA round 2 finding 4).
pub fn reencode_name(name: &[u8], tag: u8, lowercase: bool) -> Vec<u8> {
    let rdns: Vec<Vec<u8>> = children(content(name))
        .into_iter()
        .map(|rdn| {
            let entries: Vec<Vec<u8>> = children(content(rdn))
                .into_iter()
                .map(|entry| {
                    let parts = children(content(entry));
                    let value = parts[1];
                    let text = content(value);
                    let text = if lowercase {
                        text.to_ascii_lowercase()
                    } else {
                        text.to_vec()
                    };
                    let tag = if value[0] == 0x0C { tag } else { value[0] };
                    der(0x30, &[parts[0], &der(tag, &text)].concat())
                })
                .collect();
            der(0x31, &entries.concat())
        })
        .collect();
    der(0x30, &rdns.concat())
}

/// `basicConstraints` (critical, cA) and `keyUsage` (critical, keyCertSign and cRLSign).
pub fn ca_extensions() -> Vec<Vec<u8>> {
    vec![
        der(
            0x30,
            &[
                der(0x06, &[0x55, 0x1D, 0x13]),
                der(0x01, &[0xFF]),
                der(0x04, &der(0x30, &der(0x01, &[0xFF]))),
            ]
            .concat(),
        ),
        der(
            0x30,
            &[
                der(0x06, &[0x55, 0x1D, 0x0F]),
                der(0x01, &[0xFF]),
                der(0x04, &der(0x03, &[0x01, 0x06])),
            ]
            .concat(),
        ),
    ]
}

/// `extKeyUsage` (critical, exactly id-kp-timeStamping) and `keyUsage` (critical,
/// digitalSignature): what OpenSSL's `check_purpose_timestamp_sign` wants (D-4).
pub fn tsa_extensions() -> Vec<Vec<u8>> {
    let time_stamping = der(0x06, &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08]);
    vec![
        der(
            0x30,
            &[
                der(0x06, &[0x55, 0x1D, 0x25]),
                der(0x01, &[0xFF]),
                der(0x04, &der(0x30, &time_stamping)),
            ]
            .concat(),
        ),
        der(
            0x30,
            &[
                der(0x06, &[0x55, 0x1D, 0x0F]),
                der(0x01, &[0xFF]),
                der(0x04, &der(0x03, &[0x07, 0x80])),
            ]
            .concat(),
        ),
    ]
}

/// A version-3 certificate for `subject` and `spki`, issued under `issuer` by `key` (whose
/// algorithm picks the signature: sha256WithRSAEncryption, ecdsa-with-SHA256 or -SHA384),
/// valid 2025-01-01 to 2075-12-31 like the rest of the test PKI.
pub fn issue(
    serial: u32,
    issuer: &[u8],
    subject: &[u8],
    spki: &[u8],
    extensions: &[Vec<u8>],
    key: &LocalSigner,
) -> Vec<u8> {
    let (algorithm, digest) = match key.key_kind() {
        KeyKind::Rsa { .. } => (
            der(
                0x30,
                &[
                    der(
                        0x06,
                        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
                    ),
                    vec![0x05, 0x00],
                ]
                .concat(),
            ),
            DigestAlgorithm::Sha256,
        ),
        KeyKind::EcP384 => (
            der(
                0x30,
                &der(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]),
            ),
            DigestAlgorithm::Sha384,
        ),
        _ => (
            der(
                0x30,
                &der(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]),
            ),
            DigestAlgorithm::Sha256,
        ),
    };
    issue_with(
        serial,
        issuer,
        subject,
        spki,
        extensions,
        &algorithm,
        &|tbs| key.sign(digest, tbs).unwrap(),
    )
}

/// [`issue`] signed with RSASSA-PSS (SHA-256, MGF1-SHA-256, a 32-byte salt; RFC 4055 §3.1) by
/// the RSA key `key` of `fixtures/pki` ([`pss_signature`](super::pss_signature)).
pub fn issue_pss(
    serial: u32,
    issuer: &[u8],
    subject: &[u8],
    spki: &[u8],
    extensions: &[Vec<u8>],
    key: &str,
) -> Vec<u8> {
    issue_with(
        serial,
        issuer,
        subject,
        spki,
        extensions,
        &super::rsassa_pss_sha256(),
        &|tbs| super::pss_signature(key, 32, tbs),
    )
}

/// A version-3 certificate for `subject` and `spki` under `issuer` whose `signatureAlgorithm`
/// (inside and outside `tbsCertificate`) is the DER AlgorithmIdentifier `algorithm` and whose
/// signature `sign` makes over the `tbsCertificate`, valid 2025-01-01 to 2075-12-31.
pub fn issue_with(
    serial: u32,
    issuer: &[u8],
    subject: &[u8],
    spki: &[u8],
    extensions: &[Vec<u8>],
    algorithm: &[u8],
    sign: &dyn Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let mut serial_bytes: Vec<u8> = serial
        .to_be_bytes()
        .into_iter()
        .skip_while(|&b| b == 0)
        .collect();
    if serial_bytes.first().is_none_or(|&b| b & 0x80 != 0) {
        serial_bytes.insert(0, 0);
    }
    let validity = der(
        0x30,
        &[der(0x17, b"250101000000Z"), der(0x18, b"20751231235959Z")].concat(),
    );
    let tbs = der(
        0x30,
        &[
            der(0xA0, &der(0x02, &[2])),
            der(0x02, &serial_bytes),
            algorithm.to_vec(),
            issuer.to_vec(),
            validity,
            subject.to_vec(),
            spki.to_vec(),
            der(0xA3, &der(0x30, &extensions.concat())),
        ]
        .concat(),
    );
    let signature = sign(&tbs);
    der(
        0x30,
        &[
            tbs,
            algorithm.to_vec(),
            der(0x03, &[&[0u8][..], &signature].concat()),
        ]
        .concat(),
    )
}

/// A signer for `key` with the certificate `cert_name` (the key's own).
pub fn signer(key: &str, cert_name: &str) -> LocalSigner {
    LocalSigner::from_pem(&pki_text(key), &pki_text(cert_name), None)
        .unwrap_or_else(|e| panic!("{key}: {e}"))
}

fn make() -> Decoys {
    let root = cert("root.pem");
    let intermediate = cert("intermediate.pem");
    let tsa = cert("tsa.pem");
    let root_key = signer("root.key.pem", "root.pem");
    let intermediate_key = signer("intermediate.key.pem", "intermediate.pem");
    let attacker = signer("signer-p256.key.pem", "signer-p256.pem");
    let attacker_spki = spki_of(&cert("signer-p256.pem"));

    let root_name = subject_of(&root);
    let intermediate_name = subject_of(&intermediate);
    let tsa_via_intermediate_name = {
        let rdn = |oid: &[u8], text: &str| {
            der(
                0x31,
                &der(0x30, &[der(0x06, oid), der(0x0C, text.as_bytes())].concat()),
            )
        };
        der(
            0x30,
            &[
                rdn(&[0x55, 0x04, 0x0A], "Folioxide Test PKI"),
                rdn(&[0x55, 0x04, 0x0B], "TEST ONLY - DO NOT TRUST"),
                rdn(&[0x55, 0x04, 0x03], "Folioxide Test TSA via Intermediate"),
            ]
            .concat(),
        )
    };
    Decoys {
        fake_root: issue(
            0x0FA4_E001,
            &root_name,
            &root_name,
            &attacker_spki,
            &ca_extensions(),
            &attacker,
        ),
        reissued_root: issue(
            0x0042_4242,
            &root_name,
            &root_name,
            &spki_of(&root),
            &ca_extensions(),
            &root_key,
        ),
        fake_intermediate: issue(
            0x0031_337A,
            &intermediate_name,
            &intermediate_name,
            &attacker_spki,
            &ca_extensions(),
            &attacker,
        ),
        tsa_twin: issue(
            0x5151_5151,
            &root_name,
            &subject_of(&tsa),
            &spki_of(&tsa),
            &tsa_extensions(),
            &root_key,
        ),
        tsa_via_intermediate: issue(
            0x0007_5A01,
            &intermediate_name,
            &tsa_via_intermediate_name,
            &spki_of(&tsa),
            &tsa_extensions(),
            &intermediate_key,
        ),
    }
}

// ---- QA round 4 (findings 1, 2 and 5): certificates with chosen names and extensions ---------

/// A `Name` with one RDN per `(attribute type OID content octets, whole value TLV)`.
pub fn name_of(rdns: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let rdns: Vec<u8> = rdns
        .iter()
        .flat_map(|(oid, value)| der(0x31, &der(0x30, &[der(0x06, oid), value.clone()].concat())))
        .collect();
    der(0x30, &rdns)
}

/// `organizationName` (2.5.4.10).
pub const O: &[u8] = &[0x55, 0x04, 0x0A];
/// `commonName` (2.5.4.3).
pub const CN: &[u8] = &[0x55, 0x04, 0x03];

/// `O=Folioxide Test PKI, CN=<value>` with the whole value TLV `cn`.
pub fn test_name(cn: Vec<u8>) -> Vec<u8> {
    name_of(&[(O, der(0x0C, b"Folioxide Test PKI")), (CN, cn)])
}

/// An `Extension { extnID, critical, extnValue }` (RFC 5280 §4.1) of the OID content octets
/// `oid` holding the DER `value`.
pub fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![der(0x06, oid)];
    if critical {
        parts.push(der(0x01, &[0xFF]));
    }
    parts.push(der(0x04, value));
    der(0x30, &parts.concat())
}

/// A TSA certificate for `tsa.key.pem` with `subject`, issued by the root (serial `serial`),
/// with the TSA extensions of [`tsa_extensions`] and `more` after them.
pub fn tsa_cert_with(serial: u32, subject: &[u8], more: &[Vec<u8>]) -> Vec<u8> {
    let mut extensions = tsa_extensions();
    extensions.extend(more.iter().cloned());
    issue(
        serial,
        &subject_of(&cert("root.pem")),
        subject,
        &spki_of(&cert("tsa.pem")),
        &extensions,
        &signer("root.key.pem", "root.pem"),
    )
}

/// The intermediate CA (its name and key) re-issued by the root under `serial`, with the CA
/// extensions of [`ca_extensions`] and `more` after them: every certificate the real
/// intermediate issued chains to it as well.
pub fn intermediate_with(serial: u32, more: &[Vec<u8>]) -> Vec<u8> {
    let intermediate = cert("intermediate.pem");
    let mut extensions = ca_extensions();
    extensions.extend(more.iter().cloned());
    issue(
        serial,
        &subject_of(&cert("root.pem")),
        &subject_of(&intermediate),
        &spki_of(&intermediate),
        &extensions,
        &signer("root.key.pem", "root.pem"),
    )
}

/// The RSA-2048 signer's certificate (its name and key) re-issued by the intermediate under
/// `serial`, with keyUsage digitalSignature and nonRepudiation (critical) and `more`.
pub fn signer_cert_with(serial: u32, more: &[Vec<u8>]) -> Vec<u8> {
    let signer_cert = cert("signer-rsa2048.pem");
    let mut extensions = vec![extension(
        &[0x55, 0x1D, 0x0F],
        true,
        &der(0x03, &[0x06, 0xC0]),
    )];
    extensions.extend(more.iter().cloned());
    issue(
        serial,
        &subject_of(&cert("intermediate.pem")),
        &subject_of(&signer_cert),
        &spki_of(&signer_cert),
        &extensions,
        &signer("intermediate.key.pem", "intermediate.pem"),
    )
}

/// A BMPString of the UTF-16 (or UCS-2) code units `units`, written as they are.
pub fn bmp(units: &[u16]) -> Vec<u8> {
    let content: Vec<u8> = units.iter().flat_map(|u| u.to_be_bytes()).collect();
    der(0x1E, &content)
}

/// A UniversalString of the UCS-4 values `values`, written as they are.
pub fn ucs4(values: &[u32]) -> Vec<u8> {
    let content: Vec<u8> = values.iter().flat_map(|v| v.to_be_bytes()).collect();
    der(0x1C, &content)
}

/// A version-2 CRL (RFC 5280 §5.1) of `issuer` with no entries and a junk signature: OpenSSL
/// and Folioxide decode the CRLs of a timestamp token, neither verifies them.
pub fn test_crl(issuer: &[u8]) -> Vec<u8> {
    let algorithm = der(
        0x30,
        &[
            der(
                0x06,
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
            ),
            vec![0x05, 0x00],
        ]
        .concat(),
    );
    let tbs = der(
        0x30,
        &[
            der(0x02, &[1]),
            algorithm.clone(),
            issuer.to_vec(),
            der(0x17, b"261001000000Z"),
            der(0x17, b"261101000000Z"),
        ]
        .concat(),
    );
    der(0x30, &[tbs, algorithm, der(0x03, &[0, 1, 2, 3])].concat())
}
