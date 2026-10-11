//! Certificate information (M3 brief §3.1 `x509info`, §6.2 "certificates and trust"):
//! `certificate_info` and `certificate_key_kind` on every certificate of the test PKI.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod cms_support;

use std::process::Command;

use cms_support::{cert_der, der_children, der_split, fixtures_dir, openssl_available};
use folioxide_sign::algorithms::{DigestAlgorithm, KeyKind};
use folioxide_sign::x509info::{self, KeyDescription};
use folioxide_syntax::ErrorCode;

const TEST_PKI: &str = "OU=TEST ONLY - DO NOT TRUST,O=Folioxide Test PKI";

/// The serial number of a certificate, uppercase hex without leading zero octets.
fn serial_of(der: &[u8]) -> String {
    let tbs = der_children(der)[0].1.clone();
    let fields = der_children(&tbs);
    let serial = &fields[usize::from(fields[0].0 == 0xA0)].1;
    der_split(serial)
        .1
        .iter()
        .skip_while(|&&b| b == 0)
        .map(|b| format!("{b:02X}"))
        .collect()
}

#[test]
fn certificate_info_fields() {
    let der = cert_der("pki/signer-rsa2048.pem");
    let info = x509info::certificate_info(&der).unwrap();
    // RFC 4514 order, most specific first: what pdfsig prints and the Node test expects.
    assert_eq!(
        info.subject,
        format!("CN=Folioxide Test Signer RSA-2048,{TEST_PKI}")
    );
    assert_eq!(
        info.issuer,
        format!("CN=Folioxide Test Intermediate CA,{TEST_PKI}")
    );
    assert_eq!(
        info.common_name.as_deref(),
        Some("Folioxide Test Signer RSA-2048")
    );
    assert_eq!(info.serial_hex, serial_of(&der));
    assert!(
        info.serial_hex
            .chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
    );
    assert!(!info.serial_hex.starts_with("00"));
    assert_eq!(info.not_before, "2025-01-01T00:00:00Z");
    // After 2049: GeneralizedTime (RFC 5280 §4.1.2.5).
    assert_eq!(info.not_after, "2075-12-31T23:59:59Z");
    let sha256: String = DigestAlgorithm::Sha256
        .digest(&[&der])
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(info.sha256_hex, sha256);
    assert_eq!(info.key, KeyDescription::new("rsa", 2048, None));
    assert_eq!(info.key_usage, ["digitalSignature", "nonRepudiation"]);
    assert!(info.ext_key_usage.is_empty());
    assert!(!info.is_ca);
    assert_eq!(info.der, der);

    // Compare the serial and fingerprint with OpenSSL when it is available.
    if openssl_available() {
        let output = Command::new("openssl")
            .args([
                "x509",
                "-noout",
                "-serial",
                "-fingerprint",
                "-sha256",
                "-in",
            ])
            .arg(fixtures_dir().join("pki/signer-rsa2048.pem"))
            .output()
            .unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        let serial = text
            .lines()
            .find_map(|l| l.strip_prefix("serial="))
            .unwrap();
        assert_eq!(
            serial.trim_start_matches('0'),
            info.serial_hex.trim_start_matches('0')
        );
        let fingerprint = text
            .lines()
            .find_map(|l| l.split_once("Fingerprint=").map(|(_, f)| f))
            .unwrap();
        assert_eq!(fingerprint.replace(':', "").to_lowercase(), info.sha256_hex);
    }
}

#[test]
fn certificate_info_for_every_pki_certificate() {
    struct Expect {
        file: &'static str,
        cn: &'static str,
        key: KeyDescription,
        kind: Option<KeyKind>,
        key_usage: &'static [&'static str],
        eku: &'static [&'static str],
        is_ca: bool,
        not_after: &'static str,
    }
    let signer_ku: &[&str] = &["digitalSignature", "nonRepudiation"];
    let ca_ku: &[&str] = &["keyCertSign", "cRLSign"];
    let cases = [
        Expect {
            file: "root",
            cn: "Folioxide Test Root CA",
            key: KeyDescription::new("rsa", 3072, None),
            kind: Some(KeyKind::Rsa { bits: 3072 }),
            key_usage: ca_ku,
            eku: &[],
            is_ca: true,
            not_after: "2075-12-31T23:59:59Z",
        },
        Expect {
            file: "intermediate",
            cn: "Folioxide Test Intermediate CA",
            key: KeyDescription::new("ec", 384, Some("P-384")),
            kind: Some(KeyKind::EcP384),
            key_usage: ca_ku,
            eku: &[],
            is_ca: true,
            not_after: "2075-12-31T23:59:59Z",
        },
        Expect {
            file: "signer-rsa3072",
            cn: "Folioxide Test Signer RSA-3072",
            key: KeyDescription::new("rsa", 3072, None),
            kind: Some(KeyKind::Rsa { bits: 3072 }),
            key_usage: signer_ku,
            eku: &[],
            is_ca: false,
            not_after: "2075-12-31T23:59:59Z",
        },
        Expect {
            file: "signer-p256",
            cn: "Folioxide Test Signer P-256",
            key: KeyDescription::new("ec", 256, Some("P-256")),
            kind: Some(KeyKind::EcP256),
            key_usage: signer_ku,
            eku: &[],
            is_ca: false,
            not_after: "2075-12-31T23:59:59Z",
        },
        Expect {
            file: "signer-p384",
            cn: "Folioxide Test Signer P-384",
            key: KeyDescription::new("ec", 384, Some("P-384")),
            kind: Some(KeyKind::EcP384),
            key_usage: signer_ku,
            eku: &[],
            is_ca: false,
            not_after: "2075-12-31T23:59:59Z",
        },
        Expect {
            file: "tsa",
            cn: "Folioxide Test TSA",
            key: KeyDescription::new("rsa", 2048, None),
            kind: Some(KeyKind::Rsa { bits: 2048 }),
            key_usage: signer_ku,
            eku: &["1.3.6.1.5.5.7.3.8"],
            is_ca: false,
            not_after: "2075-12-31T23:59:59Z",
        },
        // UTCTime before 2050.
        Expect {
            file: "expired",
            cn: "Folioxide Test Signer (expired)",
            key: KeyDescription::new("rsa", 2048, None),
            kind: Some(KeyKind::Rsa { bits: 2048 }),
            key_usage: signer_ku,
            eku: &[],
            is_ca: false,
            not_after: "2025-12-31T23:59:59Z",
        },
        Expect {
            file: "wrong-ku",
            cn: "Folioxide Test Signer (wrong key usage)",
            key: KeyDescription::new("rsa", 2048, None),
            kind: Some(KeyKind::Rsa { bits: 2048 }),
            key_usage: &["keyEncipherment", "dataEncipherment"],
            eku: &[],
            is_ca: false,
            not_after: "2075-12-31T23:59:59Z",
        },
    ];
    for case in cases {
        let der = cert_der(&format!("pki/{}.pem", case.file));
        let info = x509info::certificate_info(&der).unwrap();
        assert_eq!(
            info.subject,
            format!("CN={},{TEST_PKI}", case.cn),
            "{}",
            case.file
        );
        assert_eq!(info.common_name.as_deref(), Some(case.cn));
        assert_eq!(info.key, case.key, "{}", case.file);
        assert_eq!(info.key.key_kind(), case.kind);
        assert_eq!(info.key_usage, case.key_usage, "{}", case.file);
        assert_eq!(info.ext_key_usage, case.eku, "{}", case.file);
        assert_eq!(info.is_ca, case.is_ca, "{}", case.file);
        assert_eq!(info.not_before, "2025-01-01T00:00:00Z");
        assert_eq!(info.not_after, case.not_after, "{}", case.file);
        assert_eq!(info.serial_hex, serial_of(&der));
        assert_eq!(x509info::certificate_key_kind(&der).ok(), case.kind);
    }
    let root = x509info::certificate_info(&cert_der("pki/root.pem")).unwrap();
    assert_eq!(root.subject, root.issuer, "self-signed");
}

#[test]
fn certificate_info_long_serial_and_errors() {
    let der = cert_der("sign/long-serial.pem");
    let info = x509info::certificate_info(&der).unwrap();
    assert_eq!(
        info.serial_hex,
        "0102030405060708090A0B0C0D0E0F101112131415161718"
    );
    assert_eq!(
        info.subject,
        "CN=Folioxide Long Serial,OU=TEST ONLY - DO NOT TRUST,O=Folioxide Test PKI"
    );
    assert_eq!(
        x509info::certificate_key_kind(&der).unwrap(),
        KeyKind::EcP256
    );

    for bad in [&b""[..], b"junk", &[0x30, 0x00], &der[..der.len() - 1]] {
        let err = x509info::certificate_info(bad).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Certificate);
        let err = x509info::certificate_key_kind(bad).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Certificate);
    }
}
