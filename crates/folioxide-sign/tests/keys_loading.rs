//! Key loading (M3 brief §3.1 "Key loading", §6.2 "keys"): PKCS#12 in its modern and legacy
//! flavours, PEM keys in every supported format, the key/certificate checks, and the error
//! mapping and hygiene rules.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod cms_support;

use cms_support::{PASSWORD, cert_der, fixture, fixture_str, pem_signer};
use folioxide_sign::algorithms::{DigestAlgorithm, KeyKind, SignatureAlgorithm};
use folioxide_sign::cms;
use folioxide_sign::signer::{LocalSigner, Signer};
use folioxide_sign::{Error, keys};
use folioxide_syntax::ErrorCode;

/// Signs and verifies with `signer`'s own certificate: the key really belongs to `chain[0]`.
fn assert_signs(signer: &LocalSigner) {
    let digest = folioxide_sign::algorithms::default_digest(signer.key_kind());
    let tbs = b"folioxide key loading";
    let signature = signer.sign(digest, tbs).unwrap();
    cms::verify_raw(
        &signer.certificate_chain()[0],
        signer.algorithm(),
        digest,
        tbs,
        &signature,
    )
    .unwrap();
}

fn p12(name: &str) -> Vec<u8> {
    fixture(&format!("pki/{name}"))
}

/// The leaf, intermediate and root, in that order, from a PKCS#12 of the test PKI.
fn assert_p12_chain(signer: &LocalSigner, leaf: &str) {
    let chain = signer.certificate_chain();
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0], cert_der(&format!("pki/{leaf}.pem")));
    assert_eq!(chain[1], cert_der("pki/intermediate.pem"));
    assert_eq!(chain[2], cert_der("pki/root.pem"));
}

#[test]
fn pkcs12_modern_aes() {
    let signer = LocalSigner::from_pkcs12(&p12("signer-rsa2048-modern.p12"), PASSWORD).unwrap();
    assert_eq!(signer.key_kind(), KeyKind::Rsa { bits: 2048 });
    assert_eq!(signer.algorithm(), SignatureAlgorithm::RsaPkcs1v15);
    assert_p12_chain(&signer, "signer-rsa2048");
    assert_signs(&signer);
}

#[test]
fn pkcs12_legacy_3des() {
    // The tests build the crate with `pkcs12-legacy` (dev-dependency features).
    let signer = LocalSigner::from_pkcs12(&p12("signer-rsa2048-3des.p12"), PASSWORD).unwrap();
    assert_eq!(signer.key_kind(), KeyKind::Rsa { bits: 2048 });
    assert_p12_chain(&signer, "signer-rsa2048");
    assert_signs(&signer);
}

#[test]
fn pkcs12_legacy_rc2_40() {
    let signer = LocalSigner::from_pkcs12(&p12("signer-rsa2048-rc2-40.p12"), PASSWORD).unwrap();
    assert_eq!(signer.key_kind(), KeyKind::Rsa { bits: 2048 });
    assert_p12_chain(&signer, "signer-rsa2048");
    assert_signs(&signer);
}

#[test]
fn pkcs12_p256_modern() {
    let signer = LocalSigner::from_pkcs12(&p12("signer-p256-modern.p12"), PASSWORD).unwrap();
    assert_eq!(signer.key_kind(), KeyKind::EcP256);
    assert_eq!(signer.algorithm(), SignatureAlgorithm::Ecdsa);
    assert_p12_chain(&signer, "signer-p256");
    assert_signs(&signer);
}

#[test]
fn pkcs12_without_mac_loads() {
    let signer =
        LocalSigner::from_pkcs12(&fixture("sign/signer-p256-nomac.p12"), PASSWORD).unwrap();
    assert_eq!(signer.key_kind(), KeyKind::EcP256);
    assert_eq!(
        signer.certificate_chain()[0],
        cert_der("pki/signer-p256.pem")
    );
    assert_signs(&signer);
}

#[test]
fn pkcs12_wrong_password_code() {
    for name in [
        "pki/signer-rsa2048-modern.p12",
        "pki/signer-rsa2048-3des.p12",
        "pki/signer-rsa2048-rc2-40.p12",
        "pki/signer-p256-modern.p12",
        // No MAC: the wrong password shows only when the bags do not decrypt.
        "sign/signer-p256-nomac.p12",
    ] {
        for password in ["wrong", "", "Folioxide"] {
            let err = LocalSigner::from_pkcs12(&fixture(name), password).unwrap_err();
            assert!(
                matches!(err, Error::WrongPassword),
                "{name} {password:?}: {err:?}"
            );
            assert_eq!(err.code(), ErrorCode::WrongPassword);
        }
    }
}

#[test]
fn pkcs12_garbage_key_load() {
    let modern = p12("signer-rsa2048-modern.p12");
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"definitely not a PKCS#12 file".to_vec(),
        vec![0x30, 0x03, 0x02, 0x01, 0x03],
        modern[..modern.len() / 2].to_vec(),
        fixture_str("pki/signer-rsa2048.pem").into_bytes(),
    ];
    for bytes in cases {
        let err = LocalSigner::from_pkcs12(&bytes, PASSWORD).unwrap_err();
        assert_eq!(err.code(), ErrorCode::KeyLoad, "{err:?}");
    }
}

#[test]
fn pem_pkcs8_plain() {
    for (name, kind) in [
        ("rsa2048", KeyKind::Rsa { bits: 2048 }),
        ("rsa3072", KeyKind::Rsa { bits: 3072 }),
        ("p256", KeyKind::EcP256),
        ("p384", KeyKind::EcP384),
    ] {
        let signer = pem_signer(name);
        assert_eq!(signer.key_kind(), kind, "{name}");
        assert_eq!(
            signer.certificate_chain(),
            [
                cert_der(&format!("pki/signer-{name}.pem")),
                cert_der("pki/intermediate.pem")
            ]
        );
        assert_signs(&signer);
    }
}

#[test]
fn pem_pkcs8_encrypted() {
    for name in ["rsa2048", "rsa3072", "p256", "p384"] {
        let signer = LocalSigner::from_pem(
            &fixture_str(&format!("pki/signer-{name}.key.enc.pem")),
            &fixture_str(&format!("pki/signer-{name}.pem")),
            Some(PASSWORD),
        )
        .unwrap();
        assert_eq!(signer.certificate_chain().len(), 1);
        assert_signs(&signer);
    }
}

#[test]
fn pem_pkcs8_encrypted_wrong_password() {
    for name in ["rsa2048", "p256"] {
        for password in ["wrong", "", "folioxide "] {
            let err = LocalSigner::from_pem(
                &fixture_str(&format!("pki/signer-{name}.key.enc.pem")),
                &fixture_str(&format!("pki/signer-{name}.pem")),
                Some(password),
            )
            .unwrap_err();
            assert!(
                matches!(err, Error::WrongPassword),
                "{name} {password:?}: {err:?}"
            );
        }
    }
}

#[test]
fn pem_encrypted_without_password_requires_password() {
    let err = LocalSigner::from_pem(
        &fixture_str("pki/signer-p384.key.enc.pem"),
        &fixture_str("pki/signer-p384.pem"),
        None,
    )
    .unwrap_err();
    assert!(matches!(err, Error::PasswordRequired), "{err:?}");
    assert_eq!(err.code(), ErrorCode::PasswordRequired);
}

#[test]
fn pem_pkcs1_rsa() {
    for (name, bits) in [("rsa2048", 2048), ("rsa3072", 3072)] {
        let key = fixture_str(&format!("pki/signer-{name}.key.pkcs1.pem"));
        assert!(key.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        let signer =
            LocalSigner::from_pem(&key, &fixture_str(&format!("pki/signer-{name}.pem")), None)
                .unwrap();
        assert_eq!(signer.key_kind(), KeyKind::Rsa { bits });
        assert_signs(&signer);
    }
}

#[test]
fn pem_sec1_ec() {
    for (name, kind) in [("p256", KeyKind::EcP256), ("p384", KeyKind::EcP384)] {
        let key = fixture_str(&format!("pki/signer-{name}.key.sec1.pem"));
        assert!(key.starts_with("-----BEGIN EC PRIVATE KEY-----"));
        let signer =
            LocalSigner::from_pem(&key, &fixture_str(&format!("pki/signer-{name}.pem")), None)
                .unwrap();
        assert_eq!(signer.key_kind(), kind);
        assert_signs(&signer);
    }
}

#[test]
fn pem_chain_reordered_leaf_first() {
    // The signer certificate is last, with OpenSSL-style text around the blocks.
    let certs = format!(
        "subject=CN=Folioxide Test Intermediate CA\n{}\nsubject=CN=Folioxide Test Root CA\n{}\n{}",
        fixture_str("pki/intermediate.pem"),
        fixture_str("pki/root.pem"),
        fixture_str("pki/signer-p256.pem"),
    );
    let signer =
        LocalSigner::from_pem(&fixture_str("pki/signer-p256.key.pem"), &certs, None).unwrap();
    assert_eq!(
        signer.certificate_chain(),
        [
            cert_der("pki/signer-p256.pem"),
            cert_der("pki/intermediate.pem"),
            cert_der("pki/root.pem"),
        ]
    );
    assert_signs(&signer);
}

#[test]
fn key_cert_mismatch_rejected() {
    // PEM: no certificate matches the key.
    let err = LocalSigner::from_pem(
        &fixture_str("pki/signer-p256.key.pem"),
        &(fixture_str("pki/signer-p384.pem") + &fixture_str("pki/intermediate.pem")),
        None,
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::KeyLoad, "{err:?}");

    // PKCS#8 DER: chain[0] must be the key's certificate, even if a later one matches.
    let key_der = pem_der(&fixture_str("pki/signer-rsa2048.key.pem"));
    for chain in [
        vec![cert_der("pki/signer-rsa3072.pem")],
        vec![
            cert_der("pki/intermediate.pem"),
            cert_der("pki/signer-rsa2048.pem"),
        ],
        vec![],
    ] {
        let err = LocalSigner::from_pkcs8_der(&key_der, chain).unwrap_err();
        assert_eq!(err.code(), ErrorCode::KeyLoad, "{err:?}");
    }
    let ok =
        LocalSigner::from_pkcs8_der(&key_der, vec![cert_der("pki/signer-rsa2048.pem")]).unwrap();
    assert_signs(&ok);

    // A first certificate that is not a certificate.
    let err = LocalSigner::from_pkcs8_der(&key_der, vec![vec![0x30, 0x00]]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::Certificate, "{err:?}");
}

#[test]
fn rsa_below_2048_rejected() {
    let err = LocalSigner::from_pem(
        &fixture_str("sign/rsa1024.key.pem"),
        &fixture_str("pki/signer-rsa2048.pem"),
        None,
    )
    .unwrap_err();
    assert!(
        matches!(&err, Error::KeyLoad(m) if m.contains("1024")),
        "{err:?}"
    );
}

#[test]
fn unsupported_keys_and_encryptions() {
    let cert = fixture_str("pki/signer-p256.pem");
    for (key, password) in [
        ("sign/p521.key.pem", None),
        ("sign/ed25519.key.pem", None),
        // Legacy OpenSSL PEM encryption (Proc-Type: 4,ENCRYPTED).
        ("sign/signer-rsa2048.key.legacy-enc.pem", Some(PASSWORD)),
        // PBES1 (PBE-SHA1-3DES) encrypted PKCS#8.
        ("sign/signer-p256.key.pbes1.pem", Some(PASSWORD)),
    ] {
        let err = LocalSigner::from_pem(&fixture_str(key), &cert, password).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported, "{key}: {err:?}");
    }
}

#[test]
fn garbage_pem_is_key_load() {
    let cert = fixture_str("pki/signer-p256.pem");
    for key in [
        "",
        "no key here",
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        "-----BEGIN EC PRIVATE KEY-----\n!!!!\n-----END EC PRIVATE KEY-----\n",
    ] {
        let err = LocalSigner::from_pem(key, &cert, None).unwrap_err();
        assert_eq!(err.code(), ErrorCode::KeyLoad, "{key:?}: {err:?}");
    }
    let err =
        LocalSigner::from_pkcs8_der(b"garbage", vec![cert_der("pki/signer-p256.pem")]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::KeyLoad);
    let err = LocalSigner::from_pem(&fixture_str("pki/signer-p256.key.pem"), "no certs", None)
        .unwrap_err();
    assert_eq!(err.code(), ErrorCode::Certificate);
}

#[test]
fn certificates_from_pem_reads_every_block_in_order() {
    let text = format!(
        "garbage\n{}{}\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n{}",
        fixture_str("pki/root.pem"),
        fixture_str("pki/signer-rsa2048.key.pem"),
        fixture_str("pki/intermediate.pem")
    );
    let certs = keys::certificates_from_pem(&text).unwrap();
    assert_eq!(
        certs,
        [cert_der("pki/root.pem"), cert_der("pki/intermediate.pem")]
    );
    let crlf = fixture_str("pki/tsa.pem").replace('\n', "\r\n");
    assert_eq!(
        keys::certificates_from_pem(&crlf).unwrap(),
        [cert_der("pki/tsa.pem")]
    );
}

#[test]
fn error_messages_never_contain_password() {
    const SECRET: &str = "S3cr3t-Pa55w0rd-Folioxide!";
    let key_body: String = fixture_str("pki/signer-rsa2048.key.pem")
        .lines()
        .nth(1)
        .unwrap()
        .to_owned();
    let mut errors: Vec<Error> = Vec::new();
    for p12 in [
        "pki/signer-rsa2048-modern.p12",
        "pki/signer-rsa2048-3des.p12",
        "pki/signer-rsa2048-rc2-40.p12",
        "sign/signer-p256-nomac.p12",
    ] {
        errors.push(LocalSigner::from_pkcs12(&fixture(p12), SECRET).unwrap_err());
    }
    errors.push(LocalSigner::from_pkcs12(b"junk", SECRET).unwrap_err());
    for key in [
        "pki/signer-rsa2048.key.enc.pem",
        "sign/signer-rsa2048.key.legacy-enc.pem",
        "sign/signer-p256.key.pbes1.pem",
    ] {
        errors.push(
            LocalSigner::from_pem(
                &fixture_str(key),
                &fixture_str("pki/signer-p256.pem"),
                Some(SECRET),
            )
            .unwrap_err(),
        );
    }
    // A key that loads but matches no certificate, and a too-small key.
    errors.push(
        LocalSigner::from_pem(
            &fixture_str("pki/signer-rsa2048.key.pem"),
            &fixture_str("pki/signer-p256.pem"),
            Some(SECRET),
        )
        .unwrap_err(),
    );
    errors.push(
        LocalSigner::from_pem(
            &fixture_str("sign/rsa1024.key.pem"),
            &fixture_str("pki/signer-p256.pem"),
            Some(SECRET),
        )
        .unwrap_err(),
    );
    assert_eq!(errors.len(), 10);
    for err in &errors {
        for text in [err.to_string(), format!("{err:?}")] {
            assert!(!text.contains(SECRET), "password in {text}");
            assert!(!text.contains(&key_body), "key bytes in {text}");
        }
    }

    // A signer's Debug shows the key kind and subject only.
    let signer = pem_signer("rsa2048");
    let debug = format!("{signer:?}");
    assert!(debug.contains("Rsa") && debug.contains("CN=Folioxide Test Signer RSA-2048"));
    assert!(!debug.contains(&key_body), "{debug}");
}

#[test]
fn sha1_is_never_used_to_sign() {
    for name in ["rsa2048", "p256"] {
        let err = pem_signer(name)
            .sign(DigestAlgorithm::Sha1, b"x")
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidArgument);
    }
}

/// The DER inside a single-block PEM.
fn pem_der(text: &str) -> Vec<u8> {
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    base64_decode(&body)
}

fn base64_decode(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in text
        .bytes()
        .filter(|&b| b != b'=' && !b.is_ascii_whitespace())
    {
        let value = ALPHABET.iter().position(|&c| c == byte).unwrap() as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

// ---- Hostile key-derivation parameters (M3 brief R-18) ----

/// A DER TLV with a definite length.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn oid(dotted: &str) -> Vec<u8> {
    use der::Encode;
    der::asn1::ObjectIdentifier::new(dotted)
        .unwrap()
        .to_der()
        .unwrap()
}

/// `ContentInfo { id-data, [0] EXPLICIT OCTET STRING content }` (RFC 7292 §4.1).
fn data_content_info(content: &[u8]) -> Vec<u8> {
    let mut body = oid("1.2.840.113549.1.7.1");
    body.extend(tlv(0xA0, &tlv(0x04, content)));
    tlv(0x30, &body)
}

/// A MAC-less PFX whose only bag is a `pkcs8ShroudedKeyBag` holding `encrypted_key_info`
/// (RFC 7292 §4.2.2), in plain `data` content, so nothing protects the parameters.
fn pfx_with_shrouded_key_bag(encrypted_key_info: &[u8]) -> Vec<u8> {
    let mut bag = oid("1.2.840.113549.1.12.10.1.2");
    bag.extend(tlv(0xA0, encrypted_key_info));
    let safe_contents = tlv(0x30, &tlv(0x30, &bag));
    let authenticated_safe = tlv(0x30, &data_content_info(&safe_contents));
    let mut pfx = tlv(0x02, &[3]);
    pfx.extend(data_content_info(&authenticated_safe));
    tlv(0x30, &pfx)
}

/// An `EncryptedPrivateKeyInfo` with these PBES2 key-derivation parameters (AES-256-CBC over 48
/// zero bytes).
fn encrypted_key_info(kdf: pkcs8::pkcs5::pbes2::Kdf) -> Vec<u8> {
    use der::Encode;
    use pkcs8::pkcs5::pbes2;
    let params = pbes2::Parameters {
        kdf,
        encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: [9; 16] },
    };
    pkcs8::EncryptedPrivateKeyInfoOwned {
        encryption_algorithm: params.into(),
        encrypted_data: der::asn1::OctetString::new(vec![0u8; 48]).unwrap(),
    }
    .to_der()
    .unwrap()
}

fn scrypt_kdf(n: u64, r: u16, p: u16) -> pkcs8::pkcs5::pbes2::Kdf {
    use pkcs8::pkcs5::pbes2::{Kdf, Salt, ScryptParams};
    Kdf::Scrypt(ScryptParams {
        salt: Salt::new([7u8; 16]).unwrap(),
        cost_parameter: n,
        block_size: r,
        parallelization: p,
        key_length: None,
    })
}

fn pbkdf2_kdf(iteration_count: u32) -> pkcs8::pkcs5::pbes2::Kdf {
    use pkcs8::pkcs5::pbes2::{Kdf, Pbkdf2Params, Pbkdf2Prf, Salt};
    Kdf::Pbkdf2(Pbkdf2Params {
        salt: Salt::new([7u8; 16]).unwrap(),
        iteration_count,
        key_length: None,
        prf: Pbkdf2Prf::HmacWithSha256,
    })
}

/// Encrypted PEM keys with excessive or invalid key-derivation parameters are refused before
/// any derivation runs, through the public entry point (the unit tests in `keys` cover every
/// boundary). Before the fix, scrypt N = 0 panicked inside `pkcs5`.
#[test]
fn pem_hostile_kdf_parameters_are_refused() {
    let certs = fixture_str("pki/signer-p256.pem");
    for (what, kdf) in [
        ("PBKDF2 2^32-1 iterations", pbkdf2_kdf(u32::MAX)),
        ("PBKDF2 11M iterations", pbkdf2_kdf(11_000_000)),
        ("scrypt 2 GiB", scrypt_kdf(1 << 21, 8, 1)),
        ("scrypt 64 GiB of work", scrypt_kdf(1 << 14, 8, u16::MAX)),
        ("scrypt N = 0", scrypt_kdf(0, 8, 1)),
        ("scrypt r = 0", scrypt_kdf(1 << 10, 0, 1)),
    ] {
        let der = encrypted_key_info(kdf);
        let pem = der::pem::encode_string("ENCRYPTED PRIVATE KEY", der::pem::LineEnding::LF, &der)
            .unwrap();
        let err = LocalSigner::from_pem(&pem, &certs, Some(PASSWORD)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::KeyLoad, "{what}: {err:?}");
    }
}

/// The same for PKCS#12: `p12-keystore` caps PBKDF2 at 1 000 000 iterations and scrypt at
/// 1 GiB, but passes scrypt N = 0 to `pkcs5`, which panicked (a MAC-less file needs no
/// password to reach it). Folioxide refuses the parameters before `p12-keystore` runs.
#[test]
fn pkcs12_hostile_kdf_parameters_are_refused() {
    for (what, kdf) in [
        ("PBKDF2 2^32-1 iterations", pbkdf2_kdf(u32::MAX)),
        ("scrypt 2 GiB", scrypt_kdf(1 << 21, 8, 1)),
        ("scrypt 64 GiB of work", scrypt_kdf(1 << 14, 8, u16::MAX)),
        ("scrypt N = 0", scrypt_kdf(0, 8, 1)),
        ("scrypt N = 1", scrypt_kdf(1, 8, 1)),
        ("scrypt p = 0", scrypt_kdf(1 << 10, 8, 0)),
    ] {
        let key_info = encrypted_key_info(kdf);
        let pfx = pfx_with_shrouded_key_bag(&key_info);
        let err = LocalSigner::from_pkcs12(&pfx, PASSWORD).unwrap_err();
        assert_eq!(err.code(), ErrorCode::KeyLoad, "{what}: {err:?}");
        // The same parameters as the content-encryption algorithm of an `encryptedData`.
        let pfx = pfx_with_encrypted_data(&key_info_algorithm(&key_info), &[0u8; 48]);
        let err = LocalSigner::from_pkcs12(&pfx, PASSWORD).unwrap_err();
        assert_eq!(
            err.code(),
            ErrorCode::KeyLoad,
            "{what} (encryptedData): {err:?}"
        );
    }
}

/// Parameters that only show once an `encryptedData` is decrypted with the right password
/// (here a key bag with scrypt N = 0 inside a PBKDF2/AES-256-CBC container) are out of the
/// scan's reach; the panic they cause in `pkcs5` is caught and reported as `KeyLoad`.
#[test]
fn pkcs12_hidden_hostile_kdf_parameters_are_key_load() {
    use der::Encode;
    use pkcs8::pkcs5::pbes2;
    let mut bag = oid("1.2.840.113549.1.12.10.1.2");
    bag.extend(tlv(0xA0, &encrypted_key_info(scrypt_kdf(0, 8, 1))));
    let safe_contents = tlv(0x30, &tlv(0x30, &bag));
    let container = pbes2::Parameters {
        kdf: pbkdf2_kdf(2048),
        encryption: pbes2::EncryptionScheme::Aes256Cbc { iv: [5; 16] },
    };
    let ciphertext = container.encrypt(PASSWORD, &safe_contents).unwrap();
    let algorithm = pkcs8::pkcs5::EncryptionScheme::from(container)
        .to_der()
        .unwrap();
    let pfx = pfx_with_encrypted_data(&algorithm, &ciphertext);
    let err = LocalSigner::from_pkcs12(&pfx, PASSWORD).unwrap_err();
    assert_eq!(err.code(), ErrorCode::KeyLoad, "{err:?}");
    // With a wrong password the container does not decrypt, so the bag is never reached.
    let err = LocalSigner::from_pkcs12(&pfx, "wrong").unwrap_err();
    assert_eq!(err.code(), ErrorCode::WrongPassword, "{err:?}");
}

/// The `AlgorithmIdentifier` that starts an `EncryptedPrivateKeyInfo` (RFC 5958 §3).
fn key_info_algorithm(encrypted_key_info: &[u8]) -> Vec<u8> {
    use der::{Decode, Encode};
    pkcs8::EncryptedPrivateKeyInfoRef::from_der(encrypted_key_info)
        .unwrap()
        .encryption_algorithm
        .to_der()
        .unwrap()
}

/// A MAC-less PFX whose only content is an `encryptedData` (RFC 7292 §4.1, RFC 5652 §8) with
/// this content-encryption `algorithm` and `ciphertext`.
fn pfx_with_encrypted_data(algorithm: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut content_info = oid("1.2.840.113549.1.7.1");
    content_info.extend_from_slice(algorithm);
    content_info.extend(tlv(0x80, ciphertext));
    let mut encrypted_data = tlv(0x02, &[0]);
    encrypted_data.extend(tlv(0x30, &content_info));
    let mut outer = oid("1.2.840.113549.1.7.6");
    outer.extend(tlv(0xA0, &tlv(0x30, &encrypted_data)));
    let authenticated_safe = tlv(0x30, &tlv(0x30, &outer));
    let mut pfx = tlv(0x02, &[3]);
    pfx.extend(data_content_info(&authenticated_safe));
    tlv(0x30, &pfx)
}
