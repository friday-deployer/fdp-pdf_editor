//! M0 dependency spike (ROADMAP WP0.1): the pinned RustCrypto stack (`der` 0.8.2, `x509-cert`
//! 0.3.0, `cms` =0.3.0-pre.1, `rsa` =0.10.0-rc.19) and `p12-keystore` 0.4.0 resolve to a single
//! graph and interoperate at runtime.
//!
//! The certificate below is a throwaway, self-signed RSA-2048 certificate made only for this test
//! (the private key was discarded). It was generated with OpenSSL 3.0.13:
//!
//! ```text
//! openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -sha256 -set_serial 1 \
//!   -days 36500 -subj "/O=Folioxide/CN=Folioxide M0 dependency spike (test only)"
//! ```

// clippy.toml relaxes these lints only inside `#[test]` functions and `#[cfg(test)]` modules, not
// in helper functions of an integration-test crate. A failing `expect` is how a test fails.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::ObjectIdentifier;
use der::{Decode, DecodePem, Encode};
use p12_keystore::{KeyStore, KeyStoreEntry, Pkcs12ImportPolicy};
use rsa::RsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use x509_cert::Certificate;

const SPIKE_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDYDCCAkigAwIBAgIBATANBgkqhkiG9w0BAQsFADBIMRIwEAYDVQQKDAlGb2xp
b3hpZGUxMjAwBgNVBAMMKUZvbGlveGlkZSBNMCBkZXBlbmRlbmN5IHNwaWtlICh0
ZXN0IG9ubHkpMCAXDTI2MTAxMDAyNTcwMFoYDzIxMjYwOTE2MDI1NzAwWjBIMRIw
EAYDVQQKDAlGb2xpb3hpZGUxMjAwBgNVBAMMKUZvbGlveGlkZSBNMCBkZXBlbmRl
bmN5IHNwaWtlICh0ZXN0IG9ubHkpMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA2snn5J7MWmeW0kDGkxoKvBxoQj4DrD7Zd823xqxDLyS1weA/RKQL94ng
JAp6IqE7GN0InwRZ6CtiXW7DmnBqrziIWL5o1ahFgBZxsBj0dvepc/0LCcQKi1EI
U2f7MC6ae1i2jtZICjpI86G9sEBA7lPyLToQQbTb6X0hu9NyqxpYfHHmsfxskRa+
IdTWK+pVtDNgzF1xapUzKeuiTxxHVoYiF/5N8ocy+Zzp61Xg+oRUooJpcJ4Xgt3s
CBDTUqJuOT5NGAu9VtIKatOey9An2W8iHdiCS+QgZMmfa/mdc/l6XkqNdDNE5pBi
VPUhELXTJM0n7mt0X6Y3nnQfj+fDCwIDAQABo1MwUTAdBgNVHQ4EFgQUWozAYIN2
EirToSdWbjJjyOg7kFcwHwYDVR0jBBgwFoAUWozAYIN2EirToSdWbjJjyOg7kFcw
DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAD3ZjakLaj9Rek4lk
z4Pf6d9dGHDG9mYxOk+aOMCfOjj1ThcHstemK9nnkJOx5TrDT+I0ISaNtVqkdTLg
vjpIqwxuIOy6gGLlRA4newCxrjsSbG9pvAsDG+G6x/fWKuQkVvOHJT3zpUYBUEQP
6qx7aU94zf8l3CO/MszUpHvPfsaX1ha7IUaKgvk9C1GL9jwmloczKY7uudqo7cTN
RxicNFUkgeVI7oOgMO7Obkvd8I5xnAvxJFGeiYcBHT5Jma+Teio/v4Q2gYncQvkJ
+2117g8cbi2/FOb4ozhGXr7O3PC8++pysIHGbSwLGf7KsiNYEnhBXnoMmHlvsYG+
1YZc0A==
-----END CERTIFICATE-----
";

/// RFC 5652 §5.1 `id-signedData`.
const ID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

fn spike_cert() -> Certificate {
    Certificate::from_pem(SPIKE_CERT_PEM).expect("x509-cert parses the spike certificate")
}

/// `cms` and `x509-cert` share one `der`: a `x509_cert::Certificate` goes straight into a CMS
/// `CertificateChoices`, and the result survives a DER round trip.
#[test]
fn cms_wraps_x509_certificate_and_round_trips() {
    let cert = spike_cert();

    // A certs-only SignedData (RFC 5652 §5): the same structure the PAdES signer will fill.
    let content_info = ContentInfo::try_from(cert.clone()).expect("certs-only SignedData");
    let encoded = content_info.to_der().expect("ContentInfo encodes");
    let decoded = ContentInfo::from_der(&encoded).expect("ContentInfo decodes");
    assert_eq!(decoded, content_info);
    assert_eq!(
        decoded.content_type,
        ObjectIdentifier::new_unwrap(ID_SIGNED_DATA)
    );

    let signed_data: SignedData = decoded.content.decode_as().expect("SignedData decodes");
    let certificates = signed_data.certificates.expect("certificates [0] present");
    let choices: Vec<&CertificateChoices> = certificates.0.iter().collect();
    assert_eq!(choices.len(), 1);
    match choices[0] {
        CertificateChoices::Certificate(embedded) => assert_eq!(embedded, &cert),
        other => panic!("unexpected certificate choice {other:?}"),
    }
}

/// `rsa` reads the subject public key that `x509-cert` parsed (shared `spki`/`der`).
#[test]
fn rsa_reads_certificate_public_key() {
    let cert = spike_cert();
    let spki_der = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .expect("SPKI encodes");
    let key = RsaPublicKey::from_public_key_der(&spki_der).expect("rsa decodes the SPKI");
    assert_eq!(key.size(), 256, "RSA-2048 modulus is 256 bytes");
}

/// `p12-keystore` parses the same certificate and writes and reads a PKCS#12 store with the
/// modern defaults (PBES2 with AES-256, HMAC-SHA-256).
#[test]
fn p12_keystore_round_trip() {
    let cert_der = spike_cert().to_der().expect("certificate encodes");
    let p12_cert = p12_keystore::Certificate::from_der(&cert_der).expect("p12-keystore parses");
    assert!(p12_cert.subject().contains("Folioxide M0 dependency spike"));

    let mut store = KeyStore::new();
    store.add_entry("spike", KeyStoreEntry::Certificate(p12_cert));
    let pfx = store
        .writer("folioxide")
        .encryption_iterations(2048)
        .mac_iterations(2048)
        .write()
        .expect("PKCS#12 writes");

    let reopened = KeyStore::from_pkcs12(&pfx, "folioxide", Pkcs12ImportPolicy::Raw)
        .expect("PKCS#12 reads back with the right password");
    let entries: Vec<_> = reopened.entries().collect();
    assert_eq!(entries.len(), 1);
    match entries[0].1 {
        KeyStoreEntry::Certificate(read_back) => assert_eq!(read_back.as_der(), cert_der),
        other => panic!("unexpected keystore entry {other:?}"),
    }

    assert!(
        KeyStore::from_pkcs12(&pfx, "wrong password", Pkcs12ImportPolicy::Raw).is_err(),
        "a wrong password must be rejected"
    );
}
