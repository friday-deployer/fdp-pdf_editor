#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The `sign-bt` oracle suite (M4 brief §6.3): PAdES B-T signatures made by Folioxide, checked
//! by pyHanko (`timestamp_validity` intact, valid and trusted), by `openssl ts -verify -data
//! sigvalue.bin -in token.der -token_in -CAfile fixtures/pki/tsa-root.pem`, by the PAdES profile
//! check and by the structural oracles.
//!
//! Every expect.json `signatures[]` value is written **from Folioxide's own report** (brief §0),
//! so the run is a differential. The two deliberate cases carry the oracles' value for a key
//! where Folioxide is stricter ([`DELIBERATE`]); the Rust test asserts ours.
//!
//! A case is *checked* (brief: at least 8) when its last signature has `pades: "B-T"`,
//! `timestamp: true` and `timestampTrusted: true`.

mod bt_support;

use bt_support::decoys::{self, decoys, issuer_of, reencode_name};
use bt_support::tokens;
use bt_support::*;
use folioxide_model::Rect;
use folioxide_sign::algorithms::DigestAlgorithm;
use folioxide_sign::appearance::SignatureAppearance;
use folioxide_sign::bt::TimestampParams;
use folioxide_sign::docmdp::DocMdpPermissions;
use folioxide_sign::field::SubFilter;
use folioxide_sign::prepare::{PrepareRequest, PreparedSignature, SignatureOptions, prepare};
use folioxide_sign::report::{ModificationLevel, PadesLevel, SignatureKind, SignatureReport};
use folioxide_sign::sign::{SignRequest, sign};
use folioxide_sign::signer::{LocalSigner, Signer};
use folioxide_sign::tsp::{DEFAULT_TSA_RESERVE, Timestamper};
use folioxide_sign::{ProblemCode, cms};
use folioxide_syntax::ErrorCode;
use folioxide_testkit::emit::{emit_file, json_string};
use folioxide_testkit::tsa::{Echo, Ess, MockTsa, MockTsaOptions};
use folioxide_testkit::{EMIT_ENABLED, ExpectJson, emit_case};

/// The suite name.
const SUITE: &str = "sign-bt";

/// The trust root every case names (relative to the repository root).
const TRUST_ROOT: &str = "fixtures/pki/root.pem";

/// One deliberate difference: in case `case`, the expect file carries the oracles' JSON value
/// `oracle` for `key` of the signature at `index`, because Folioxide is stricter (`why`).
struct Deliberate {
    case: &'static str,
    index: usize,
    key: &'static str,
    oracle: &'static str,
    why: &'static str,
}

/// Where Folioxide's report and the oracles deliberately differ (brief §0.1, §6.3).
const DELIBERATE: &[Deliberate] = &[
    Deliberate {
        case: "tst-tsa-eku-noncritical",
        index: 0,
        key: "timestamp",
        oracle: "true",
        why: "a TSA certificate whose timeStamping extended key usage is not critical is not \
              suitable (RFC 3161 §2.3, OpenSSL check_purpose_timestamp_sign; D-4): Folioxide \
              and OpenSSL refuse the token, pyHanko accepts it",
    },
    Deliberate {
        case: "tst-tsa-eku-noncritical",
        index: 0,
        key: "timestampTrusted",
        oracle: "true",
        why: "pyHanko trusts the token of the unsuitable TSA certificate; Folioxide never \
              trusts a token that is not valid",
    },
    Deliberate {
        case: "tst-tsa-eku-noncritical",
        index: 0,
        key: "pades",
        oracle: "\"B-T\"",
        why: "the PAdES profile check is structural (a token attribute is present); Folioxide \
              calls a signature B-T only when its selected token is intact and valid (V8)",
    },
    Deliberate {
        case: "tst-imprint-mismatch",
        index: 0,
        key: "pades",
        oracle: "\"B-T\"",
        why: "the PAdES profile check is structural (a token attribute is present); Folioxide \
              calls a signature B-T only when its selected token is intact and valid (V8)",
    },
    // QA round 4 finding 1: pyHanko calls the token valid (asn1crypto reads the surrogate
    // late and only fails the TSA's path), OpenSSL cannot decode the TSA certificate's subject.
    Deliberate {
        case: "tst-tsa-subject-bmp-surrogate",
        index: 0,
        key: "timestamp",
        oracle: "true",
        why: "the TSA certificate's subject holds a BMPString with a lone surrogate, which \
              OpenSSL cannot convert (ASN1_mbstring_ncopy: illegal characters), so ts -verify \
              refuses the token; pyHanko calls it valid (and untrusted)",
    },
    Deliberate {
        case: "tst-tsa-subject-bmp-surrogate",
        index: 0,
        key: "pades",
        oracle: "\"B-T\"",
        why: "the PAdES profile check is structural (a token attribute is present); Folioxide \
              calls a signature B-T only when its selected token is intact and valid (V8)",
    },
    // QA round 4 finding 5: Folioxide does not process name constraints, so a path whose CA
    // carries one is untrusted even when the path satisfies it (stricter than both).
    Deliberate {
        case: "tst-tsa-ca-name-constraints-satisfied",
        index: 0,
        key: "timestampTrusted",
        oracle: "true",
        why: "the TSA's intermediate carries a non-critical nameConstraints the path satisfies; \
              pyHanko and OpenSSL process it and trust the token, Folioxide does not process \
              name constraints and trusts no path that carries one (brief §0.1)",
    },
    // QA round 5 finding 36: the PAdES profile check is structural.
    Deliberate {
        case: "tst-tsa-spki-pss-pkcs1",
        index: 0,
        key: "pades",
        oracle: "\"B-T\"",
        why: "the PAdES profile check is structural (a token attribute is present); Folioxide \
              calls a signature B-T only when its selected token is intact and valid (V8)",
    },
    // QA round 5 finding 32 (ruling R-22 (a)): OpenSSL's X509_check_akid refuses a wrong
    // authorityCertSerialNumber given alone; pyHanko compares the serial only with an issuer.
    Deliberate {
        case: "tst-tsa-akid-serial-only-wrong",
        index: 0,
        key: "timestampTrusted",
        oracle: "true",
        why: "the TSA certificate's authorityKeyIdentifier holds only an \
              authorityCertSerialNumber that is not the root's serial: OpenSSL refuses the edge \
              (X509_check_akid: authority and issuer serial number mismatch), as Folioxide does; \
              pyHanko compares a serial only together with an authorityCertIssuer and trusts the \
              token (brief §0.1)",
    },
    // Final fix round 2, finding 1: extensions asn1crypto parses (and pyHanko's validator
    // refuses when they do not decode, so the token is untrusted there) and OpenSSL does not
    // decode. Ours: the TSA certificate is unsuitable, so the token is not valid (stricter);
    // timestampTrusted false is equal.
    Deliberate {
        case: "tst-tsa-cert-pkup-junk",
        index: 0,
        key: "timestamp",
        oracle: "true",
        why: "the TSA certificate's privateKeyUsagePeriod extension is a NULL: asn1crypto refuses \
              to parse it, so pyHanko calls the token valid but untrusted, and OpenSSL does not \
              decode the type (OK); Folioxide decodes every extension type either reference \
              decodes and calls the certificate unsuitable (final fix round 2, finding 1)",
    },
    Deliberate {
        case: "tst-tsa-cert-pkup-junk",
        index: 0,
        key: "pades",
        oracle: "\"B-T\"",
        why: "the PAdES profile check is structural (a token attribute is present); Folioxide \
              calls a signature B-T only when its selected token is intact and valid (V8)",
    },
    Deliberate {
        case: "tst-tsa-cert-subjdirattrs-junk",
        index: 0,
        key: "timestamp",
        oracle: "true",
        why: "the TSA certificate's subjectDirectoryAttributes extension is an OBJECT IDENTIFIER: \
              asn1crypto refuses to parse it, so pyHanko calls the token valid but untrusted, and \
              OpenSSL does not decode the type (OK); Folioxide calls the certificate unsuitable \
              (final fix round 2, finding 1)",
    },
    Deliberate {
        case: "tst-tsa-cert-subjdirattrs-junk",
        index: 0,
        key: "pades",
        oracle: "\"B-T\"",
        why: "the PAdES profile check is structural (a token attribute is present); Folioxide \
              calls a signature B-T only when its selected token is intact and valid (V8)",
    },
    Deliberate {
        case: "tst-tsa-cert-tlsfeature-junk",
        index: 0,
        key: "timestamp",
        oracle: "true",
        why: "the TSA certificate's TLS feature extension is empty: asn1crypto refuses to parse \
              it, so pyHanko calls the token valid but untrusted, and OpenSSL does not decode the \
              type (OK); Folioxide calls the certificate unsuitable (final fix round 2, finding 1)",
    },
    Deliberate {
        case: "tst-tsa-cert-tlsfeature-junk",
        index: 0,
        key: "pades",
        oracle: "\"B-T\"",
        why: "the PAdES profile check is structural (a token attribute is present); Folioxide \
              calls a signature B-T only when its selected token is intact and valid (V8)",
    },
    // Final fix round 2, finding 1: a well-formed proxyCertInfo or RFC 3779 block on the TSA
    // certificate. Folioxide does not process them and trusts no path that carries one;
    // pyHanko does not know them and trusts the token.
    Deliberate {
        case: "tst-tsa-cert-proxycertinfo-valid",
        index: 0,
        key: "timestampTrusted",
        oracle: "true",
        why: "the TSA certificate is a proxy certificate (a well-formed proxyCertInfo, RFC 3820): \
              OpenSSL refuses the chain (proxy certificates not allowed) and Folioxide, which \
              does not process proxy certificates, does not trust it; pyHanko does not know the \
              extension and trusts the token (final fix round 2, finding 1)",
    },
    // Final fix round 2, finding 2: RSASSA-PSS-params with a repeated field. The token is not
    // valid for Folioxide, pyHanko and OpenSSL alike; only the structural profile check differs.
    Deliberate {
        case: "tst-tsa-spki-pss-params-dup-salt",
        index: 0,
        key: "pades",
        oracle: "\"B-T\"",
        why: "the PAdES profile check is structural (a token attribute is present); Folioxide \
              calls a signature B-T only when its selected token is intact and valid (V8)",
    },
    Deliberate {
        case: "tst-pss-params-dup-salt",
        index: 0,
        key: "pades",
        oracle: "\"B-T\"",
        why: "the PAdES profile check is structural (a token attribute is present); Folioxide \
              calls a signature B-T only when its selected token is intact and valid (V8)",
    },
    Deliberate {
        case: "tst-pss-params-dup-hash",
        index: 0,
        key: "pades",
        oracle: "\"B-T\"",
        why: "the PAdES profile check is structural (a token attribute is present); Folioxide \
              calls a signature B-T only when its selected token is intact and valid (V8)",
    },
    Deliberate {
        case: "tst-tsa-cert-ipaddrblocks-inherit",
        index: 0,
        key: "timestampTrusted",
        oracle: "true",
        why: "the TSA certificate carries a well-formed RFC 3779 ipAddrBlocks (inherit): OpenSSL \
              validates the resources (an inherited block under a root without one passes) and \
              pyHanko does not know the extension, so both trust the token; Folioxide does not \
              process RFC 3779 resources and trusts no path that carries one (final fix round 2, \
              finding 1)",
    },
    // Manager ruling R-30 (b): ECDSA certificate signatures take no parameters (RFC 5758
    // §3.2). asn1crypto forces NULL only for the RSA algorithms, so pyHanko trusts these paths,
    // and so does OpenSSL; Folioxide does not (stricter than both).
    Deliberate {
        case: "doc-signer-sigalg-ecdsa-params-null",
        index: 0,
        key: "trusted",
        oracle: "true",
        why: ECDSA_PARAMETERS,
    },
    Deliberate {
        case: "doc-signer-sigalg-ecdsa-params-integer",
        index: 0,
        key: "trusted",
        oracle: "true",
        why: ECDSA_PARAMETERS,
    },
    Deliberate {
        case: "doc-signer-sigalg-ecdsa-params-octet-string",
        index: 0,
        key: "trusted",
        oracle: "true",
        why: ECDSA_PARAMETERS,
    },
    Deliberate {
        case: "doc-signer-sigalg-ecdsa-params-sequence",
        index: 0,
        key: "trusted",
        oracle: "true",
        why: ECDSA_PARAMETERS,
    },
];

/// Why the `doc-signer-sigalg-ecdsa-params-*` rows of [`DELIBERATE`] differ.
const ECDSA_PARAMETERS: &str = "the document signer's certificate is signed with \
    ecdsa-with-SHA384 whose AlgorithmIdentifier carries parameters, inside tbsCertificate and \
    outside, which RFC 5758 §3.2 says MUST be omitted: Folioxide does not trust the edge \
    (manager ruling R-30 (b)); pyHanko (asn1crypto forces NULL parameters only for the RSA \
    algorithms) and OpenSSL trust the path";

/// The tokens of QA rounds 1 to 3 (round 1 findings F2–F6, round 2 finding 3, round 3 findings
/// 2–4) that pyHanko accepts and Folioxide refuses, with why: each gets the three deliberate
/// rows `timestamp`, `timestampTrusted` and `pades` (the oracles' `true`, `true`, `"B-T"`), and,
/// when OpenSSL refuses it too, a `knownFailures` row.
const STRICTER: &[(&str, bool, &str)] = &[
    (
        "tst-tsa-name-mismatch",
        true,
        "the TSTInfo tsa field names another TSA than the certificate (RFC 3161 §2.4.2); OpenSSL \
         refuses it (tsa name mismatch), pyHanko does not read the field",
    ),
    (
        "tst-ess-v2-ok-v1-wrong",
        true,
        "every ESS signing-certificate attribute present must identify the TSA certificate, as \
         OpenSSL checks; pyHanko reads only v2 when present",
    ),
    (
        "tst-ess-second-cert-id-junk",
        true,
        "every later ESS identifier must name a certificate of the TSA's chain, as OpenSSL \
         checks (ess cert id not found); pyHanko reads only the first",
    ),
    (
        "tst-ess-second-cert-id-decoy",
        true,
        "a later ESS identifier names an attacker's root that carries the real root's name (and \
         is in the token): no verified signature links it to the TSA certificate and OpenSSL \
         does not find it in its verified chain (ess cert id not found); pyHanko reads only the \
         first identifier (QA round 2 finding 3)",
    ),
    (
        "tst-ess-second-cert-id-reissued-root",
        true,
        "a later ESS identifier names a re-issued copy of the root (same name and key, another \
         serial) instead of the trust anchor: it is not on the validated path, which is where \
         OpenSSL looks (ess cert id not found); pyHanko reads only the first identifier (QA \
         round 2 finding 3)",
    ),
    (
        "tst-imprint-algorithm-parameters",
        true,
        "the imprint's SHA-256 with an OCTET STRING parameter is not the request's algorithm \
         (RFC 5754 §2; OpenSSL: message imprint mismatch); pyHanko compares the OID only",
    ),
    (
        "tst-digest-algorithms-empty",
        true,
        "SignedData.digestAlgorithms must list the SignerInfo's digest (OpenSSL: unable to find \
         message digest); pyHanko does not read the set",
    ),
    (
        "tst-signer-info-version-3",
        false,
        "RFC 5652 §5.3: a SignerInfo with an issuerAndSerialNumber is version 1; pyHanko and \
         OpenSSL both accept 3 there, Folioxide reads the token as a whitelist",
    ),
    (
        "tst-signed-attrs-values-unsorted",
        true,
        "the TSA signed attributes whose values are not in DER SET OF order: OpenSSL re-encodes \
         them as DER before it verifies (bad signature), pyHanko hashes them as found; RFC 5652 \
         §5.4 signs the DER encoding (QA round 3 finding 2)",
    ),
    (
        "tst-signed-attrs-indefinite",
        true,
        "the TSA signed attributes written with indefinite lengths: OpenSSL re-encodes them as \
         DER before it verifies (bad signature), pyHanko hashes them as found (QA round 3 \
         finding 2)",
    ),
    (
        "tst-signed-attrs-out-of-order",
        false,
        "the TSA signed attributes out of DER order: OpenSSL keeps the order it reads and \
         pyHanko hashes them as found, so both accept; BouncyCastle (EU DSS) sorts them, and RFC \
         5652 §5.4 signs the DER encoding, so Folioxide refuses (QA round 3 finding 2)",
    ),
    (
        "tst-ess-policies-junk",
        true,
        "the signing-certificate-v2 policies field is not a SEQUENCE OF PolicyInformation: \
         OpenSSL's ESS_SIGNING_CERT_V2 decoder refuses the token, pyHanko does not read the \
         field (QA round 3 finding 3)",
    ),
    (
        "tst-tst-info-extensions-junk",
        true,
        "the TSTInfo extensions field holds no Extension: OpenSSL's TS_TST_INFO decoder refuses \
         the token, pyHanko does not read the field (QA round 3 finding 4)",
    ),
    (
        "tst-tsa-gn-unknown-ctx9",
        true,
        "the TSTInfo tsa field is a context tag [9], no GeneralName choice: OpenSSL's \
         GENERAL_NAME template refuses the token (no matching choice type), pyHanko does not read \
         the field (QA round 4 finding 2)",
    ),
    (
        "tst-crl-issuer-bmp-surrogate",
        true,
        "a CRL of the token has an issuer name whose BMPString holds a lone surrogate, which \
         OpenSSL cannot convert (ASN1_mbstring_ncopy: illegal characters), so it refuses the \
         token; pyHanko does not read the CRLs (QA round 4 finding 1)",
    ),
    (
        "tst-tsa-cert-duplicate-ski",
        true,
        "the TSA certificate has two subjectKeyIdentifier extensions: OpenSSL's \
         ossl_x509v3_cache_extensions marks it invalid (invalid certificate), so ts -verify \
         refuses the token, as Folioxide does (TsaCertificateUnsuitable); pyHanko accepts it \
         (QA round 5 finding 37, ruling R-22 (c))",
    ),
    (
        "tst-tsa-cert-duplicate-bc",
        true,
        "the TSA certificate has two basicConstraints extensions: OpenSSL marks it invalid \
         (invalid certificate) and refuses the token, as Folioxide does; pyHanko accepts it (QA \
         round 5 finding 37, ruling R-22 (c))",
    ),
    (
        "tst-tsa-cert-nscerttype-junk",
        true,
        "the TSA certificate's nsCertType extension is a NULL, not a BIT STRING: OpenSSL's \
         ossl_x509v3_cache_extensions decodes it and marks the certificate invalid (invalid \
         certificate), as Folioxide does (TsaCertificateUnsuitable); asn1crypto does not parse \
         the type, so pyHanko accepts it (final fix round 2, finding 1)",
    ),
    (
        "tst-tsa-cert-ipaddrblocks-junk",
        true,
        "the TSA certificate's RFC 3779 ipAddrBlocks extension is a NULL: OpenSSL decodes it and \
         marks the certificate invalid, as Folioxide does; pyHanko does not know the type and \
         accepts it (final fix round 2, finding 1)",
    ),
    (
        "tst-tsa-cert-asid-junk",
        true,
        "the TSA certificate's RFC 3779 autonomousSysIds extension is empty: OpenSSL decodes it \
         and marks the certificate invalid, as Folioxide does; pyHanko does not know the type and \
         accepts it (final fix round 2, finding 1)",
    ),
    (
        "tst-tsa-cert-proxycertinfo-junk",
        true,
        "the TSA certificate's proxyCertInfo extension is an OBJECT IDENTIFIER: OpenSSL decodes it \
         and marks the certificate invalid, as Folioxide does; pyHanko does not know the type and \
         accepts it (final fix round 2, finding 1)",
    ),
    // M4 closing round, findings 8 and 11 (ruling R-26).
    (
        "tst-tsa-cert-critical-ski",
        true,
        "the TSA certificate's subjectKeyIdentifier is critical (RFC 5280 §4.2.1.2: it MUST be \
         non-critical): OpenSSL's X509_supported_extension does not list it, so ts -verify \
         refuses the token (unhandled critical extension), as Folioxide does \
         (TsaCertificateUnsuitable); pyHanko trusts it (closing round, findings 8 and 11)",
    ),
    (
        "tst-tsa-cert-critical-aki",
        true,
        "the TSA certificate's authorityKeyIdentifier is critical (RFC 5280 §4.2.1.1: it MUST be \
         non-critical): OpenSSL refuses the token (unhandled critical extension), as Folioxide \
         does; pyHanko trusts it (closing round, finding 11)",
    ),
    (
        "tst-tsa-cert-critical-aia",
        true,
        "the TSA certificate's authorityInfoAccess is critical (RFC 5280 §4.2.2.1: it MUST be \
         non-critical): OpenSSL refuses the token (unhandled critical extension), as Folioxide \
         does; pyHanko trusts it (closing round, findings 8 and 11)",
    ),
    (
        "tst-tsa-cert-critical-freshestcrl",
        true,
        "the TSA certificate's freshestCRL is critical (RFC 5280 §4.2.1.15: it MUST be \
         non-critical): OpenSSL refuses the token (unhandled critical extension), as Folioxide \
         does; pyHanko trusts it (closing round, finding 8)",
    ),
    (
        "tst-tsa-cert-critical-qcstatements",
        true,
        "the TSA certificate's qcStatements is critical: OpenSSL does not handle it and refuses \
         the token (unhandled critical extension), as Folioxide does; pyHanko trusts it \
         (closing round, finding 8)",
    ),
];

/// The deliberate `(key, oracle value)` pairs of a [`STRICTER`] case.
const STRICTER_ROWS: [(&str, &str); 3] = [
    ("timestamp", "true"),
    ("timestampTrusted", "true"),
    ("pades", "\"B-T\""),
];

/// The oracle value Folioxide's `entry` is replaced with for `key` of the signature at
/// `index` of `case`, and why.
fn deliberate_value(case: &str, index: usize, key: &str) -> Option<(&'static str, &'static str)> {
    if let Some(d) = DELIBERATE
        .iter()
        .find(|d| d.case == case && d.index == index && d.key == key)
    {
        return Some((d.oracle, d.why));
    }
    let (_, _, why) = STRICTER.iter().find(|(name, _, _)| *name == case)?;
    let (_, oracle) = STRICTER_ROWS.iter().find(|(k, _)| *k == key)?;
    (index == 0).then_some((*oracle, *why))
}

/// The `knownFailures` of a case.
fn known_failures(case: &str) -> Vec<(&'static str, &'static str)> {
    match case {
        "tst-tsa-eku-noncritical" => vec![(
            "signatures[0].timestamp.openssl",
            "OpenSSL rejects a non-critical timeStamping EKU (RFC 3161 §2.3), as Folioxide does",
        )],
        "tst-rsa-pss-signed" => vec![(
            "signatures[0].timestamp.openssl",
            "OpenSSL 3.0 verifies a token with PKCS7_signatureVerify, which knows PKCS #1 v1.5 \
             only, so it cannot verify this RSASSA-PSS token (RFC 4056); Folioxide and pyHanko \
             accept it (an OpenSSL limit, not a token defect: the proposed exception to brief \
             §5.5 (iii))",
        )],
        "tst-tsa-subject-bmp-surrogate" => vec![(
            "signatures[0].timestamp.openssl",
            "OpenSSL cannot decode the TSA certificate's subject (a BMPString surrogate: \
             illegal characters) and refuses the token, as Folioxide does (QA round 4 finding 1)",
        )],
        "tst-tsa-ca-name-constraints-excluded" => vec![(
            "signatures[0].timestamp.openssl",
            "the TSA's intermediate excludes the TSA's name in a non-critical nameConstraints: \
             OpenSSL refuses the chain (excluded subtree violation), pyHanko and Folioxide do not \
             trust it (QA round 4 finding 5)",
        )],
        "tst-tsa-akid-keyid-wrong"
        | "tst-tsa-akid-serial-only-wrong"
        | "tst-tsa-inter-akid-issuer-wrong" => vec![(
            "signatures[0].timestamp.openssl",
            "a certificate's authorityKeyIdentifier does not describe its issuer: OpenSSL's \
             X509_check_akid refuses the edge (unable to get local issuer certificate), and \
             Folioxide does not trust the token (QA round 5 finding 32, ruling R-22 (a))",
        )],
        "tst-tsa-spki-pss-pkcs1" => {
            const WHY: &str = "pyHanko raises an AssertionError on the whole signature when it \
                validates the token (a PKCS #1 v1.5 signature by a key whose id-RSASSA-PSS \
                SubjectPublicKeyInfo restricts it to RSASSA-PSS, RFC 4055 §1.2), so it reports \
                no status: its refusal; OpenSSL's ts -verify fails too (signatures[0].timestamp \
                .openssl), and Folioxide calls the token not valid (QA round 5 finding 36, \
                ruling R-22 (b))";
            [
                "signatures[0].pyhanko",
                "signatures[0].trusted.pyhanko",
                "signatures[0].coverage.pyhanko",
                "signatures[0].modification.pyhanko",
                "signatures[0].timestamp.pyhanko",
                "signatures[0].timestampTrusted.pyhanko",
            ]
            .into_iter()
            .map(|key| (key, WHY))
            .collect()
        }
        "tst-tsa-cert-proxycertinfo-valid" => vec![(
            "signatures[0].timestamp.openssl",
            "OpenSSL refuses a chain with a proxy certificate unless the caller allows them \
             (X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED); Folioxide calls the token valid but \
             untrusted, as for a path it cannot process (final fix round 2, finding 1)",
        )],
        "doc-signer-spki-pss" => vec![(
            "signatures[0].rejected.pdfsig",
            "poppler verifies the PKCS #1 v1.5 value with the RSA key and ignores that the \
             certificate's id-RSASSA-PSS SubjectPublicKeyInfo restricts it to RSASSA-PSS (RFC \
             4055 §1.2); pyHanko (AssertionError) and OpenSSL (illegal or unsupported padding \
             mode) refuse the signature, as Folioxide does (QA round 5 finding 36, ruling R-22 \
             (b))",
        )],
        "tst-sid-subject-key-identifier" => vec![(
            "signatures[0].timestamp.openssl",
            "OpenSSL 3.0's PKCS #7 decoder has no subjectKeyIdentifier signer identifier (RFC \
             5652 §5.3 allows it), so the token does not decode there; Folioxide and pyHanko \
             accept it (an OpenSSL limit, not a token defect: the proposed exception to brief \
             §5.5 (iii))",
        )],
        other => STRICTER
            .iter()
            .filter(|(name, openssl_refuses, _)| *name == other && *openssl_refuses)
            .map(|_| {
                (
                    "signatures[0].timestamp.openssl",
                    "OpenSSL refuses the token, as Folioxide does (QA rounds 1 to 5); pyHanko accepts it",
                )
            })
            .collect(),
    }
}

/// One oracle case: the file, its input (for `prefixOf`), the expectation, and supporting files
/// written next to it (a trust anchor of its own).
struct Case {
    name: String,
    pdf: Vec<u8>,
    input: Option<Vec<u8>>,
    expect: ExpectJson,
    reports: Vec<SignatureReport>,
    files: Vec<(String, Vec<u8>)>,
}

impl Case {
    /// The expect entry of the last signature, as JSON text.
    fn last_entry(&self) -> String {
        let signatures = self.expect.get("signatures").unwrap_or_default();
        let start = signatures.rfind('{').unwrap_or(0);
        signatures[start..].to_owned()
    }

    /// Whether the last signature is expected B-T with a sound and trusted token.
    fn checked(&self) -> bool {
        let last = self.last_entry();
        last.contains("\"pades\": \"B-T\"")
            && last.contains("\"timestamp\": true")
            && last.contains("\"timestampTrusted\": true")
    }
}

/// The expected `timestamp` value of a report: `true` (a sound selected token), `"invalid"`
/// (a token, not sound) or `false` (none, or a document timestamp).
fn timestamp_value(report: &SignatureReport) -> &'static str {
    if report.kind == SignatureKind::DocTimeStamp {
        return "false";
    }
    match &report.timestamp {
        Some(t) if t.intact && t.valid => "true",
        Some(_) => "\"invalid\"",
        None => "false",
    }
}

/// The `signatures[]` entry of `report` (the signature at `index` of case `case`).
fn entry(case: &str, index: usize, report: &SignatureReport) -> String {
    let mut parts: Vec<(&str, String)> = vec![
        (
            "field",
            json_string(report.field_name.as_deref().unwrap_or_default()),
        ),
        ("intact", report.intact.to_string()),
        ("valid", report.signature_valid.to_string()),
    ];
    if let Some(trusted) = report.trusted {
        parts.push(("trusted", trusted.to_string()));
    }
    parts.push(("coverage", json_string(report.coverage.as_str())));
    parts.push(("modification", json_string(report.modification.as_str())));
    if let Some(p) = report.docmdp {
        // Ours once V11 lands (WP4.2A); until then what ISO 32000-2 §12.8.2.2 allows at the
        // reported modification level (document timestamps and DSS updates under every P).
        let allowed = match p {
            1 => ModificationLevel::LtaUpdates,
            2 => ModificationLevel::FormFilling,
            _ => ModificationLevel::Annotations,
        };
        let ok = report.docmdp_ok.unwrap_or(report.modification <= allowed);
        parts.push(("docmdp", p.to_string()));
        parts.push(("docmdpOk", ok.to_string()));
    }
    if report.kind == SignatureKind::Signature {
        parts.push((
            "pades",
            match report.pades_level {
                Some(PadesLevel::BT) => "\"B-T\"".to_owned(),
                Some(PadesLevel::BB) => "\"B-B\"".to_owned(),
                _ => "false".to_owned(),
            },
        ));
    }
    parts.push(("timestamp", timestamp_value(report).to_owned()));
    if report.kind == SignatureKind::Signature
        && let Some(trusted) = report.timestamp.as_ref().and_then(|t| t.trusted)
    {
        parts.push(("timestampTrusted", trusted.to_string()));
    }
    let keys: Vec<&str> = DELIBERATE
        .iter()
        .filter(|d| d.case == case && d.index == index)
        .map(|d| d.key)
        .chain(
            STRICTER
                .iter()
                .filter(|(name, _, _)| *name == case && index == 0)
                .flat_map(|_| STRICTER_ROWS.iter().map(|(key, _)| *key)),
        )
        .collect();
    for key in keys {
        let (oracle, why) = deliberate_value(case, index, key).unwrap_or_default();
        let slot = parts
            .iter_mut()
            .find(|(k, _)| *k == key)
            .unwrap_or_else(|| panic!("{case}: no key {key} to override"));
        assert_ne!(slot.1, oracle, "{case}: a stale deliberate row ({why})");
        slot.1 = oracle.to_owned();
    }
    let body: Vec<String> = parts
        .iter()
        .map(|(key, value)| format!("\"{key}\": {value}"))
        .collect();
    format!("{{{}}}", body.join(", "))
}

/// The number of `startxref` keywords, as the runner counts revisions.
fn startxref_count(pdf: &[u8]) -> i64 {
    let key = b"startxref";
    pdf.windows(key.len())
        .enumerate()
        .filter(|(i, w)| *w == key && (*i == 0 || !pdf[i - 1].is_ascii_alphabetic()))
        .count() as i64
}

/// A case for `pdf`, made from `input` (`None`: the file is checked as it is).
fn case(name: &str, input: Option<&[u8]>, pdf: Vec<u8>) -> Case {
    case_with_anchor(name, input, pdf, None)
}

/// [`case`] with the trust anchor `anchor` (DER) besides [`TRUST_ROOT`], for Folioxide and the
/// oracles alike: it is written next to the case as `<name>.anchor.pem`.
fn case_with_anchor(name: &str, input: Option<&[u8]>, pdf: Vec<u8>, anchor: Option<&[u8]>) -> Case {
    if let Some(input) = input {
        assert!(pdf.starts_with(input), "{name}: prefix");
    }
    let mut roots = vec![json_string(TRUST_ROOT)];
    let mut files = Vec::new();
    let reports = match anchor {
        Some(anchor) => {
            let file = format!("{name}.anchor.pem");
            roots.push(json_string(&file));
            files.push((file, pem(&[anchor.to_vec()]).into_bytes()));
            let mut anchors = anchors();
            anchors.push(anchor.to_vec());
            verify_with(
                &pdf,
                &folioxide_sign::verify_pdf::VerifyOptions::new().with_trust_anchors_der(anchors),
            )
        }
        None => verify(&pdf),
    };
    assert!(!reports.is_empty(), "{name}");
    let entries: Vec<String> = reports
        .iter()
        .filter(|r| r.field_name.is_some())
        .enumerate()
        .map(|(i, r)| entry(name, i, r))
        .collect();
    let mut expect = ExpectJson::new()
        .raw("trustRoots", format!("[{}]", roots.join(", ")))
        .int("pages", open(&pdf).page_count().unwrap() as i64)
        .int("revisions", startxref_count(&pdf));
    if input.is_some() {
        expect = expect.string("prefixOf", &format!("{name}.input.pdf"));
    }
    expect = expect.raw("signatures", format!("[{}]", entries.join(", ")));
    let known = known_failures(name);
    if !known.is_empty() {
        expect = expect.string_map("knownFailures", &known);
    }
    Case {
        name: name.to_owned(),
        pdf,
        input: input.map(<[u8]>::to_vec),
        expect,
        reports,
        files,
    }
}

/// Asserts that every signature of `case` is sound and the last one is B-T with a trusted
/// token and covers the file.
fn assert_sound_bt(case: &Case) {
    for r in &case.reports {
        assert!(r.is_valid(), "{}: {}", case.name, summary(r));
        assert_eq!(r.trusted, Some(true), "{}: {}", case.name, summary(r));
    }
    let last = case.reports.last().unwrap();
    assert_eq!(
        last.pades_level,
        Some(PadesLevel::BT),
        "{}: {}",
        case.name,
        summary(last)
    );
    let ts = last.timestamp.as_ref().unwrap();
    assert!(
        ts.intact && ts.valid && ts.trusted == Some(true) && ts.problems.is_empty(),
        "{}: {ts:?}",
        case.name
    );
    assert_eq!(last.modification, ModificationLevel::None, "{}", case.name);
    assert!(case.checked(), "{}: {}", case.name, case.last_entry());
}

/// Signs `source` B-T with `signer`, `options`, `params` and the timestamper.
fn sign_bt_params(
    source: &[u8],
    signer: &dyn Signer,
    options: SignatureOptions,
    params: TimestampParams,
    timestamper: &dyn Timestamper,
) -> folioxide_sign::Result<Vec<u8>> {
    sign(
        &open(source),
        &SignRequest::new(signer, time())
            .with_options(options)
            .with_timestamper(timestamper, params),
    )
}

/// A B-T case signed by `signer` with the default mock TSA.
fn mock_case(name: &str, source: &[u8], signer: &LocalSigner) -> Case {
    let c = case(name, Some(source), sign_bt(source, signer));
    assert_sound_bt(&c);
    c
}

/// The committed `openssl ts -reply` token through the two-phase path (brief §4.3): the same
/// deterministic request as `bt_sign.rs` `bt_external_openssl_token_embedded`.
fn openssl_case() -> Case {
    let signer = rsa2048();
    let prepared = prepared_bt(&signer, &minimal());
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let request = prepared
        .timestamp_request(&value, &TimestampParams::new().with_nonce(Some(NONCE)))
        .unwrap();
    assert_eq!(
        request,
        tsa_fixture("openssl-reply.tsq"),
        "fixtures/sign/tsa/openssl-reply.tsq is stale: regenerate it with \
         `.venv/bin/python -I tools/fixtures/sign.py --only tsa` (brief R-15)"
    );
    let signed = prepared
        .finish_with_timestamp(&value, &request, &tsa_fixture("openssl-reply.tsr"))
        .unwrap();
    let c = case("bt-openssl-external", Some(&minimal()), signed);
    assert_sound_bt(&c);
    let ts = c.reports[0].timestamp.as_ref().unwrap();
    assert!(ts.tsa_name.is_some() && ts.accuracy_micros == Some(1_000_000));
    c
}

/// `source` prepared for a B-T signature by `signer` (token budget [`DEFAULT_TSA_RESERVE`]).
fn prepared_bt(signer: &LocalSigner, source: &[u8]) -> PreparedSignature {
    let request = PrepareRequest::new(
        signer.certificate_chain().to_vec(),
        signer.algorithm(),
        time(),
    )
    .with_options(SignatureOptions::new(time()).with_tsa_reserve(Some(DEFAULT_TSA_RESERVE)));
    prepare(&open(source), &request).unwrap()
}

/// A B-T file of `minimal.pdf` signed by RSA-2048 whose token `tsa` makes for the honest
/// request, written below Folioxide's own `finish` (which refuses the deliberate tokens).
fn attack(tsa: &MockTsa) -> Vec<u8> {
    let signer = rsa2048();
    let prepared = prepared_bt(&signer, &minimal());
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let request = prepared
        .timestamp_request(&value, &TimestampParams::new().with_nonce(Some(NONCE)))
        .unwrap();
    let token = tsa.token_for(&request).unwrap();
    let cms = cms::assemble_with_timestamp(
        prepared.to_be_signed(),
        &value,
        signer.certificate_chain(),
        signer.algorithm(),
        signer.key_kind(),
        prepared.digest_algorithm(),
        &token,
    )
    .unwrap();
    embed_raw(&prepared, &cms)
}

/// `tst_tsa_eku_noncritical`: a sound signature whose token's TSA certificate has a
/// non-critical timeStamping EKU. Ours: the token is intact but not valid, the signature B-B.
fn eku_noncritical_case() -> Case {
    let pdf = attack(&mock_tsa_with(
        "tsa-eku-noncritical.pem",
        MockTsaOptions::default(),
    ));
    let c = case("tst-tsa-eku-noncritical", Some(&minimal()), pdf);
    let r = &c.reports[0];
    assert!(r.is_valid() && r.trusted == Some(true), "{}", summary(r));
    assert_eq!(r.pades_level, Some(PadesLevel::BB), "{}", summary(r));
    let ts = r.timestamp.as_ref().unwrap();
    assert!(
        ts.intact && !ts.valid && ts.trusted == Some(false),
        "{ts:?}"
    );
    assert_eq!(ts.problems[0].code, ProblemCode::TsaCertificateUnsuitable);
    c
}

/// `tst_imprint_mismatch`: the token's imprint is over the DER OCTET STRING of the signature
/// value, not its contents octets. Ours: not intact, the signature B-B.
fn imprint_mismatch_case() -> Case {
    let signer = rsa2048();
    let prepared = prepared_bt(&signer, &minimal());
    let value = signer
        .sign(prepared.digest_algorithm(), prepared.to_be_signed())
        .unwrap();
    let mut octet_string = vec![0x04, 0x82, 0x01, 0x00];
    octet_string.extend_from_slice(&value);
    let pdf = attack(&mock_tsa_with(
        "tsa.pem",
        MockTsaOptions {
            imprint: Echo::Replace(DigestAlgorithm::Sha256.digest(&[&octet_string])),
            ..MockTsaOptions::default()
        },
    ));
    let c = case("tst-imprint-mismatch", Some(&minimal()), pdf);
    let r = &c.reports[0];
    assert!(r.is_valid(), "{}", summary(r));
    assert_eq!(r.pades_level, Some(PadesLevel::BB), "{}", summary(r));
    let ts = r.timestamp.as_ref().unwrap();
    assert!(
        !ts.intact && ts.valid && ts.trusted == Some(false),
        "{ts:?}"
    );
    assert_eq!(ts.problems[0].code, ProblemCode::TimestampImprintMismatch);
    assert!(c.last_entry().contains("\"timestamp\": \"invalid\""));
    c
}

/// A [`STRICTER`] case: a sound signature whose token `options` bends. Ours: the token is
/// `intact` or not and `valid` or not (never both), with `code` first; the signature B-B.
fn stricter_case(
    name: &str,
    options: MockTsaOptions,
    (intact, valid): (bool, bool),
    code: ProblemCode,
) -> Case {
    assert!(STRICTER.iter().any(|(n, _, _)| *n == name), "{name}");
    let c = case(
        name,
        Some(&minimal()),
        attack(&mock_tsa_with("tsa.pem", options)),
    );
    let r = &c.reports[0];
    assert!(
        r.is_valid() && r.trusted == Some(true),
        "{name}: {}",
        summary(r)
    );
    assert_eq!(
        r.pades_level,
        Some(PadesLevel::BB),
        "{name}: {}",
        summary(r)
    );
    let ts = r.timestamp.as_ref().unwrap();
    assert!(!(intact && valid), "{name}");
    assert!(
        ts.intact == intact && ts.valid == valid && ts.trusted == Some(false),
        "{name}: {ts:?}"
    );
    assert_eq!(ts.problems[0].code, code, "{name}: {ts:?}");
    c
}

/// The cases of [`STRICTER`].
fn stricter_cases() -> Vec<Case> {
    let sha256 = [
        0x30, 0x0E, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x01,
        0x00,
    ];
    // The document signer's subject as a directoryName [4]: another TSA than the token's.
    let directory_name = directory_name(&subject_name(&cert("signer-rsa2048.pem")));
    vec![
        stricter_case(
            "tst-tsa-name-mismatch",
            MockTsaOptions {
                tsa_general_name: Some(directory_name),
                ..MockTsaOptions::default()
            },
            (true, false),
            ProblemCode::TsaNameMismatch,
        ),
        stricter_case(
            "tst-ess-v2-ok-v1-wrong",
            MockTsaOptions {
                ess: Ess::V2AndWrongV1,
                ..MockTsaOptions::default()
            },
            (true, false),
            ProblemCode::TimestampEssMismatch,
        ),
        stricter_case(
            "tst-ess-second-cert-id-junk",
            MockTsaOptions {
                ess_more_cert_ids: vec![b"junk".to_vec()],
                ..MockTsaOptions::default()
            },
            (true, false),
            ProblemCode::TimestampEssMismatch,
        ),
        stricter_case(
            "tst-ess-second-cert-id-decoy",
            MockTsaOptions {
                extra_certificate_entries: vec![decoys().fake_root.clone()],
                ess_more_cert_ids: vec![decoys().fake_root.clone()],
                ..MockTsaOptions::default()
            },
            (true, false),
            ProblemCode::TimestampEssMismatch,
        ),
        stricter_case(
            "tst-ess-second-cert-id-reissued-root",
            MockTsaOptions {
                extra_certificate_entries: vec![decoys().reissued_root.clone()],
                ess_more_cert_ids: vec![decoys().reissued_root.clone()],
                ..MockTsaOptions::default()
            },
            (true, false),
            ProblemCode::TimestampEssMismatch,
        ),
        stricter_case(
            "tst-imprint-algorithm-parameters",
            MockTsaOptions {
                imprint_algorithm: Some(sha256.to_vec()),
                ..MockTsaOptions::default()
            },
            (false, true),
            ProblemCode::TimestampImprintMismatch,
        ),
        stricter_case(
            "tst-digest-algorithms-empty",
            MockTsaOptions {
                digest_algorithms: Some(Vec::new()),
                ..MockTsaOptions::default()
            },
            (false, false),
            ProblemCode::TimestampMalformed,
        ),
        stricter_case(
            "tst-signer-info-version-3",
            MockTsaOptions {
                signer_info_version: 3,
                ..MockTsaOptions::default()
            },
            (false, false),
            ProblemCode::TimestampMalformed,
        ),
        // QA round 3 findings 2–4 (variants r3-attr-signing-time-unsorted-values,
        // r3-ber-sattr-all-attrs-indefinite, r3-ess-policies-junk-integer-v2,
        // r3-tstinfo-extensions-octet-string).
        stricter_case(
            "tst-signed-attrs-values-unsorted",
            MockTsaOptions {
                extra_signed_attributes: vec![tokens::unsorted_attribute(
                    &tokens::SIGNING_TIME,
                    &[
                        tokens::utc_time("261010120030Z"),
                        tokens::utc_time("261010120031Z"),
                    ],
                )],
                ..MockTsaOptions::default()
            },
            (false, false),
            ProblemCode::TimestampMalformed,
        ),
        stricter_case(
            "tst-signed-attrs-indefinite",
            MockTsaOptions {
                signed_attrs_encoding: Some(tokens::attributes_indefinite),
                ..MockTsaOptions::default()
            },
            (false, false),
            ProblemCode::TimestampMalformed,
        ),
        stricter_case(
            "tst-signed-attrs-out-of-order",
            MockTsaOptions {
                signed_attrs_encoding: Some(tokens::attributes_reversed),
                ..MockTsaOptions::default()
            },
            (false, false),
            ProblemCode::TimestampMalformed,
        ),
        stricter_case(
            "tst-ess-policies-junk",
            MockTsaOptions {
                ess_policies: Some(tokens::seq(&[tokens::seq(&[tokens::int(1)])])),
                ..MockTsaOptions::default()
            },
            (false, false),
            ProblemCode::TimestampMalformed,
        ),
        stricter_case(
            "tst-tst-info-extensions-junk",
            MockTsaOptions {
                tst_extensions: Some(tokens::tst_extensions(&[tokens::octets(b"zz")])),
                ..MockTsaOptions::default()
            },
            (false, false),
            ProblemCode::TimestampMalformed,
        ),
        // QA round 4 findings 1 and 2 (variants r5-tsa-gn-unknown-ctx9,
        // r5-crl-issuer-bmp-lone-surrogate).
        stricter_case(
            "tst-tsa-gn-unknown-ctx9",
            MockTsaOptions {
                tsa_general_name: Some(tokens::der(0x89, b"tsa")),
                ..MockTsaOptions::default()
            },
            (false, false),
            ProblemCode::TimestampMalformed,
        ),
        stricter_case(
            "tst-crl-issuer-bmp-surrogate",
            MockTsaOptions {
                crls: vec![decoys::test_crl(&decoys::test_name(decoys::bmp(&[
                    0x54, 0xD800,
                ])))],
                ..MockTsaOptions::default()
            },
            (false, false),
            ProblemCode::TimestampMalformed,
        ),
    ]
}

/// A mock TSA for `tsa.key.pem` with the certificate `tsa_cert`, carrying `extra`.
fn mock_with_cert(tsa_cert: Vec<u8>, extra: Vec<Vec<u8>>) -> MockTsa {
    let key = tsa_key("tsa.pem");
    MockTsa::new(
        tsa_cert,
        extra,
        Box::new(move |attrs| key.sign(DigestAlgorithm::Sha256, attrs).unwrap()),
    )
}

/// The cases of QA round 4 (findings 1, 5 and 9) whose certificates are issued at test time.
fn round4_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    let root = cert("root.pem");

    // Finding 1: the TSA certificate's subject has a BMPString with a lone surrogate. Ours:
    // malformed; pyHanko: valid and untrusted (row DELIBERATE); OpenSSL refuses.
    let tsa_cert = decoys::tsa_cert_with(
        0x0A5E_0B00,
        &decoys::test_name(decoys::bmp(&[0x54, 0xD800])),
        &[],
    );
    let c = case(
        "tst-tsa-subject-bmp-surrogate",
        Some(&minimal()),
        attack(&mock_with_cert(tsa_cert, vec![root.clone()])),
    );
    let ts = c.reports[0].timestamp.as_ref().unwrap();
    assert!(
        !ts.intact && !ts.valid && ts.trusted == Some(false),
        "{ts:?}"
    );
    assert_eq!(ts.problems[0].code, ProblemCode::TimestampMalformed);
    cases.push(c);

    // Finding 5: the TSA certificate issued by an intermediate CA (the test intermediate's name
    // and key, re-issued by the root) with a non-critical nameConstraints. Excluding the TSA's
    // name: untrusted for pyHanko and Folioxide, OpenSSL refuses the chain. Excluding a dNSName
    // the path does not hold: pyHanko and OpenSSL trust it, Folioxide does not (DELIBERATE).
    let tsa_cert = decoys::decoys().tsa_via_intermediate.clone();
    let constraint = |base: Vec<u8>| {
        decoys::extension(
            &[0x55, 0x1D, 0x1E],
            false,
            &tokens::seq(&[tokens::der(0xA1, &tokens::seq(&[base]))]),
        )
    };
    for (serial, name, base) in [
        (
            0x0A5E_0B10,
            "tst-tsa-ca-name-constraints-excluded",
            tokens::der(0xA4, &subject_name(&tsa_cert)),
        ),
        (
            0x0A5E_0B11,
            "tst-tsa-ca-name-constraints-satisfied",
            tokens::der(0x82, b"example.org"),
        ),
    ] {
        let intermediate = decoys::intermediate_with(serial, &[constraint(base)]);
        let signed = sign_bt_params(
            &minimal(),
            &rsa2048(),
            SignatureOptions::new(time()),
            TimestampParams::new().with_nonce(Some(NONCE)),
            &Tsa(mock_with_cert(
                tsa_cert.clone(),
                vec![intermediate, root.clone()],
            )),
        )
        .unwrap();
        let c = case(name, Some(&minimal()), signed);
        let r = &c.reports[0];
        assert!(
            r.is_valid() && r.trusted == Some(true),
            "{name}: {}",
            summary(r)
        );
        assert_eq!(
            r.pades_level,
            Some(PadesLevel::BT),
            "{name}: {}",
            summary(r)
        );
        let ts = r.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && ts.valid && ts.trusted == Some(false),
            "{name}: {ts:?}"
        );
        cases.push(c);
    }

    // Finding 9 (nc_doc/nc-exclude-noncritical): the document signer's intermediate excludes
    // the signer's name in a non-critical nameConstraints. pyHanko: trusted False; so is ours.
    let signer_cert = cert("signer-rsa2048.pem");
    let intermediate = decoys::intermediate_with(
        0x0A5E_0B20,
        &[constraint(tokens::der(0xA4, &subject_name(&signer_cert)))],
    );
    let signer = LocalSigner::from_pem(
        &pki_text("signer-rsa2048.key.pem"),
        &pem(&[signer_cert, intermediate]),
        None,
    )
    .unwrap();
    let c = case(
        "doc-signer-ca-name-constraints-excluded",
        Some(&minimal()),
        sign_bt(&minimal(), &signer),
    );
    let r = &c.reports[0];
    assert!(r.is_valid() && r.trusted == Some(false), "{}", summary(r));
    assert_eq!(r.pades_level, Some(PadesLevel::BT), "{}", summary(r));
    cases.push(c);
    cases
}

/// A non-critical `AuthorityKeyIdentifier` extension with the parts that are given; `issuer`
/// is the content of `authorityCertIssuer [1]`.
fn akid(key_id: Option<&[u8]>, issuer: Option<Vec<u8>>, serial: Option<&[u8]>) -> Vec<u8> {
    let mut parts = Vec::new();
    if let Some(key_id) = key_id {
        parts.push(tokens::der(0x80, key_id));
    }
    if let Some(issuer) = issuer {
        parts.push(tokens::der(0xA1, &issuer));
    }
    if let Some(serial) = serial {
        parts.push(tokens::der(0x82, serial));
    }
    decoys::extension(&[0x55, 0x1D, 0x23], false, &tokens::seq(&parts))
}

/// A case whose signature every oracle must reject (`"rejected": true`, M3 brief D-3): ours is
/// not valid and not trusted.
fn rejected_case(name: &str, input: &[u8], pdf: Vec<u8>) -> Case {
    assert!(pdf.starts_with(input), "{name}: prefix");
    let reports = verify(&pdf);
    let [r] = reports.as_slice() else {
        panic!("{name}: {} reports", reports.len());
    };
    assert!(
        !r.signature_valid && r.trusted == Some(false),
        "{name}: {}",
        summary(r)
    );
    let field = r.field_name.clone().unwrap();
    let mut expect = ExpectJson::new()
        .raw("trustRoots", format!("[{}]", json_string(TRUST_ROOT)))
        .int("pages", open(&pdf).page_count().unwrap() as i64)
        .int("revisions", startxref_count(&pdf))
        .string("prefixOf", &format!("{name}.input.pdf"))
        .raw(
            "signatures",
            format!(
                "[{{\"field\": {}, \"rejected\": true}}]",
                json_string(&field)
            ),
        );
    let known = known_failures(name);
    if !known.is_empty() {
        expect = expect.string_map("knownFailures", &known);
    }
    Case {
        name: name.to_owned(),
        pdf,
        input: Some(input.to_vec()),
        expect,
        reports,
        files: Vec::new(),
    }
}

/// The cases of QA round 5 (findings 32, 36 and 37; ruling R-22) whose certificates are issued
/// at test time.
fn round5_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    let root = cert("root.pem");
    let root_ski = decoys::ski_of(&root).unwrap();
    let tsa_subject = subject_name(&cert("tsa.pem"));

    // Finding 32: an authorityKeyIdentifier that does not describe the issuer. The TSA
    // certificate (keyIdentifier wrong: pyHanko untrusted; a serial alone wrong: pyHanko
    // trusted, DELIBERATE), the TSA's intermediate (authorityCertIssuer wrong), all valid and
    // untrusted; OpenSSL cannot build the chain (knownFailures).
    for (serial, name, ext) in [
        (
            0x0A5E_0C00,
            "tst-tsa-akid-keyid-wrong",
            akid(Some(&[0xAA; 20]), None, None),
        ),
        (
            0x0A5E_0C01,
            "tst-tsa-akid-serial-only-wrong",
            akid(None, None, Some(&[0x01, 0x02])),
        ),
    ] {
        let tsa_cert = decoys::tsa_cert_with(serial, &tsa_subject, &[ext]);
        let signed = sign_bt_params(
            &minimal(),
            &rsa2048(),
            SignatureOptions::new(time()),
            TimestampParams::new().with_nonce(Some(NONCE)),
            &Tsa(mock_with_cert(tsa_cert, vec![root.clone()])),
        )
        .unwrap();
        let c = case(name, Some(&minimal()), signed);
        let r = &c.reports[0];
        assert!(
            r.is_valid() && r.trusted == Some(true),
            "{name}: {}",
            summary(r)
        );
        assert_eq!(r.pades_level, Some(PadesLevel::BT), "{name}");
        let ts = r.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && ts.valid && ts.trusted == Some(false),
            "{name}: {ts:?}"
        );
        cases.push(c);
    }
    {
        let name = "tst-tsa-inter-akid-issuer-wrong";
        let intermediate = decoys::intermediate_with(
            0x0A5E_0C10,
            &[akid(
                Some(&root_ski),
                Some(directory_name(&tsa_subject)),
                Some(&decoys::serial_of(&root)),
            )],
        );
        let signed = sign_bt_params(
            &minimal(),
            &rsa2048(),
            SignatureOptions::new(time()),
            TimestampParams::new().with_nonce(Some(NONCE)),
            &Tsa(mock_with_cert(
                decoys::decoys().tsa_via_intermediate.clone(),
                vec![intermediate, root.clone()],
            )),
        )
        .unwrap();
        let c = case(name, Some(&minimal()), signed);
        let ts = c.reports[0].timestamp.as_ref().unwrap();
        assert!(
            ts.intact && ts.valid && ts.trusted == Some(false),
            "{name}: {ts:?}"
        );
        cases.push(c);
    }
    {
        // The document signer's certificate names the root's key identifier instead of the
        // intermediate's (nc_doc6/akid-leaf-keyid-correct-only): pyHanko trusted False.
        let name = "doc-signer-akid-names-root";
        let leaf = decoys::signer_cert_with(0x0A5E_0C20, &[akid(Some(&root_ski), None, None)]);
        let signer = LocalSigner::from_pem(
            &pki_text("signer-rsa2048.key.pem"),
            &pem(&[leaf, cert("intermediate.pem")]),
            None,
        )
        .unwrap();
        let c = case(name, Some(&minimal()), sign_bt(&minimal(), &signer));
        let r = &c.reports[0];
        assert!(r.is_valid() && r.trusted == Some(false), "{}", summary(r));
        assert_eq!(r.pades_level, Some(PadesLevel::BT), "{}", summary(r));
        cases.push(c);
    }

    // Finding 37: a TSA certificate with a duplicated extension. Ours: not valid
    // (TsaCertificateUnsuitable), B-B; OpenSSL: invalid certificate; pyHanko accepts (STRICTER).
    let ski = decoys::extension(&[0x55, 0x1D, 0x0E], false, &tokens::octets(&[1, 2, 3, 4]));
    let bc = decoys::extension(&[0x55, 0x1D, 0x13], false, &tokens::seq(&[]));
    for (serial, name, extensions) in [
        (
            0x0A5E_0C30,
            "tst-tsa-cert-duplicate-ski",
            vec![ski.clone(), ski],
        ),
        (
            0x0A5E_0C31,
            "tst-tsa-cert-duplicate-bc",
            vec![bc.clone(), bc],
        ),
    ] {
        let tsa_cert = decoys::tsa_cert_with(serial, &tsa_subject, &extensions);
        let c = case(
            name,
            Some(&minimal()),
            attack(&mock_with_cert(tsa_cert, vec![root.clone()])),
        );
        let r = &c.reports[0];
        assert!(
            r.is_valid() && r.trusted == Some(true),
            "{name}: {}",
            summary(r)
        );
        assert_eq!(r.pades_level, Some(PadesLevel::BB), "{name}");
        let ts = r.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && !ts.valid && ts.trusted == Some(false),
            "{name}: {ts:?}"
        );
        assert_eq!(ts.problems[0].code, ProblemCode::TsaCertificateUnsuitable);
        cases.push(c);
    }

    // Finding 36: a token signed with PKCS #1 v1.5 by a TSA whose certificate restricts its
    // key to RSASSA-PSS (r7-spki-pss-no-params). Ours: the token intact, not valid
    // (TimestampSignatureInvalid), the signature B-B; OpenSSL: ts -verify fails (last octet
    // invalid); pyHanko raises an AssertionError on the whole signature (knownFailures).
    {
        let tsa = cert("tsa.pem");
        let pss_tsa = decoys::issue(
            0x0A5E_0C50,
            &decoys::subject_of(&root),
            &decoys::subject_of(&tsa),
            &decoys::pss_spki(&decoys::spki_of(&tsa), None),
            &decoys::tsa_extensions(),
            &decoys::signer("root.key.pem", "root.pem"),
        );
        let name = "tst-tsa-spki-pss-pkcs1";
        let c = case(
            name,
            Some(&minimal()),
            attack(&mock_with_cert(pss_tsa, vec![root.clone()])),
        );
        let r = &c.reports[0];
        assert!(
            r.is_valid() && r.trusted == Some(true),
            "{name}: {}",
            summary(r)
        );
        assert_eq!(r.pades_level, Some(PadesLevel::BB), "{name}");
        let ts = r.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && !ts.valid && ts.trusted == Some(false),
            "{name}: {ts:?}"
        );
        assert_eq!(ts.problems[0].code, ProblemCode::TimestampSignatureInvalid);
        assert!(c.last_entry().contains("\"timestamp\": \"invalid\""));
        cases.push(c);
    }
    // Finding 36: a document signature whose signer certificate restricts its key to
    // RSASSA-PSS (id-RSASSA-PSS SubjectPublicKeyInfo) with a PKCS #1 v1.5 signature value,
    // made below the signing API (which refuses the certificate). Every oracle rejects it:
    // pyHanko raises, OpenSSL: illegal or unsupported padding mode.
    {
        let name = "doc-signer-spki-pss";
        let signer_cert = cert("signer-rsa2048.pem");
        let intermediate = cert("intermediate.pem");
        let spki = decoys::spki_of(&signer_cert);
        let pss_cert = decoys::issue(
            0x0A5E_0C40,
            &decoys::subject_of(&intermediate),
            &decoys::subject_of(&signer_cert),
            &decoys::pss_spki(&spki, None),
            &[decoys::extension(
                &[0x55, 0x1D, 0x0F],
                true,
                &tokens::der(0x03, &[0x06, 0xC0]),
            )],
            &decoys::signer("intermediate.key.pem", "intermediate.pem"),
        );
        let rsa = rsa2048();
        let prepared = prepare(
            &open(&minimal()),
            &PrepareRequest::new(rsa.certificate_chain().to_vec(), rsa.algorithm(), time()),
        )
        .unwrap();
        let attrs = cms::build_signed_attrs(&cms::SignedAttrsInput {
            digest: DigestAlgorithm::Sha256,
            document_digest: prepared.document_digest(),
            signer_cert_der: &pss_cert,
        })
        .unwrap();
        let value = rsa.sign(DigestAlgorithm::Sha256, &attrs).unwrap();
        let cms_der = cms::assemble(
            &attrs,
            &value,
            &[pss_cert, intermediate],
            rsa.algorithm(),
            rsa.key_kind(),
            DigestAlgorithm::Sha256,
        )
        .unwrap();
        cases.push(rejected_case(
            name,
            &minimal(),
            embed_raw(&prepared, &cms_der),
        ));
    }
    cases
}

/// The cases of M4 final fix round 2 (findings 1 and 2) whose certificates are issued at test
/// time.
fn final_fix_2_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    let root = cert("root.pem");
    let tsa_subject = subject_name(&cert("tsa.pem"));
    let oid = |content: &[u8]| tokens::der(0x06, content);
    const NS_CERT_TYPE: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x01];
    const IP_ADDR_BLOCKS: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x07];
    const AS_IDENTIFIERS: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x08];
    const PROXY_CERT_INFO: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0E];
    const PRIVATE_KEY_USAGE_PERIOD: &[u8] = &[0x55, 0x1D, 0x10];
    const SUBJECT_DIRECTORY_ATTRIBUTES: &[u8] = &[0x55, 0x1D, 0x09];
    const TLS_FEATURE: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x18];

    // Finding 1: a TSA certificate whose extension of a type asn1crypto or OpenSSL decodes
    // (and Folioxide had not) does not decode (r8-ext-*-{junk-null,empty,junk-oid}). Ours: the
    // certificate is unsuitable, the token not valid, B-B.
    let junk_oid = oid(&[0x2A, 0x03, 0x04]);
    for (serial, name, ext_oid, value) in [
        (
            0x0A5E_0D00,
            "tst-tsa-cert-nscerttype-junk",
            NS_CERT_TYPE,
            vec![0x05, 0x00],
        ),
        (
            0x0A5E_0D01,
            "tst-tsa-cert-ipaddrblocks-junk",
            IP_ADDR_BLOCKS,
            vec![0x05, 0x00],
        ),
        (
            0x0A5E_0D02,
            "tst-tsa-cert-asid-junk",
            AS_IDENTIFIERS,
            Vec::new(),
        ),
        (
            0x0A5E_0D03,
            "tst-tsa-cert-proxycertinfo-junk",
            PROXY_CERT_INFO,
            junk_oid.clone(),
        ),
        (
            0x0A5E_0D04,
            "tst-tsa-cert-pkup-junk",
            PRIVATE_KEY_USAGE_PERIOD,
            vec![0x05, 0x00],
        ),
        (
            0x0A5E_0D05,
            "tst-tsa-cert-subjdirattrs-junk",
            SUBJECT_DIRECTORY_ATTRIBUTES,
            junk_oid.clone(),
        ),
        (
            0x0A5E_0D06,
            "tst-tsa-cert-tlsfeature-junk",
            TLS_FEATURE,
            Vec::new(),
        ),
    ] {
        let extension = decoys::extension(ext_oid, false, &value);
        let tsa_cert = decoys::tsa_cert_with(serial, &tsa_subject, &[extension]);
        let c = case(
            name,
            Some(&minimal()),
            attack(&mock_with_cert(tsa_cert, vec![root.clone()])),
        );
        let r = &c.reports[0];
        assert!(
            r.is_valid() && r.trusted == Some(true),
            "{name}: {}",
            summary(r)
        );
        assert_eq!(r.pades_level, Some(PadesLevel::BB), "{name}");
        let ts = r.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && !ts.valid && ts.trusted == Some(false),
            "{name}: {ts:?}"
        );
        assert_eq!(ts.problems[0].code, ProblemCode::TsaCertificateUnsuitable);
        cases.push(c);
    }

    // Finding 1, the controls of the extensions Folioxide does not process: well formed on the
    // TSA certificate, the token valid but untrusted (DELIBERATE).
    for (serial, name, ext_oid, value) in [
        (
            0x0A5E_0D10,
            "tst-tsa-cert-proxycertinfo-valid",
            PROXY_CERT_INFO,
            tokens::seq(&[tokens::seq(&[oid(&[
                0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x15, 0x01,
            ])])]),
        ),
        (
            0x0A5E_0D11,
            "tst-tsa-cert-ipaddrblocks-inherit",
            IP_ADDR_BLOCKS,
            tokens::seq(&[tokens::seq(&[
                tokens::octets(&[0x00, 0x01]),
                vec![0x05, 0x00],
            ])]),
        ),
    ] {
        let extension = decoys::extension(ext_oid, false, &value);
        let tsa_cert = decoys::tsa_cert_with(serial, &tsa_subject, &[extension]);
        let signed = sign_bt_params(
            &minimal(),
            &rsa2048(),
            SignatureOptions::new(time()),
            TimestampParams::new().with_nonce(Some(NONCE)),
            &Tsa(mock_with_cert(tsa_cert, vec![root.clone()])),
        )
        .unwrap();
        let c = case(name, Some(&minimal()), signed);
        let r = &c.reports[0];
        assert!(
            r.is_valid() && r.trusted == Some(true),
            "{name}: {}",
            summary(r)
        );
        assert_eq!(r.pades_level, Some(PadesLevel::BT), "{name}");
        let ts = r.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && ts.valid && ts.trusted == Some(false),
            "{name}: {ts:?}"
        );
        cases.push(c);
    }

    // Finding 1 on document signatures (nc_doc8/{leafjunk,cajunk}-{subjdirattrs,pkup,
    // tlsfeature}): ours untrusted, as pyHanko.
    let signer_cert = cert("signer-rsa2048.pem");
    for (name, leaf, intermediate) in [
        (
            "doc-signer-subjdirattrs-junk",
            decoys::signer_cert_with(
                0x0A5E_0D20,
                &[decoys::extension(
                    SUBJECT_DIRECTORY_ATTRIBUTES,
                    false,
                    &[0x05, 0x00],
                )],
            ),
            cert("intermediate.pem"),
        ),
        (
            "doc-signer-pkup-junk",
            decoys::signer_cert_with(
                0x0A5E_0D21,
                &[decoys::extension(
                    PRIVATE_KEY_USAGE_PERIOD,
                    false,
                    &junk_oid,
                )],
            ),
            cert("intermediate.pem"),
        ),
        (
            "doc-signer-ca-tlsfeature-junk",
            signer_cert.clone(),
            decoys::intermediate_with(
                0x0A5E_0D22,
                &[decoys::extension(TLS_FEATURE, false, &[0x05, 0x00])],
            ),
        ),
    ] {
        let signer = LocalSigner::from_pem(
            &pki_text("signer-rsa2048.key.pem"),
            &pem(&[leaf, intermediate]),
            None,
        )
        .unwrap();
        let c = case(name, Some(&minimal()), sign_bt(&minimal(), &signer));
        let r = &c.reports[0];
        assert!(
            r.is_valid() && r.trusted == Some(false),
            "{name}: {}",
            summary(r)
        );
        assert_eq!(
            r.pades_level,
            Some(PadesLevel::BT),
            "{name}: {}",
            summary(r)
        );
        cases.push(c);
    }

    // Finding 2: RSASSA-PSS-params with a repeated field, which a last-wins reader takes for
    // SHA-256 with a 32-byte salt: on the TSA certificate's id-RSASSA-PSS key, and in the
    // token's signatureAlgorithm. Ours: the token not valid; pyHanko compares the first salt
    // length (invalid), OpenSSL cannot decode them.
    let pss = |fields: &[Vec<u8>]| tokens::seq(fields);
    let sha2 = |last: u8| {
        tokens::seq(&[
            oid(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, last]),
            vec![0x05, 0x00],
        ])
    };
    let sha256 = sha2(0x01);
    let hash = |h: &[u8]| tokens::der(0xA0, h);
    let mgf1 = |h: &[u8]| {
        tokens::der(
            0xA1,
            &tokens::seq(&[
                oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08]),
                h.to_vec(),
            ]),
        )
    };
    let salt = |s: u8| tokens::der(0xA2, &tokens::der(0x02, &[s]));
    let dup_salt = pss(&[hash(&sha256), mgf1(&sha256), salt(64), salt(32)]);
    let dup_hash = pss(&[hash(&sha2(0x03)), hash(&sha256), mgf1(&sha256), salt(32)]);
    let rsassa_pss = oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A]);
    let tsa = cert("tsa.pem");
    let spki_case = |serial: u32, name: &str, params: &[u8]| {
        let pss_tsa = decoys::issue(
            serial,
            &decoys::subject_of(&root),
            &decoys::subject_of(&tsa),
            &decoys::pss_spki(&decoys::spki_of(&tsa), Some(params)),
            &decoys::tsa_extensions(),
            &decoys::signer("root.key.pem", "root.pem"),
        );
        let pdf = attack(&mock_tsa_pss_for(pss_tsa, 32, MockTsaOptions::default()));
        case(name, Some(&minimal()), pdf)
    };
    let token_case = |name: &str, params: Vec<u8>| {
        let options = MockTsaOptions {
            signature_algorithm: Some(tokens::seq(&[rsassa_pss.clone(), params])),
            ..MockTsaOptions::default()
        };
        let pdf = attack(&mock_tsa_pss_for(cert("tsa.pem"), 32, options));
        case(name, Some(&minimal()), pdf)
    };
    for c in [
        spki_case(0x0A5E_0D30, "tst-tsa-spki-pss-params-dup-salt", &dup_salt),
        token_case("tst-pss-params-dup-salt", dup_salt.clone()),
        token_case("tst-pss-params-dup-hash", dup_hash.clone()),
    ] {
        let r = &c.reports[0];
        assert!(
            r.is_valid() && r.trusted == Some(true),
            "{}: {}",
            c.name,
            summary(r)
        );
        assert_eq!(r.pades_level, Some(PadesLevel::BB), "{}", c.name);
        let ts = r.timestamp.as_ref().unwrap();
        assert!(ts.intact && !ts.valid, "{}: {ts:?}", c.name);
        assert!(
            c.last_entry().contains("\"timestamp\": \"invalid\""),
            "{}",
            c.name
        );
        cases.push(c);
    }
    cases
}

/// The cases of the M4 closing round (findings 7, 8 and 11) whose certificates are issued at
/// test time.
fn closing_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    let root = cert("root.pem");
    let tsa = cert("tsa.pem");
    let tsa_subject = subject_name(&tsa);
    let oid = |content: &[u8]| tokens::der(0x06, content);
    let uri = tokens::der(0x86, b"http://example.org/ca");
    let distribution_points =
        tokens::seq(&[tokens::seq(&[tokens::der(0xA0, &tokens::der(0xA0, &uri))])]);

    // Findings 8 and 11 (r9-crit-{ski,aki,aia,freshestcrl,qcstatements}, the expert's
    // crit/tsa-{aki,ski,aia}): a TSA certificate with a critical extension OpenSSL's
    // X509_supported_extension does not list. Ours: the certificate is unsuitable, the token
    // not valid, B-B; OpenSSL: unhandled critical extension; pyHanko trusts it (STRICTER).
    let root_ski = decoys::ski_of(&root).unwrap();
    let access = |method: u8| {
        tokens::seq(&[tokens::seq(&[
            oid(&[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, method]),
            uri.clone(),
        ])])
    };
    for (serial, name, ext_oid, value) in [
        (
            0x0A5E_0E00,
            "tst-tsa-cert-critical-ski",
            &[0x55, 0x1D, 0x0E][..],
            tokens::octets(&[1, 2, 3, 4]),
        ),
        (
            0x0A5E_0E01,
            "tst-tsa-cert-critical-aki",
            &[0x55, 0x1D, 0x23][..],
            tokens::seq(&[tokens::der(0x80, &root_ski)]),
        ),
        (
            0x0A5E_0E02,
            "tst-tsa-cert-critical-aia",
            &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01][..],
            access(0x02),
        ),
        (
            0x0A5E_0E03,
            "tst-tsa-cert-critical-freshestcrl",
            &[0x55, 0x1D, 0x2E][..],
            distribution_points.clone(),
        ),
        (
            0x0A5E_0E04,
            "tst-tsa-cert-critical-qcstatements",
            &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x03][..],
            // QcCompliance (0.4.0.1862.1.1, ETSI EN 319 412-5).
            tokens::seq(&[tokens::seq(&[oid(&[0x04, 0x00, 0x8E, 0x46, 0x01, 0x01])])]),
        ),
    ] {
        let extension = decoys::extension(ext_oid, true, &value);
        let tsa_cert = decoys::tsa_cert_with(serial, &tsa_subject, &[extension]);
        let c = case(
            name,
            Some(&minimal()),
            attack(&mock_with_cert(tsa_cert, vec![root.clone()])),
        );
        let r = &c.reports[0];
        assert!(
            r.is_valid() && r.trusted == Some(true),
            "{name}: {}",
            summary(r)
        );
        assert_eq!(r.pades_level, Some(PadesLevel::BB), "{name}");
        let ts = r.timestamp.as_ref().unwrap();
        assert!(
            ts.intact && !ts.valid && ts.trusted == Some(false),
            "{name}: {ts:?}"
        );
        assert_eq!(ts.problems[0].code, ProblemCode::TsaCertificateUnsuitable);
        cases.push(c);
    }
    // The controls, through Folioxide's own signer: critical extensions OpenSSL handles
    // (r9-crit-crldp, r9-crit-ocspnocheck). B-T, the token trusted, by all three.
    for (serial, name, ext_oid, value) in [
        (
            0x0A5E_0E10,
            "tst-tsa-cert-critical-crldp",
            &[0x55, 0x1D, 0x1F][..],
            distribution_points.clone(),
        ),
        (
            0x0A5E_0E11,
            "tst-tsa-cert-critical-ocspnocheck",
            &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x05][..],
            vec![0x05, 0x00],
        ),
    ] {
        let extension = decoys::extension(ext_oid, true, &value);
        let tsa_cert = decoys::tsa_cert_with(serial, &tsa_subject, &[extension]);
        let signed = sign_bt_params(
            &minimal(),
            &rsa2048(),
            SignatureOptions::new(time()),
            TimestampParams::new().with_nonce(Some(NONCE)),
            &Tsa(mock_with_cert(tsa_cert, vec![root.clone()])),
        )
        .unwrap();
        let c = case(name, Some(&minimal()), signed);
        assert_sound_bt(&c);
        cases.push(c);
    }

    // Finding 7 (r9-pssanchor-int-both, r9-pss256-anchor-hash-alg-int-params; controls
    // r9-pssanchor-null-both-control): RSASSA-PSS-params whose hash AlgorithmIdentifiers carry
    // an INTEGER as parameters (RFC 4055 §2.1 allows absent or NULL) on the id-RSASSA-PSS key
    // of the TSA's trust anchor, and of the TSA's intermediate. The TSA certificate is signed
    // with RSASSA-PSS SHA-256 / 32 by that key. Ours: the key is unusable, the token valid but
    // untrusted; pyHanko compares the parameters structurally and does not trust it either.
    // The anchor has a name of its own, so the test root (the same key without the
    // restriction) cannot stand in for it. Folioxide's signer embeds the tokens (trust is not
    // a signing-side check).
    let sha256 = |parameters: &[u8]| {
        tokens::seq(&[
            oid(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]),
            parameters.to_vec(),
        ])
    };
    let pss_params = |hash: &[u8]| {
        tokens::seq(&[
            tokens::der(0xA0, hash),
            tokens::der(
                0xA1,
                &tokens::seq(&[
                    oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08]),
                    hash.to_vec(),
                ]),
            ),
            tokens::der(0xA2, &tokens::der(0x02, &[32])),
        ])
    };
    let null = vec![0x05, 0x00];
    let integer = tokens::der(0x02, &[0x01]);
    let anchor_name = decoys::test_name(tokens::der(0x0C, b"Folioxide Test PSS-only Root"));
    let intermediate_name =
        decoys::test_name(tokens::der(0x0C, b"Folioxide Test PSS-only Intermediate"));
    let sign_with = |tsa_cert: Vec<u8>, extra: Vec<Vec<u8>>| {
        sign_bt_params(
            &minimal(),
            &rsa2048(),
            SignatureOptions::new(time()),
            TimestampParams::new().with_nonce(Some(NONCE)),
            &Tsa(mock_with_cert(tsa_cert, extra)),
        )
        .unwrap()
    };
    for (serial, label, hash_parameters, trusted) in [
        (0x0A5E_0E20, "control", null, true),
        (0x0A5E_0E28, "hash-params-int", integer, false),
    ] {
        let params = pss_params(&sha256(&hash_parameters));
        // The anchor: the root's key restricted by `params`.
        let anchor = decoys::issue_pss(
            serial,
            &anchor_name,
            &anchor_name,
            &decoys::pss_spki(&decoys::spki_of(&root), Some(&params)),
            &decoys::ca_extensions(),
            "root.key.pem",
        );
        let tsa_cert = decoys::issue_pss(
            serial + 1,
            &anchor_name,
            &tsa_subject,
            &decoys::spki_of(&tsa),
            &decoys::tsa_extensions(),
            "root.key.pem",
        );
        let name = format!("tst-tsa-anchor-pss-{label}");
        let c = case_with_anchor(
            &name,
            Some(&minimal()),
            sign_with(tsa_cert, Vec::new()),
            Some(&anchor),
        );
        // The intermediate: the RSA-3072 signer's key restricted by `params`, under the root.
        let intermediate = decoys::issue(
            serial + 2,
            &decoys::subject_of(&root),
            &intermediate_name,
            &decoys::pss_spki(&decoys::spki_of(&cert("signer-rsa3072.pem")), Some(&params)),
            &decoys::ca_extensions(),
            &decoys::signer("root.key.pem", "root.pem"),
        );
        let tsa_cert = decoys::issue_pss(
            serial + 3,
            &intermediate_name,
            &tsa_subject,
            &decoys::spki_of(&tsa),
            &decoys::tsa_extensions(),
            "signer-rsa3072.key.pem",
        );
        let name = format!("tst-tsa-inter-pss-{label}");
        let d = case(
            &name,
            Some(&minimal()),
            sign_with(tsa_cert, vec![intermediate, root.clone()]),
        );
        for c in [c, d] {
            let r = &c.reports[0];
            assert!(
                r.is_valid() && r.trusted == Some(true),
                "{}: {}",
                c.name,
                summary(r)
            );
            assert_eq!(r.pades_level, Some(PadesLevel::BT), "{}", c.name);
            let ts = r.timestamp.as_ref().unwrap();
            assert!(
                ts.intact && ts.valid && ts.trusted == Some(trusted),
                "{}: {ts:?}",
                c.name
            );
            assert_eq!(c.checked(), trusted, "{}", c.name);
            cases.push(c);
        }
    }
    cases
}

/// The subjectKeyIdentifier of `tsa.pem` (gen-pki.sh: `subjectKeyIdentifier = hash`).
fn tsa_subject_key_identifier() -> Vec<u8> {
    let tsa = cert("tsa.pem");
    let marker = [0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14];
    let at = tsa.windows(marker.len()).position(|w| w == marker).unwrap() + marker.len();
    tsa[at..at + 20].to_vec()
}

/// `name` as a `directoryName` GeneralName (`[4] EXPLICIT Name`).
fn directory_name(name: &[u8]) -> Vec<u8> {
    bt_support::decoys::der(0xA4, name)
}

/// The subject `Name` TLV of a DER certificate (tbsCertificate: version, serial, signature,
/// issuer, validity, subject).
fn subject_name(der: &[u8]) -> Vec<u8> {
    let element = |d: &[u8]| -> (usize, usize) {
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
    };
    let (h, _) = element(der);
    let tbs = &der[h..];
    let (h, l) = element(tbs);
    let mut rest = &tbs[h..h + l];
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let (h, l) = element(rest);
        fields.push(&rest[..h + l]);
        rest = &rest[h + l..];
    }
    let skip = usize::from(fields[0][0] == 0xA0);
    fields[skip + 4].to_vec()
}

/// B-T + P = 2 certification + a visible appearance in one signature (brief §6.3), when the
/// certification (WP4.1A) and appearance (WP4.3A) stages are in: until then `prepare` refuses
/// them with `Unsupported` and the case is not made (the other cases are enough for the
/// suite's minimum). Certification alone is used while only the appearance is missing.
fn certified_visible_case() -> Option<Case> {
    let certified =
        SignatureOptions::new(time()).with_certification(Some(DocMdpPermissions::FormFilling));
    let visible = certified
        .clone()
        .with_appearance(Some(SignatureAppearance::new(Rect::new(
            72.0, 600.0, 272.0, 660.0,
        ))));
    for (name, options) in [
        ("bt-certified-p2-visible", visible),
        ("bt-certified-p2", certified),
    ] {
        match sign_bt_params(
            &minimal(),
            &rsa2048(),
            options,
            TimestampParams::new().with_nonce(Some(NONCE)),
            &Tsa(mock_tsa()),
        ) {
            Ok(pdf) => {
                let c = case(name, Some(&minimal()), pdf);
                assert_sound_bt(&c);
                assert_eq!(c.reports[0].docmdp, Some(2), "{name}");
                return Some(c);
            }
            Err(e) if e.code() == ErrorCode::Unsupported => continue,
            Err(e) => panic!("{name}: {e}"),
        }
    }
    None
}

/// Every case of the suite.
fn cases() -> Vec<Case> {
    let mut cases = Vec::new();

    // Single signatures.
    cases.push(mock_case("bt-p256-mock", &minimal(), &p256()));
    cases.push(mock_case("bt-rsa2048-mock", &minimal(), &rsa2048()));
    {
        let signed = sign_bt_params(
            &minimal(),
            &p384(),
            SignatureOptions::new(time()).with_digest(Some(DigestAlgorithm::Sha384)),
            TimestampParams::new()
                .with_nonce(Some(NONCE))
                .with_digest(Some(DigestAlgorithm::Sha384)),
            &Tsa(mock_tsa()),
        )
        .unwrap();
        let c = case("bt-p384-sha384", Some(&minimal()), signed);
        assert_sound_bt(&c);
        let r = &c.reports[0];
        assert_eq!(r.digest_algorithm.as_deref(), Some("sha384"));
        let ts = r.timestamp.as_ref().unwrap();
        assert_eq!(ts.imprint_algorithm.as_deref(), Some("sha384"));
        cases.push(c);
    }
    {
        // A named TSA, a signingTime in the token and a genTime with a fraction.
        let named = Tsa(mock_tsa_with(
            "tsa.pem",
            MockTsaOptions {
                tsa_name: true,
                signing_time_attr: true,
                gen_time: "20261010120030.125Z".into(),
                ..MockTsaOptions::default()
            },
        ));
        let signed = sign_bt_params(
            &minimal(),
            &p256(),
            SignatureOptions::new(time()),
            TimestampParams::new().with_nonce(Some(NONCE)),
            &named,
        )
        .unwrap();
        let c = case("bt-p256-tsa-name-fraction", Some(&minimal()), signed);
        assert_sound_bt(&c);
        let ts = c.reports[0].timestamp.as_ref().unwrap();
        assert_eq!(ts.gen_time, "2026-10-10T12:00:30.125Z");
        assert!(ts.tsa_name.is_some());
        cases.push(c);
    }
    {
        // adbe.pkcs7.detached with a token: pyHanko and OpenSSL check the token; it is not a
        // PAdES signature (pades false).
        let signed = sign_bt_params(
            &minimal(),
            &rsa2048(),
            SignatureOptions::new(time()).with_sub_filter(SubFilter::AdbePkcs7Detached),
            TimestampParams::new().with_nonce(Some(NONCE)),
            &Tsa(mock_tsa()),
        )
        .unwrap();
        let c = case("bt-adbe-pkcs7-detached", Some(&minimal()), signed);
        let r = &c.reports[0];
        assert!(r.is_valid() && r.pades_level.is_none(), "{}", summary(r));
        let ts = r.timestamp.as_ref().unwrap();
        assert!(ts.intact && ts.valid && ts.trusted == Some(true), "{ts:?}");
        cases.push(c);
    }

    {
        // QA round 2 finding 4: names compare as RFC 5280 §7.1 and OpenSSL's X509_NAME_cmp do.
        // The TSTInfo tsa name is the TSA's subject as PrintableString and the ESS v1 and v2
        // issuerSerial names the issuer lowercased; the second identifiers name the root.
        let tsa = cert("tsa.pem");
        let renamed = Tsa(mock_tsa_with(
            "tsa.pem",
            MockTsaOptions {
                tsa_general_name: Some(directory_name(&reencode_name(
                    &subject_name(&tsa),
                    0x13,
                    false,
                ))),
                ess: Ess::V1AndV2,
                ess_more_cert_ids: vec![cert("root.pem")],
                ess_issuer_name: Some(reencode_name(&issuer_of(&tsa), 0x0C, true)),
                ..MockTsaOptions::default()
            },
        ));
        let signed = sign_bt_params(
            &minimal(),
            &rsa2048(),
            SignatureOptions::new(time()),
            TimestampParams::new().with_nonce(Some(NONCE)),
            &renamed,
        )
        .unwrap();
        let c = case("bt-tsa-names-reencoded", Some(&minimal()), signed);
        assert_sound_bt(&c);
        cases.push(c);
    }

    // RFC 5652 constructs OpenSSL 3.0's `ts -verify` cannot read (known failures above): a token
    // signed with RSASSA-PSS, and one whose SignerInfo names the TSA certificate by its
    // subjectKeyIdentifier. Both go through Folioxide's signing side.
    for (name, tsa) in [
        (
            "tst-rsa-pss-signed",
            Tsa(mock_tsa_pss(MockTsaOptions::default())),
        ),
        (
            "tst-sid-subject-key-identifier",
            Tsa(mock_tsa_with(
                "tsa.pem",
                MockTsaOptions {
                    signer_key_identifier: Some(tsa_subject_key_identifier()),
                    signer_info_version: 3,
                    ..MockTsaOptions::default()
                },
            )),
        ),
    ] {
        let signed = sign_bt_params(
            &minimal(),
            &rsa2048(),
            SignatureOptions::new(time()),
            TimestampParams::new().with_nonce(Some(NONCE)),
            &tsa,
        )
        .unwrap();
        let c = case(name, Some(&minimal()), signed);
        assert_sound_bt(&c);
        cases.push(c);
    }

    // Interoperability: the committed `openssl ts -reply` token.
    cases.push(openssl_case());

    // Several signatures.
    {
        let first = sign_bt(&minimal(), &rsa2048());
        let second = sign_bt(&first, &p256());
        let c = case("bt-two-signatures", Some(&first), second);
        assert_sound_bt(&c);
        assert_eq!(c.reports.len(), 2);
        assert_eq!(c.reports[0].modification, ModificationLevel::FormFilling);
        assert_eq!(c.reports[0].pades_level, Some(PadesLevel::BT));
        cases.push(c);
    }
    {
        let source = pdf_fixture("pyhanko-rsa2048.pdf");
        let c = mock_case("bt-on-pyhanko", &source, &p256());
        assert_eq!(c.reports.len(), 2);
        assert_eq!(c.reports[0].pades_level, Some(PadesLevel::BB));
        assert_eq!(c.reports[0].modification, ModificationLevel::FormFilling);
        cases.push(c);
    }
    cases.extend(certified_visible_case());

    // Document timestamps: pyHanko's file as it is ([signature, timestamp]; the token in
    // /Contents is verified, V7c), then a B-T signature on top of it.
    {
        let pdf = pdf_fixture("pyhanko-doc-timestamp.pdf");
        let c = case("doc-timestamp-passthrough", None, pdf.clone());
        let kinds: Vec<SignatureKind> = c.reports.iter().map(|r| r.kind).collect();
        assert_eq!(
            kinds,
            [SignatureKind::Signature, SignatureKind::DocTimeStamp]
        );
        for r in &c.reports {
            assert!(r.is_valid() && r.trusted == Some(true), "{}", summary(r));
        }
        cases.push(c);
        let c = mock_case("bt-after-doc-timestamp", &pdf, &rsa2048());
        assert_eq!(c.reports.len(), 3);
        assert_eq!(c.reports[1].kind, SignatureKind::DocTimeStamp);
        cases.push(c);
    }

    // Deliberate cases.
    cases.push(eku_noncritical_case());
    cases.push(imprint_mismatch_case());
    cases.extend(stricter_cases());
    cases.extend(round4_cases());
    cases.extend(round5_cases());
    cases.extend(final_fix_2_cases());
    cases.extend(closing_cases());
    cases.extend(final_fix_3_cases());
    cases
}

/// The cases of manager ruling R-30 (b) (M4 adversarial round 10, variants `r10-samealg-*`):
/// certificates signed with an algorithm whose parameters, inside `tbsCertificate` and
/// outside, are absent, NULL, an INTEGER, an OCTET STRING or a SEQUENCE. RSASSA-PKCS1-v1_5
/// takes absent or NULL (RFC 4055 §5), ECDSA none (RFC 5758 §3.2); every other edge is
/// untrusted. For RSA that is pyHanko's verdict (asn1crypto forces NULL parameters on
/// sha256WithRSAEncryption); for ECDSA, pyHanko and OpenSSL trust every shape ([`DELIBERATE`],
/// [`ECDSA_PARAMETERS`]).
fn final_fix_3_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    let root = cert("root.pem");
    let tsa = cert("tsa.pem");
    let intermediate = cert("intermediate.pem");
    let signer_cert = cert("signer-rsa2048.pem");
    let root_key = decoys::signer("root.key.pem", "root.pem");
    let intermediate_key = decoys::signer("intermediate.key.pem", "intermediate.pem");
    let algorithm =
        |oid: &[u8], parameters: &[u8]| tokens::seq(&[tokens::der(0x06, oid), parameters.to_vec()]);
    let parameters: [(&str, Vec<u8>); 5] = [
        ("absent", Vec::new()),
        ("null", vec![0x05, 0x00]),
        ("integer", tokens::der(0x02, &[0x01])),
        ("octet-string", tokens::der(0x04, &[])),
        ("sequence", tokens::seq(&[])),
    ];

    // The TSA certificate signed by the root with sha256WithRSAEncryption. Ours: the token
    // intact and valid, trusted only for absent and NULL parameters; pyHanko the same, while
    // OpenSSL's ts -verify accepts every shape (stricter than OpenSSL).
    for (index, (label, params)) in parameters.iter().enumerate() {
        let tsa_cert = decoys::issue_with(
            0x0A5E_0F00 + index as u32,
            &decoys::subject_of(&root),
            &decoys::subject_of(&tsa),
            &decoys::spki_of(&tsa),
            &decoys::tsa_extensions(),
            &algorithm(
                &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
                params,
            ),
            &|tbs| root_key.sign(DigestAlgorithm::Sha256, tbs).unwrap(),
        );
        let signed = sign_bt_params(
            &minimal(),
            &rsa2048(),
            SignatureOptions::new(time()),
            TimestampParams::new().with_nonce(Some(NONCE)),
            &Tsa(mock_with_cert(tsa_cert, vec![root.clone()])),
        )
        .unwrap();
        let name = format!("tst-tsa-cert-sigalg-params-{label}");
        let c = case(&name, Some(&minimal()), signed);
        let trusted = matches!(*label, "absent" | "null");
        if trusted {
            assert_sound_bt(&c);
        } else {
            let r = &c.reports[0];
            assert!(
                r.is_valid() && r.trusted == Some(true),
                "{name}: {}",
                summary(r)
            );
            assert_eq!(r.pades_level, Some(PadesLevel::BT), "{name}");
            let ts = r.timestamp.as_ref().unwrap();
            assert!(
                ts.intact && ts.valid && ts.trusted == Some(false),
                "{name}: {ts:?}"
            );
            assert!(!c.checked(), "{name}");
        }
        cases.push(c);
    }

    // The document signer's certificate (the RSA-2048 signer's name and key) signed by the
    // P-384 intermediate with ecdsa-with-SHA384. Ours: valid, trusted only without parameters;
    // pyHanko and OpenSSL trust every shape (DELIBERATE rows: stricter than both).
    for (index, (label, params)) in parameters.iter().enumerate() {
        let leaf = decoys::issue_with(
            0x0A5E_0F10 + index as u32,
            &decoys::subject_of(&intermediate),
            &decoys::subject_of(&signer_cert),
            &decoys::spki_of(&signer_cert),
            &[decoys::extension(
                &[0x55, 0x1D, 0x0F],
                true,
                &tokens::der(0x03, &[0x06, 0xC0]),
            )],
            &algorithm(&[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03], params),
            &|tbs| intermediate_key.sign(DigestAlgorithm::Sha384, tbs).unwrap(),
        );
        let signer = LocalSigner::from_pem(
            &pki_text("signer-rsa2048.key.pem"),
            &pem(&[leaf, intermediate.clone()]),
            None,
        )
        .unwrap();
        let name = format!("doc-signer-sigalg-ecdsa-params-{label}");
        let c = case(&name, Some(&minimal()), sign_bt(&minimal(), &signer));
        let r = &c.reports[0];
        let trusted = *label == "absent";
        assert!(
            r.is_valid() && r.trusted == Some(trusted),
            "{name}: {}",
            summary(r)
        );
        assert_eq!(r.pades_level, Some(PadesLevel::BT), "{name}");
        cases.push(c);
    }
    cases
}

#[test]
fn oracle_sign_bt() {
    let cases = cases();
    let checked = cases.iter().filter(|c| c.checked()).count();
    assert!(checked >= 8, "only {checked} checked cases");
    // Every deliberate row names a case of the suite.
    for d in DELIBERATE {
        assert!(
            cases.iter().any(|c| c.name == d.case),
            "deliberate row for unknown case {}",
            d.case
        );
    }
    for (name, _, _) in STRICTER {
        assert!(
            cases.iter().any(|c| c.name == *name),
            "stricter row for unknown case {name}"
        );
    }
    let mut written = 0;
    for case in &cases {
        if let Some(input) = &case.input {
            emit_file(SUITE, &format!("{}.input.pdf", case.name), input).unwrap();
        }
        for (file, bytes) in &case.files {
            emit_file(SUITE, file, bytes).unwrap();
        }
        if emit_case(SUITE, &case.name, &case.pdf, &case.expect)
            .unwrap()
            .is_some()
        {
            written += 1;
        }
    }
    assert_eq!(written, if EMIT_ENABLED { cases.len() } else { 0 });
}
