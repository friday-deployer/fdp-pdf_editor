//! A mock RFC 3161 timestamp authority for tests (M4 brief §3.4; DECISIONS D13 D-21).
//!
//! [`MockTsa`] answers a DER `TimeStampReq` with a deterministic DER `TimeStampResp`, signing
//! the token's signed attributes through a closure (RSA PKCS#1 v1.5 with SHA-256 over the
//! `0x31`-tagged attributes), so the testkit needs no RSA implementation. It reads requests and
//! writes its DER with its own small reader and writer, independently of
//! `folioxide_sign::tsp`, so the two cross-check each other (brief R-20). [`MockTsaOptions`]
//! bends the response for the negative tests: another status, nonce or imprint, a missing or
//! wrong ESS attribute, another eContentType, two SignerInfos, and so on.
//!
//! The token it writes has the shape of OpenSSL's `ts -reply` tokens (brief §0): SignedData
//! version 3, digestAlgorithm sha256 **with NULL**, the TSTInfo as eContent, the TSA
//! certificate and the extra certificates, and one SignerInfo with the signed attributes
//! content-type, message-digest, (signing-time) and ESS signing-certificate-v2 (or v1), signed
//! with `sha256WithRSAEncryption`. A request that does not parse is answered with `rejection`
//! and failInfo `badDataFormat`.
//!
//! Tests adapt it to `folioxide_sign::tsp::Timestamper`:
//!
//! ```text
//! struct T(MockTsa);
//! impl folioxide_sign::tsp::Timestamper for T {
//!     fn timestamp(&self, request: &[u8]) -> folioxide_sign::Result<Vec<u8>> {
//!         Ok(self.0.respond(request))
//!     }
//! }
//! ```

use std::fmt;

use sha1::Digest as _;

/// What the mock does with a request field it echoes: the nonce or the message imprint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Echo {
    /// Copy the request's value (the default).
    #[default]
    Echo,
    /// Leave it out of the token (for the imprint: an empty hash).
    Omit,
    /// Write these bytes instead (the INTEGER content octets of a nonce, the hash of an
    /// imprint).
    Replace(Vec<u8>),
}

/// Which ESS signing-certificate attribute the token's signed attributes carry (RFC 2634,
/// RFC 5035, RFC 5816).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Ess {
    /// `signing-certificate-v2` with the SHA-256 certHash of the TSA certificate (the default).
    #[default]
    V2,
    /// `signing-certificate` (v1) with the SHA-1 certHash.
    V1,
    /// Neither attribute.
    Missing,
    /// `signing-certificate-v2` whose certHash is not the TSA certificate's.
    WrongHash,
    /// Both `signing-certificate-v2` and `signing-certificate` (v1), each identifying the TSA
    /// certificate.
    V1AndV2,
    /// A correct `signing-certificate-v2` and a `signing-certificate` (v1) whose certHash is
    /// not the TSA certificate's (OpenSSL checks both, pyHanko only v2).
    V2AndWrongV1,
}

/// A re-encoding of DER bytes (for [`MockTsaOptions::signed_attrs_encoding`]).
pub type Reencode = fn(&[u8]) -> Vec<u8>;

/// How [`MockTsa::respond`] builds its response. [`Default`] is a well-formed `granted`
/// response.
#[derive(Clone, Debug)]
pub struct MockTsaOptions {
    /// The TSTInfo `genTime`, as the GeneralizedTime text (default `"20261010120030Z"`).
    pub gen_time: String,
    /// The TSTInfo `serialNumber` (default 1).
    pub serial: u64,
    /// The TSTInfo `policy`, a dotted OID (default `"1.2.3.4.1"`).
    pub policy: String,
    /// The `PKIStatus` (default 0, `granted`). A token is written for 0 and 1 only.
    pub status: u8,
    /// The `statusString`, when set.
    pub status_string: Option<String>,
    /// The `failInfo` bits (bit `i` is `PKIFailureInfo` bit `i`), when set.
    pub fail_info: Option<u32>,
    /// The TSTInfo `nonce` (default: echoed).
    pub nonce: Echo,
    /// The TSTInfo `messageImprint` hash (default: echoed).
    pub imprint: Echo,
    /// The ESS signing-certificate attribute (default v2).
    pub ess: Ess,
    /// The token's eContentType, a dotted OID (default `id-ct-TSTInfo`,
    /// `"1.2.840.113549.1.9.16.1.4"`).
    pub econtent_type: String,
    /// Whether the token carries the TSA certificate and the extra certificates (default
    /// true).
    pub include_certs: bool,
    /// The TSTInfo `accuracy` in seconds, when set (default 1).
    pub accuracy_secs: Option<u32>,
    /// Whether the TSTInfo carries `tsa` (the TSA certificate's subject as a `directoryName`;
    /// default false).
    pub tsa_name: bool,
    /// Whether the signed attributes carry a signing-time attribute, as OpenSSL's tokens do
    /// (default false).
    pub signing_time_attr: bool,
    /// How many SignerInfos the token has (default 1; 2 for the negative test).
    pub signer_infos: u8,
    /// The TSTInfo `version` (default 1).
    pub tst_version: u32,
    /// The TSTInfo `tsa` GeneralName (DER, without the `[0]` around it), written instead of the
    /// TSA certificate's subject, when set (whatever `tsa_name` says).
    pub tsa_general_name: Option<Vec<u8>>,
    /// The TSTInfo messageImprint `hashAlgorithm` (a DER AlgorithmIdentifier), written instead
    /// of the request's, when set.
    pub imprint_algorithm: Option<Vec<u8>>,
    /// More ESS certificate identifiers after the TSA certificate's, in every ESS attribute the
    /// token carries: one per entry, over its bytes with the attribute's hash and with the
    /// issuerSerial of the certificate it is (none for bytes that are no certificate, which
    /// name nothing; default none).
    pub ess_more_cert_ids: Vec<Vec<u8>>,
    /// The ESS certificate identifiers of every ESS attribute the token carries, in order: one
    /// per entry, as for `ess_more_cert_ids`, written **instead of** the TSA certificate's and
    /// `ess_more_cert_ids` when set (so the first may name another certificate; default none).
    pub ess_cert_ids: Option<Vec<Vec<u8>>>,
    /// The identifiers of the `signing-certificate` (v1) attribute only, overriding the two
    /// fields above for it when set (default none).
    pub ess_v1_cert_ids: Option<Vec<Vec<u8>>>,
    /// The issuer `Name` (DER) written into the issuerSerial of every identifier that names a
    /// certificate, instead of that certificate's own issuer, when set (default none).
    pub ess_issuer_name: Option<Vec<u8>>,
    /// The SignerInfo identifies the TSA certificate by this subjectKeyIdentifier
    /// (`sid [0] IMPLICIT`) instead of its issuerAndSerialNumber, when set; RFC 5652 §5.3 then
    /// wants `signer_info_version` 3 (default none).
    pub signer_key_identifier: Option<Vec<u8>>,
    /// `SignedData.version` (default 3, RFC 5652 §5.1).
    pub signed_data_version: u8,
    /// The SignerInfo `version` (default 1, for its issuerAndSerialNumber; RFC 5652 §5.3).
    pub signer_info_version: u8,
    /// `SignedData.digestAlgorithms` (DER AlgorithmIdentifiers), when set; default sha256 with
    /// NULL.
    pub digest_algorithms: Option<Vec<Vec<u8>>>,
    /// More elements (DER) of `SignedData.certificates`, sorted in with the certificates, for
    /// example something that is not a certificate (default none; needs `include_certs`).
    pub extra_certificate_entries: Vec<Vec<u8>>,
    /// The SignerInfo `signatureAlgorithm` (a DER AlgorithmIdentifier), when set; default
    /// sha256WithRSAEncryption with NULL.
    pub signature_algorithm: Option<Vec<u8>>,
    /// More signed attributes (whole DER `Attribute`s), sorted in with the others, for example
    /// one whose values are not in DER `SET OF` order (default none).
    pub extra_signed_attributes: Vec<Vec<u8>>,
    /// Re-encodes the DER signed attributes (the `SET`, tag `0x31`) before they are signed: the
    /// TSA signs and sends what this returns (its first octet becomes the `[0]` tag), for
    /// example a BER encoding (default none).
    pub signed_attrs_encoding: Option<Reencode>,
    /// The `policies` element (DER) written after `certs` in every `SigningCertificate(V2)`
    /// value, when set (default none).
    pub ess_policies: Option<Vec<u8>>,
    /// An element (DER, its `[1]` tag included) written at the end of the TSTInfo, where its
    /// `extensions` go, when set (default none).
    pub tst_extensions: Option<Vec<u8>>,
    /// Elements (DER) of `SignedData.crls` (`[1] IMPLICIT`, after the certificates), sorted,
    /// for example a CRL whose issuer name OpenSSL cannot decode; none and no `[1]` by default.
    pub crls: Vec<Vec<u8>>,
}

impl Default for MockTsaOptions {
    fn default() -> Self {
        MockTsaOptions {
            gen_time: "20261010120030Z".to_owned(),
            serial: 1,
            policy: "1.2.3.4.1".to_owned(),
            status: 0,
            status_string: None,
            fail_info: None,
            nonce: Echo::Echo,
            imprint: Echo::Echo,
            ess: Ess::V2,
            econtent_type: "1.2.840.113549.1.9.16.1.4".to_owned(),
            include_certs: true,
            accuracy_secs: Some(1),
            tsa_name: false,
            signing_time_attr: false,
            signer_infos: 1,
            tst_version: 1,
            tsa_general_name: None,
            imprint_algorithm: None,
            ess_more_cert_ids: Vec::new(),
            ess_cert_ids: None,
            ess_v1_cert_ids: None,
            ess_issuer_name: None,
            signer_key_identifier: None,
            signed_data_version: 3,
            signer_info_version: 1,
            digest_algorithms: None,
            extra_certificate_entries: Vec::new(),
            signature_algorithm: None,
            extra_signed_attributes: Vec::new(),
            signed_attrs_encoding: None,
            ess_policies: None,
            tst_extensions: None,
            crls: Vec::new(),
        }
    }
}

/// The signing closure: RSA PKCS#1 v1.5 with SHA-256 over the DER signed attributes (universal
/// `SET` tag `0x31`), returning the signature value.
pub type SignFn = Box<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;

/// A deterministic mock RFC 3161 TSA (M4 brief §3.4).
pub struct MockTsa {
    /// The TSA certificate (DER), the token's signer.
    tsa_cert_der: Vec<u8>,
    /// More certificates (DER) the token carries after the TSA certificate.
    extra: Vec<Vec<u8>>,
    /// Signs the token's signed attributes.
    sign: SignFn,
    /// How responses are built.
    options: MockTsaOptions,
}

impl MockTsa {
    /// A mock TSA with the certificate `tsa_cert_der`, the `extra` certificates (an
    /// intermediate, the root) and `sign`, which signs with the certificate's key, and the
    /// default [`MockTsaOptions`].
    pub fn new(tsa_cert_der: Vec<u8>, extra: Vec<Vec<u8>>, sign: SignFn) -> Self {
        MockTsa {
            tsa_cert_der,
            extra,
            sign,
            options: MockTsaOptions::default(),
        }
    }

    /// The same TSA, building responses with `options`.
    #[must_use]
    pub fn with_options(mut self, options: MockTsaOptions) -> Self {
        self.options = options;
        self
    }

    /// The options responses are built with.
    pub fn options(&self) -> &MockTsaOptions {
        &self.options
    }

    /// The DER `TimeStampResp` for the DER `TimeStampReq` `request_der`: deterministic for
    /// the same request and options (the closure signs deterministically).
    ///
    /// A request that does not parse gets `rejection` with failInfo `badDataFormat`.
    pub fn respond(&self, request_der: &[u8]) -> Vec<u8> {
        let o = &self.options;
        let Some(request) = Request::parse(request_der) else {
            let refused = status_info(2, Some("the request does not parse"), Some(1 << 5));
            return response(&refused, None);
        };
        let status = status_info(o.status, o.status_string.as_deref(), o.fail_info);
        if o.status > 1 {
            return response(&status, None);
        }
        let token = self.token(&request);
        response(&status, Some(&token))
    }

    /// The bare `TimeStampToken` (ContentInfo) [`respond`](Self::respond) would send for
    /// `request_der`; `None` when the request does not parse.
    pub fn token_for(&self, request_der: &[u8]) -> Option<Vec<u8>> {
        Request::parse(request_der).map(|request| self.token(&request))
    }

    /// The token for a parsed request.
    fn token(&self, request: &Request) -> Vec<u8> {
        let o = &self.options;
        let tst_info = self.tst_info(request);
        let cert = Cert::parse(&self.tsa_cert_der);

        // Signed attributes, DER-sorted (X.690 §11.6).
        let mut attrs = vec![
            attribute(
                OID_CONTENT_TYPE,
                &tlv(TAG_OID, &oid_bytes(&o.econtent_type)),
            ),
            attribute(
                OID_MESSAGE_DIGEST,
                &tlv(TAG_OCTET_STRING, &sha2::Sha256::digest(&tst_info)),
            ),
        ];
        if o.signing_time_attr {
            let utc = o.gen_time.get(2..14).unwrap_or("000101000000");
            attrs.push(attribute(
                OID_SIGNING_TIME,
                &tlv(TAG_UTC_TIME, format!("{utc}Z").as_bytes()),
            ));
        }
        // IssuerSerial ::= SEQUENCE { GeneralNames { [4] issuer }, serial }
        let issuer_serial = |c: &Cert| {
            let issuer = o.ess_issuer_name.as_ref().unwrap_or(&c.issuer);
            let names = tlv(TAG_SEQUENCE, &tlv(0xA4, issuer));
            tlv(TAG_SEQUENCE, &[names, c.serial.clone()].concat())
        };
        // ESSCertID(v2) ::= SEQUENCE { certHash, issuerSerial }; the v2 hashAlgorithm is the
        // DEFAULT sha256, so it is omitted.
        let cert_id = |hash: &[u8], cert: Option<&Cert>| -> Vec<u8> {
            let mut content = tlv(TAG_OCTET_STRING, hash);
            if let Some(cert) = cert {
                content.extend(issuer_serial(cert));
            }
            tlv(TAG_SEQUENCE, &content)
        };
        // SigningCertificate(V2) ::= SEQUENCE { certs SEQUENCE OF ESSCertID(v2) }: the TSA
        // certificate's identifier (over `first`), then `ess_more_cert_ids`; or `listed`.
        let signing_certificate =
            |hash: fn(&[u8]) -> Vec<u8>, first: &[u8], listed: Option<&Vec<Vec<u8>>>| -> Vec<u8> {
                let mut ids = Vec::new();
                match listed {
                    Some(listed) => {
                        for named in listed {
                            ids.extend(cert_id(&hash(named), Cert::parse(named).as_ref()));
                        }
                    }
                    None => {
                        ids.extend(cert_id(&hash(first), cert.as_ref()));
                        for more in &o.ess_more_cert_ids {
                            ids.extend(cert_id(&hash(more), Cert::parse(more).as_ref()));
                        }
                    }
                }
                let mut content = tlv(TAG_SEQUENCE, &ids);
                if let Some(policies) = &o.ess_policies {
                    content.extend_from_slice(policies);
                }
                tlv(TAG_SEQUENCE, &content)
            };
        let sha256 = |data: &[u8]| sha2::Sha256::digest(data).to_vec();
        let sha1 = |data: &[u8]| sha1::Sha1::digest(data).to_vec();
        let not_the_tsa: &[u8] = b"not the TSA certificate";
        let tsa_cert: &[u8] = &self.tsa_cert_der;
        let (v2, v1): (Option<&[u8]>, Option<&[u8]>) = match o.ess {
            Ess::V2 => (Some(tsa_cert), None),
            Ess::V1 => (None, Some(tsa_cert)),
            Ess::Missing => (None, None),
            Ess::WrongHash => (Some(not_the_tsa), None),
            Ess::V1AndV2 => (Some(tsa_cert), Some(tsa_cert)),
            Ess::V2AndWrongV1 => (Some(tsa_cert), Some(not_the_tsa)),
        };
        if let Some(first) = v2 {
            attrs.push(attribute(
                OID_SIGNING_CERTIFICATE_V2,
                &signing_certificate(sha256, first, o.ess_cert_ids.as_ref()),
            ));
        }
        if let Some(first) = v1 {
            let listed = o.ess_v1_cert_ids.as_ref().or(o.ess_cert_ids.as_ref());
            attrs.push(attribute(
                OID_SIGNING_CERTIFICATE,
                &signing_certificate(sha1, first, listed),
            ));
        }
        attrs.extend(o.extra_signed_attributes.iter().cloned());
        attrs.sort_by(|a, b| der_order(a, b));
        let mut signed_attrs = tlv(TAG_SET, &attrs.concat());
        if let Some(encode) = o.signed_attrs_encoding {
            signed_attrs = encode(&signed_attrs);
        }
        let signature = (self.sign)(&signed_attrs);
        let mut implicit_attrs = signed_attrs;
        if let Some(first) = implicit_attrs.first_mut() {
            *first = 0xA0;
        }

        let sha256 = tlv(
            TAG_SEQUENCE,
            &[tlv(TAG_OID, OID_SHA256), NULL.to_vec()].concat(),
        );
        let signature_algorithm = o.signature_algorithm.clone().unwrap_or_else(|| {
            tlv(
                TAG_SEQUENCE,
                &[tlv(TAG_OID, OID_SHA256_WITH_RSA), NULL.to_vec()].concat(),
            )
        });
        let sid = match (&o.signer_key_identifier, &cert) {
            (Some(ski), _) => tlv(0x80, ski),
            (None, Some(c)) => tlv(TAG_SEQUENCE, &[c.issuer.clone(), c.serial.clone()].concat()),
            (None, None) => tlv(
                TAG_SEQUENCE,
                &[tlv(TAG_SEQUENCE, &[]), tlv(TAG_INTEGER, &[1])].concat(),
            ),
        };
        let signer_info = tlv(
            TAG_SEQUENCE,
            &[
                tlv(TAG_INTEGER, &[o.signer_info_version]),
                sid,
                sha256.clone(),
                implicit_attrs,
                signature_algorithm,
                tlv(TAG_OCTET_STRING, &signature),
            ]
            .concat(),
        );
        let signer_infos: Vec<u8> = (0..o.signer_infos.max(1))
            .flat_map(|_| signer_info.clone())
            .collect();

        let encap = tlv(
            TAG_SEQUENCE,
            &[
                tlv(TAG_OID, &oid_bytes(&o.econtent_type)),
                tlv(0xA0, &tlv(TAG_OCTET_STRING, &tst_info)),
            ]
            .concat(),
        );
        let digest_algorithms = match &o.digest_algorithms {
            Some(members) => members.concat(),
            None => sha256.clone(),
        };
        let mut parts = vec![
            tlv(TAG_INTEGER, &[o.signed_data_version]),
            tlv(TAG_SET, &digest_algorithms),
            encap,
        ];
        if o.include_certs {
            let mut certs: Vec<&[u8]> = vec![&self.tsa_cert_der];
            certs.extend(self.extra.iter().map(Vec::as_slice));
            certs.extend(o.extra_certificate_entries.iter().map(Vec::as_slice));
            certs.sort_by(|a, b| der_order(a, b));
            parts.push(tlv(0xA0, &certs.concat()));
        }
        if !o.crls.is_empty() {
            let mut crls: Vec<&[u8]> = o.crls.iter().map(Vec::as_slice).collect();
            crls.sort_by(|a, b| der_order(a, b));
            parts.push(tlv(0xA1, &crls.concat()));
        }
        parts.push(tlv(TAG_SET, &signer_infos));
        let signed_data = tlv(TAG_SEQUENCE, &parts.concat());
        tlv(
            TAG_SEQUENCE,
            &[tlv(TAG_OID, OID_SIGNED_DATA), tlv(0xA0, &signed_data)].concat(),
        )
    }

    /// The DER TSTInfo for `request`.
    fn tst_info(&self, request: &Request) -> Vec<u8> {
        let o = &self.options;
        let hash = match &o.imprint {
            Echo::Echo => request.hash.clone(),
            Echo::Omit => Vec::new(),
            Echo::Replace(bytes) => bytes.clone(),
        };
        let algorithm = o
            .imprint_algorithm
            .clone()
            .unwrap_or_else(|| request.algorithm.clone());
        let imprint = tlv(
            TAG_SEQUENCE,
            &[algorithm, tlv(TAG_OCTET_STRING, &hash)].concat(),
        );
        let mut parts = vec![
            tlv(TAG_INTEGER, &unsigned_integer(u64::from(o.tst_version))),
            tlv(TAG_OID, &oid_bytes(&o.policy)),
            imprint,
            tlv(TAG_INTEGER, &unsigned_integer(o.serial)),
            tlv(TAG_GENERALIZED_TIME, o.gen_time.as_bytes()),
        ];
        if let Some(seconds) = o.accuracy_secs {
            parts.push(tlv(
                TAG_SEQUENCE,
                &tlv(TAG_INTEGER, &unsigned_integer(u64::from(seconds))),
            ));
        }
        let nonce = match &o.nonce {
            Echo::Echo => request.nonce.clone(),
            Echo::Omit => None,
            Echo::Replace(bytes) => Some(bytes.clone()),
        };
        if let Some(nonce) = nonce {
            parts.push(tlv(TAG_INTEGER, &nonce));
        }
        if let Some(general_name) = &o.tsa_general_name {
            parts.push(tlv(0xA0, general_name));
        } else if o.tsa_name
            && let Some(cert) = Cert::parse(&self.tsa_cert_der)
        {
            // tsa [0] EXPLICIT GeneralName, directoryName [4] EXPLICIT Name.
            parts.push(tlv(0xA0, &tlv(0xA4, &cert.subject)));
        }
        if let Some(extensions) = &o.tst_extensions {
            parts.push(extensions.clone());
        }
        tlv(TAG_SEQUENCE, &parts.concat())
    }
}

impl fmt::Debug for MockTsa {
    /// The certificate sizes and the options; not the closure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockTsa")
            .field("tsa_cert_len", &self.tsa_cert_der.len())
            .field("extra_certs", &self.extra.len())
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

// ---- DER, written and read by hand (independent of folioxide_sign, brief R-20) ----------------

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_UTC_TIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const NULL: [u8; 2] = [0x05, 0x00];

/// 1.2.840.113549.1.7.2 id-signedData.
const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
/// 2.16.840.1.101.3.4.2.1 id-sha256.
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// 1.2.840.113549.1.1.11 sha256WithRSAEncryption.
const OID_SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
/// 1.2.840.113549.1.9.3 content-type.
const OID_CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
/// 1.2.840.113549.1.9.4 message-digest.
const OID_MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
/// 1.2.840.113549.1.9.5 signing-time.
const OID_SIGNING_TIME: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];
/// 1.2.840.113549.1.9.16.2.12 id-aa-signingCertificate.
const OID_SIGNING_CERTIFICATE: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0C,
];
/// 1.2.840.113549.1.9.16.2.47 id-aa-signingCertificateV2.
const OID_SIGNING_CERTIFICATE_V2: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
];

/// The DER TLV `tag || length || content` (definite length, one-octet tag).
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let octets: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | octets.len() as u8);
        out.extend(octets);
    }
    out.extend_from_slice(content);
    out
}

/// `Attribute ::= SEQUENCE { attrType OID, attrValues SET { value } }`.
fn attribute(oid: &[u8], value: &[u8]) -> Vec<u8> {
    tlv(
        TAG_SEQUENCE,
        &[tlv(TAG_OID, oid), tlv(TAG_SET, value)].concat(),
    )
}

/// The content octets of the minimal positive INTEGER `value`.
fn unsigned_integer(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let skip = bytes.iter().take_while(|&&b| b == 0).count().min(7);
    let mut out: Vec<u8> = bytes.get(skip..).unwrap_or_default().to_vec();
    if out.first().is_some_and(|&b| b & 0x80 != 0) {
        out.insert(0, 0);
    }
    out
}

/// The DER content octets of a dotted OID (X.690 §8.19); empty for text that is not one.
fn oid_bytes(dotted: &str) -> Vec<u8> {
    let arcs: Option<Vec<u64>> = dotted.split('.').map(|a| a.parse().ok()).collect();
    let Some(arcs) = arcs else {
        return Vec::new();
    };
    let (Some(&first), Some(&second)) = (arcs.first(), arcs.get(1)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut push = |mut value: u64| {
        let mut group = vec![(value & 0x7F) as u8];
        value >>= 7;
        while value > 0 {
            group.push(0x80 | (value & 0x7F) as u8);
            value >>= 7;
        }
        group.reverse();
        out.extend(group);
    };
    push(first.saturating_mul(40).saturating_add(second));
    for &arc in arcs.iter().skip(2) {
        push(arc);
    }
    out
}

/// The order of two encodings in a DER `SET OF` (X.690 §11.6: as octet strings, the shorter
/// padded with zeros at its end).
fn der_order(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let len = a.len().max(b.len());
    (0..len)
        .map(|i| {
            a.get(i)
                .copied()
                .unwrap_or(0)
                .cmp(&b.get(i).copied().unwrap_or(0))
        })
        .find(|o| o.is_ne())
        .unwrap_or(std::cmp::Ordering::Equal)
}

/// `PKIStatusInfo ::= SEQUENCE { status, statusString PKIFreeText OPTIONAL, failInfo BIT STRING
/// OPTIONAL }`.
fn status_info(status: u8, text: Option<&str>, fail_info: Option<u32>) -> Vec<u8> {
    let mut parts = tlv(TAG_INTEGER, &unsigned_integer(u64::from(status)));
    if let Some(text) = text {
        parts.extend(tlv(TAG_SEQUENCE, &tlv(TAG_UTF8_STRING, text.as_bytes())));
    }
    if let Some(bits) = fail_info {
        // Bit i is the i-th bit from the top of the first octet on (X.690 §8.6.2); trailing
        // zero octets are dropped and the unused bits counted, as DER requires for a named
        // bit list (X.690 §11.2.2).
        let mut octets: Vec<u8> = (0..4u32)
            .map(|octet| {
                (0..8u32).fold(0u8, |acc, bit| {
                    if bits & (1 << (octet * 8 + bit)) != 0 {
                        acc | (0x80 >> bit)
                    } else {
                        acc
                    }
                })
            })
            .collect();
        while octets.last() == Some(&0) {
            octets.pop();
        }
        let unused = octets.last().map_or(0, |last| last.trailing_zeros() as u8);
        let mut content = vec![unused];
        content.extend(octets);
        parts.extend(tlv(TAG_BIT_STRING, &content));
    }
    tlv(TAG_SEQUENCE, &parts)
}

/// `TimeStampResp ::= SEQUENCE { status PKIStatusInfo, timeStampToken OPTIONAL }`.
fn response(status: &[u8], token: Option<&[u8]>) -> Vec<u8> {
    tlv(TAG_SEQUENCE, &[status, token.unwrap_or_default()].concat())
}

/// One DER element: `(tag, content, whole element)`.
type Element<'a> = (u8, &'a [u8], &'a [u8]);

/// The DER element at the start of `input`.
fn read(input: &[u8]) -> Option<Element<'_>> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 {
            return None;
        }
        let len = input
            .get(2..2 + count)?
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, 2 + count)
    };
    let end = header.checked_add(len)?;
    Some((tag, input.get(header..end)?, input.get(..end)?))
}

/// The elements of a constructed element's content, in order.
fn elements(mut content: &[u8]) -> Option<Vec<Element<'_>>> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let element = read(content)?;
        content = content.get(element.2.len()..)?;
        out.push(element);
    }
    Some(out)
}

/// What the mock needs from a request.
struct Request {
    /// The whole `hashAlgorithm` AlgorithmIdentifier, echoed into the TSTInfo.
    algorithm: Vec<u8>,
    /// The `hashedMessage`.
    hash: Vec<u8>,
    /// The nonce's INTEGER content octets.
    nonce: Option<Vec<u8>>,
}

impl Request {
    fn parse(der: &[u8]) -> Option<Request> {
        let (tag, content, whole) = read(der)?;
        if tag != TAG_SEQUENCE || whole.len() != der.len() {
            return None;
        }
        let fields = elements(content)?;
        let (version, imprint) = (fields.first()?, fields.get(1)?);
        if version.0 != TAG_INTEGER || version.1 != [1] || imprint.0 != TAG_SEQUENCE {
            return None;
        }
        let imprint = elements(imprint.1)?;
        let (algorithm, hash) = (imprint.first()?, imprint.get(1)?);
        if algorithm.0 != TAG_SEQUENCE || hash.0 != TAG_OCTET_STRING {
            return None;
        }
        let nonce = fields
            .iter()
            .skip(2)
            .find(|f| f.0 == TAG_INTEGER)
            .map(|f| f.1.to_vec());
        Some(Request {
            algorithm: algorithm.2.to_vec(),
            hash: hash.1.to_vec(),
            nonce,
        })
    }
}

/// What the mock needs from its certificate.
struct Cert {
    /// The issuer `Name` TLV.
    issuer: Vec<u8>,
    /// The serial number `INTEGER` TLV.
    serial: Vec<u8>,
    /// The subject `Name` TLV.
    subject: Vec<u8>,
}

impl Cert {
    fn parse(der: &[u8]) -> Option<Cert> {
        let (_, content, _) = read(der)?;
        let tbs = elements(content)?;
        let fields = elements(tbs.first()?.1)?;
        let skip = usize::from(fields.first()?.0 == 0xA0);
        let serial = fields.get(skip)?;
        let issuer = fields.get(skip + 2)?;
        let subject = fields.get(skip + 4)?;
        Some(Cert {
            issuer: issuer.2.to_vec(),
            serial: serial.2.to_vec(),
            subject: subject.2.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tsa() -> MockTsa {
        MockTsa::new(vec![0x30, 0x00], vec![], Box::new(|_| vec![0; 256]))
    }

    /// `TimeStampReq` with a SHA-256 imprint of zeros and nonce 5.
    fn request() -> Vec<u8> {
        let algorithm = tlv(
            TAG_SEQUENCE,
            &[tlv(TAG_OID, OID_SHA256), NULL.to_vec()].concat(),
        );
        let imprint = tlv(
            TAG_SEQUENCE,
            &[algorithm, tlv(TAG_OCTET_STRING, &[0; 32])].concat(),
        );
        tlv(
            TAG_SEQUENCE,
            &[
                tlv(TAG_INTEGER, &[1]),
                imprint,
                tlv(TAG_INTEGER, &[5]),
                vec![0x01, 0x01, 0xFF],
            ]
            .concat(),
        )
    }

    #[test]
    fn options_default_to_a_granted_response() {
        let o = MockTsaOptions::default();
        assert_eq!(o.gen_time, "20261010120030Z");
        assert_eq!(o.policy, "1.2.3.4.1");
        assert_eq!((o.status, o.serial, o.signer_infos), (0, 1, 1));
        assert_eq!(
            (o.nonce, o.imprint, o.ess),
            (Echo::Echo, Echo::Echo, Ess::V2)
        );
        assert_eq!(o.econtent_type, "1.2.840.113549.1.9.16.1.4");
        assert!(o.include_certs);
        assert_eq!(o.tst_version, 1);
        assert_eq!((o.signed_data_version, o.signer_info_version), (3, 1));
        assert!(o.tsa_general_name.is_none() && o.imprint_algorithm.is_none());
        assert!(o.digest_algorithms.is_none() && o.signature_algorithm.is_none());
        assert!(o.ess_more_cert_ids.is_empty() && o.extra_certificate_entries.is_empty());
        assert!(o.extra_signed_attributes.is_empty() && o.signed_attrs_encoding.is_none());
        assert!(o.ess_policies.is_none() && o.tst_extensions.is_none());
        assert!(o.crls.is_empty());
    }

    #[test]
    fn responses_are_deterministic_and_carry_a_token() {
        let tsa = tsa();
        let response = tsa.respond(&request());
        assert_eq!(response, tsa.respond(&request()));
        let (tag, content, _) = read(&response).unwrap();
        assert_eq!(tag, TAG_SEQUENCE);
        let fields = elements(content).unwrap();
        assert_eq!(fields.len(), 2, "status and token");
        assert_eq!(fields[0].2, [0x30, 0x03, 0x02, 0x01, 0x00]);
        assert_eq!(Some(fields[1].2.to_vec()), tsa.token_for(&request()));
        let debug = format!("{tsa:?}");
        assert!(
            debug.contains("MockTsa") && debug.contains("tsa_cert_len: 2"),
            "{debug}"
        );
    }

    #[test]
    fn refusals_and_garbage() {
        let tsa = tsa().with_options(MockTsaOptions {
            status: 2,
            status_string: Some("busy".into()),
            fail_info: Some(1 << 14),
            ..MockTsaOptions::default()
        });
        assert_eq!(tsa.options().status, 2);
        let response = tsa.respond(&request());
        let (_, content, _) = read(&response).unwrap();
        let fields = elements(content).unwrap();
        assert_eq!(fields.len(), 1, "no token");
        // timeNotAvailable (14): the 7th bit of the second octet, 1 unused bit.
        assert!(fields[0].2.ends_with(&[0x03, 0x03, 0x01, 0x00, 0x02]));
        let garbage = tsa.respond(b"garbage");
        assert!(
            garbage.ends_with(&[0x03, 0x02, 0x02, 0x04]),
            "{garbage:02x?}"
        );
        assert_eq!(tsa.token_for(b"garbage"), None);
    }

    #[test]
    fn mock_tsa_is_send_sync() {
        fn send_sync<T: Send + Sync + 'static>() {}
        send_sync::<MockTsa>();
    }

    #[test]
    fn der_helpers() {
        assert_eq!(tlv(0x04, &[1, 2]), [0x04, 0x02, 1, 2]);
        let long = tlv(0x04, &[0; 200]);
        assert_eq!(&long[..3], &[0x04, 0x81, 200]);
        assert_eq!(long.len(), 203);
        assert_eq!(oid_bytes("1.2.3.4.1"), [0x2A, 0x03, 0x04, 0x01]);
        assert_eq!(oid_bytes("2.16.840.1.101.3.4.2.1"), OID_SHA256);
        assert_eq!(oid_bytes("not an oid"), Vec::<u8>::new());
        assert_eq!(unsigned_integer(0), [0]);
        assert_eq!(unsigned_integer(0x80), [0, 0x80]);
        assert_eq!(der_order(&[1, 2], &[1, 2, 0]), std::cmp::Ordering::Equal);
        assert_eq!(read(&[0x30, 0x84, 0, 0, 0, 1, 5]).map(|r| r.0), Some(0x30));
        assert!(read(&[0x30, 0x05]).is_none());
    }
}
