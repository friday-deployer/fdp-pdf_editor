//! Crate-private certificate access: raw slices for CMS identifiers, and typed fields read with
//! the lenient `Raw` profile of `x509-cert`.
//!
//! Raw slices matter because Folioxide never re-encodes a certificate: the CMS `sid` and the ESS
//! `issuerSerial` copy the issuer `Name` and serial `INTEGER` exactly as the certificate encodes
//! them (M3 brief §4.3), and a verifier compares them byte for byte first.

use der::Decode as _;
use x509_cert::certificate::{CertificateInner, Raw};

use crate::cms::tlv::{self, TAG_BIT_STRING, TAG_CONTEXT_0, TAG_INTEGER, TAG_SEQUENCE};
use crate::error::{Error, Result};
use crate::keys::public::PublicKey;

/// The deepest nesting followed when locating the parts of a certificate.
const CERT_DEPTH: usize = 8;

/// A certificate parsed with the lenient `Raw` profile.
pub(crate) type RawProfileCertificate = CertificateInner<Raw>;

/// The raw parts of a DER certificate (RFC 5280 §4.1).
#[derive(Clone, Copy, Debug)]
pub(crate) struct CertParts<'a> {
    /// `tbsCertificate.serialNumber`: the whole `INTEGER` TLV.
    pub serial: &'a [u8],
    /// The content octets of the serial number `INTEGER`.
    pub serial_content: &'a [u8],
    /// `tbsCertificate.signature`: the whole `AlgorithmIdentifier` TLV, not checked to be one
    /// (RFC 5280 §4.1.2.3).
    pub signature: &'a [u8],
    /// `tbsCertificate.issuer`: the whole `Name` TLV.
    pub issuer: &'a [u8],
    /// `tbsCertificate.subject`: the whole `Name` TLV.
    pub subject: &'a [u8],
    /// `tbsCertificate.subjectPublicKeyInfo`: the whole TLV.
    pub spki: &'a [u8],
    /// The whole `tbsCertificate` TLV, exactly as encoded: the bytes the issuer signed.
    pub tbs: &'a [u8],
}

impl<'a> CertParts<'a> {
    /// Locates the parts of `der` without decoding them.
    ///
    /// # Errors
    /// [`Error::Certificate`] when the bytes are not shaped like a certificate.
    pub(crate) fn parse(der: &'a [u8]) -> Result<CertParts<'a>> {
        let malformed =
            |what: &str| Error::Certificate(format!("the certificate does not parse: {what}"));
        let cert = tlv::read_exact(der, CERT_DEPTH).map_err(|e| malformed(&e.to_string()))?;
        if cert.tag != TAG_SEQUENCE {
            return Err(malformed("not a SEQUENCE"));
        }
        let tbs = tlv::children(der, &cert, 0, CERT_DEPTH)
            .next()
            .ok_or_else(|| malformed("no tbsCertificate"))?
            .map_err(|e| malformed(&e.to_string()))?;
        if tbs.tag != TAG_SEQUENCE {
            return Err(malformed("tbsCertificate is not a SEQUENCE"));
        }
        let mut fields = tlv::children(der, &tbs, 1, CERT_DEPTH);
        let mut next = || -> Result<tlv::Element> {
            fields
                .next()
                .ok_or_else(|| malformed("tbsCertificate is too short"))?
                .map_err(|e| malformed(&e.to_string()))
        };
        let mut serial = next()?;
        if serial.tag == TAG_CONTEXT_0 {
            // version [0] EXPLICIT Version DEFAULT v1
            serial = next()?;
        }
        if serial.tag != TAG_INTEGER {
            return Err(malformed("serialNumber is not an INTEGER"));
        }
        let signature = next()?;
        let issuer = next()?;
        let _validity = next()?;
        let subject = next()?;
        let spki = next()?;
        for (name, element) in [
            ("issuer", &issuer),
            ("subject", &subject),
            ("subjectPublicKeyInfo", &spki),
        ] {
            if element.tag != TAG_SEQUENCE {
                return Err(malformed(&format!("{name} is not a SEQUENCE")));
            }
        }
        Ok(CertParts {
            serial: serial.raw(der),
            serial_content: serial.content(der),
            signature: signature.raw(der),
            issuer: issuer.raw(der),
            subject: subject.raw(der),
            spki: spki.raw(der),
            tbs: tbs.raw(der),
        })
    }

    /// The certificate's outer `signatureAlgorithm` (the whole `AlgorithmIdentifier` TLV) and
    /// the contents of its `signatureValue` BIT STRING without the unused-bits octet
    /// (RFC 5280 §4.1.1.2, §4.1.1.3).
    ///
    /// # Errors
    /// [`Error::Certificate`] when the certificate has no such fields, or the BIT STRING has
    /// unused bits.
    pub(crate) fn outer_signature(der: &'a [u8]) -> Result<(&'a [u8], &'a [u8])> {
        let malformed = |what: &str| {
            Error::Certificate(format!("the certificate signature does not parse: {what}"))
        };
        let cert = tlv::read_exact(der, CERT_DEPTH).map_err(|e| malformed(&e.to_string()))?;
        let fields = tlv::children_vec(der, &cert, 0, CERT_DEPTH, 3)
            .map_err(|e| malformed(&e.to_string()))?;
        let [_tbs, algorithm, value] = fields.as_slice() else {
            return Err(malformed(
                "expected tbsCertificate, signatureAlgorithm, signatureValue",
            ));
        };
        if algorithm.tag != TAG_SEQUENCE {
            return Err(malformed("signatureAlgorithm is not a SEQUENCE"));
        }
        if value.tag != TAG_BIT_STRING {
            return Err(malformed("signatureValue is not a BIT STRING"));
        }
        match value.content(der).split_first() {
            Some((0, bits)) => Ok((algorithm.raw(der), bits)),
            _ => Err(malformed("signatureValue has unused bits")),
        }
    }

    /// The certificate's public key.
    ///
    /// # Errors
    /// As [`PublicKey::from_spki_der`].
    pub(crate) fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_spki_der(self.spki)
    }
}

/// Decodes a certificate with the lenient `Raw` profile (serial numbers of any length, any time
/// encoding).
///
/// # Errors
/// [`Error::Certificate`] when it does not decode.
pub(crate) fn decode(der: &[u8]) -> Result<RawProfileCertificate> {
    RawProfileCertificate::from_der(der)
        .map_err(|e| Error::Certificate(format!("the certificate does not parse: {e}")))
}

/// The subjectKeyIdentifier extension value (RFC 5280 §4.2.1.2), when present and decodable.
pub(crate) fn subject_key_identifier(der: &[u8]) -> Option<Vec<u8>> {
    let cert = decode(der).ok()?;
    let (_, ski) = cert
        .tbs_certificate()
        .get_extension::<x509_cert::ext::pkix::SubjectKeyIdentifier>()
        .ok()??;
    Some(ski.0.as_bytes().to_vec())
}

/// Whether two DER `Name`s denote the same name: byte-identical, or with equal canonical forms
/// ([`canonical_name`]), the comparison RFC 5280 §7.1 asks for and OpenSSL's `X509_NAME_cmp`
/// makes (M4 QA round 2 finding 4). A re-encoded name (another string type, case or spacing,
/// another order inside an RDN, other length octets) still matches; a name that does not read
/// as a `Name` only matches itself.
pub(crate) fn names_match(a: &[u8], b: &[u8]) -> bool {
    if a == b {
        return true;
    }
    match (canonical_name(a), canonical_name(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// The most attributes (over all RDNs) [`canonical_name`] reads in one name; a longer name
/// only matches itself byte for byte.
const MAX_NAME_ATTRIBUTES: usize = 256;

/// The canonical value of one `AttributeTypeAndValue` (RFC 5280 §4.1.2.4).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CanonicalValue {
    /// A UTF8String, BMPString, UniversalString, PrintableString, TeletexString, IA5String or
    /// VisibleString, as UTF-8 without leading and trailing white space, with every inner run
    /// of white space one space and ASCII letters lowercased (OpenSSL `asn1_string_canon`).
    Text(Vec<u8>),
    /// Any other value: its identifier octet and content octets, compared exactly.
    Other(u8, Vec<u8>),
}

/// A `Name` in canonical form: its RDNs in order, each a sorted list of (attribute type OID
/// content octets, canonical value).
pub(crate) type CanonicalName = Vec<Vec<(Vec<u8>, CanonicalValue)>>;

/// The canonical form of the DER `Name` `der`, as OpenSSL's `x509_name_canon` and
/// `asn1_string_canon` compute it for `X509_NAME_cmp`:
///
/// - the RDN sequence keeps its order, and the attributes of one RDN are a set (their order
///   does not matter);
/// - the string types of [`CanonicalValue::Text`] are converted to UTF-8 and folded as
///   described there (the one-byte types only when they hold ASCII that every reader decodes
///   alike, see [`canonical_value`]);
/// - every other value stays exactly as encoded.
///
/// Only ASCII is case-folded, as in OpenSSL, so the comparison is never more lenient than
/// OpenSSL's. RFC 4518's full string preparation, which pyHanko's asn1crypto applies, folds
/// more, so it is never more lenient than pyHanko's either. Where the two readers decode a
/// string differently (a one-byte string beyond ASCII, a BMPString with surrogates) the value
/// is compared exactly, which is stricter than both.
///
/// `None` when `der` is not a `Name`, an RDN is empty, a string does not decode, or there are
/// more than [`MAX_NAME_ATTRIBUTES`] attributes.
pub(crate) fn canonical_name(der: &[u8]) -> Option<CanonicalName> {
    let name = tlv::read_exact(der, CERT_DEPTH).ok()?;
    if name.tag != TAG_SEQUENCE {
        return None;
    }
    let rdns = tlv::children_vec(der, &name, 0, CERT_DEPTH, MAX_NAME_ATTRIBUTES).ok()?;
    let mut out = Vec::with_capacity(rdns.len());
    let mut attributes = 0usize;
    for rdn in &rdns {
        if rdn.tag != tlv::TAG_SET {
            return None;
        }
        let entries = tlv::children_vec(der, rdn, 1, CERT_DEPTH, MAX_NAME_ATTRIBUTES).ok()?;
        attributes = attributes.checked_add(entries.len())?;
        // RFC 5280 §4.1.2.4: RelativeDistinguishedName ::= SET SIZE (1..MAX).
        if entries.is_empty() || attributes > MAX_NAME_ATTRIBUTES {
            return None;
        }
        let mut canonical = Vec::with_capacity(entries.len());
        for entry in &entries {
            if entry.tag != TAG_SEQUENCE {
                return None;
            }
            let parts = tlv::children_vec(der, entry, 2, CERT_DEPTH, 2).ok()?;
            let [kind, value] = parts.as_slice() else {
                return None;
            };
            if kind.tag != tlv::TAG_OID {
                return None;
            }
            canonical.push((
                kind.content(der).to_vec(),
                canonical_value(value.tag, value.content(der))?,
            ));
        }
        canonical.sort();
        out.push(canonical);
    }
    Some(out)
}

/// The canonical value of an attribute value with identifier octet `tag` and `content` (the
/// types of OpenSSL's `ASN1_MASK_CANON`, a one-byte type only when it holds ASCII that T.61,
/// ISO 8859-1 and ASCII readers decode alike); `None` when a UTF8String, BMPString or
/// UniversalString does not decode.
///
/// A value holding a character beyond the Basic Multilingual Plane is compared exactly, its
/// string type included: OpenSSL folds a UTF8String and a UniversalString spelling of such a
/// character into one name, asn1crypto (so pyHanko) does not, and a token whose ESS issuer or
/// SignerInfo `sid` relied on that was valid for Folioxide only (M4 QA round 5 finding 34).
/// Exact is never more lenient than either.
fn canonical_value(tag: u8, content: &[u8]) -> Option<CanonicalValue> {
    let text: String = match tag {
        // UTF8String.
        0x0C => std::str::from_utf8(content).ok()?.to_owned(),
        // PrintableString, IA5String, VisibleString, TeletexString: one byte per character, as
        // OpenSSL reads them (ISO 8859-1), but only where every reader agrees on the
        // characters: ASCII, and for TeletexString without the eight ASCII positions where
        // T.61 has other characters (asn1crypto, so pyHanko, decodes T.61). Anything else is
        // compared exactly, which is never more lenient than either.
        0x13 | 0x16 | 0x1A if content.is_ascii() => {
            content.iter().map(|&b| char::from(b)).collect()
        }
        0x14 if content
            .iter()
            .all(|&b| b.is_ascii() && !T61_DIFFERS_FROM_ASCII.contains(&b)) =>
        {
            content.iter().map(|&b| char::from(b)).collect()
        }
        // BMPString: UCS-2, big-endian (a surrogate is no character).
        0x1E => {
            if !content.len().is_multiple_of(2) {
                return None;
            }
            content
                .chunks_exact(2)
                .map(|pair| match pair {
                    [hi, lo] => char::from_u32(u32::from(u16::from_be_bytes([*hi, *lo]))),
                    _ => None,
                })
                .collect::<Option<String>>()?
        }
        // UniversalString: UCS-4, big-endian.
        0x1C => {
            if !content.len().is_multiple_of(4) {
                return None;
            }
            content
                .chunks_exact(4)
                .map(|quad| match quad {
                    [a, b, c, d] => char::from_u32(u32::from_be_bytes([*a, *b, *c, *d])),
                    _ => None,
                })
                .collect::<Option<String>>()?
        }
        _ => return Some(CanonicalValue::Other(tag, content.to_vec())),
    };
    if text.chars().any(|c| u32::from(c) > 0xFFFF) {
        return Some(CanonicalValue::Other(tag, content.to_vec()));
    }
    Some(CanonicalValue::Text(fold_text(text.as_bytes())))
}

/// The ASCII positions where ITU-T T.61 (TeletexString, as asn1crypto decodes it) has another
/// character than ASCII and ISO 8859-1 (as OpenSSL decodes it): `#`, `$`, `\`, `^`, `` ` ``,
/// `{`, `}`, `~`.
const T61_DIFFERS_FROM_ASCII: [u8; 8] = [0x23, 0x24, 0x5C, 0x5E, 0x60, 0x7B, 0x7D, 0x7E];

/// OpenSSL's `ossl_isspace`: space, tab, line feed, vertical tab, form feed, carriage return.
fn is_openssl_space(b: u8) -> bool {
    b == b' ' || (0x09..=0x0D).contains(&b)
}

/// `utf8` without leading and trailing white space, every inner run of white space one space,
/// ASCII letters lowercased, every other byte unchanged (OpenSSL `asn1_string_canon`).
fn fold_text(utf8: &[u8]) -> Vec<u8> {
    let start = utf8
        .iter()
        .position(|&b| !is_openssl_space(b))
        .unwrap_or(utf8.len());
    let end = utf8
        .iter()
        .rposition(|&b| !is_openssl_space(b))
        .map_or(start, |last| last + 1);
    let mut out = Vec::with_capacity(end.saturating_sub(start));
    let mut in_space = false;
    for &b in utf8.get(start..end).unwrap_or_default() {
        if is_openssl_space(b) {
            if !in_space {
                out.push(b' ');
            }
            in_space = true;
        } else {
            out.push(b.to_ascii_lowercase());
            in_space = false;
        }
    }
    out
}

/// `id-ce-subjectAltName` (RFC 5280 §4.2.1.6), checked at compile time.
const OID_SUBJECT_ALT_NAME: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("2.5.29.17");

/// Whether the DER `GeneralName` `general_name` (RFC 5280 §4.2.1.6) is one of the subject names
/// of the certificate `cert_der`: a `directoryName` equal to its subject, or a name equal to an
/// entry of its subjectAltName extensions (a `directoryName` compared with [`names_match`], so
/// another string type or ASCII case still matches, any other choice byte for byte). This is
/// OpenSSL's `ts_check_signer_name` for the TSTInfo `tsa` field (RFC 3161 §2.4.2: it "MUST
/// correspond to one of the subject names included in the certificate"), which compares with
/// `GENERAL_NAME_cmp`: `X509_NAME_cmp` for a `directoryName`, the decoded value for the other
/// choices (the bytes here, which is never more lenient).
///
/// Both sides are decoded as OpenSSL's `GENERAL_NAME` template reads them
/// ([`names::general_name`](super::names::general_name), [`names::general_names`](super::names::general_names);
/// M4 QA round 4 finding 2): a `general_name` that does not decode matches nothing, and a
/// subjectAltName extension that does not decode ends the search, as OpenSSL's
/// `X509_get_ext_d2i` does there. A certificate that does not decode matches nothing.
pub(crate) fn has_subject_name(cert_der: &[u8], general_name: &[u8]) -> bool {
    let Ok(parts) = CertParts::parse(cert_der) else {
        return false;
    };
    let Ok(name) = tlv::read_exact(general_name, CERT_DEPTH) else {
        return false;
    };
    if super::names::general_name(general_name, &name, 0).is_err() {
        return false;
    }
    // directoryName [4] EXPLICIT Name: the Name inside.
    let directory_name = |input: &[u8], element: &tlv::Element| -> Option<Vec<u8>> {
        if element.tag != tlv::TAG_CONTEXT_4 {
            return None;
        }
        let inner = tlv::children_vec(input, element, 0, CERT_DEPTH, 1).ok()?;
        let [name] = inner.as_slice() else {
            return None;
        };
        Some(name.raw(input).to_vec())
    };
    let wanted_directory = directory_name(general_name, &name);
    if wanted_directory
        .as_deref()
        .is_some_and(|wanted| names_match(wanted, parts.subject))
    {
        return true;
    }
    let Ok(certificate) = decode(cert_der) else {
        return false;
    };
    let Some(extensions) = certificate.tbs_certificate().extensions() else {
        return false;
    };
    for extension in extensions
        .iter()
        .filter(|e| e.extn_id == OID_SUBJECT_ALT_NAME)
    {
        let names = extension.extn_value.as_bytes();
        let Some(entries) = super::names::general_names(names) else {
            return false;
        };
        for entry in entries {
            let matches = match (&wanted_directory, directory_name(names, &entry)) {
                (Some(wanted), Some(present)) => names_match(wanted, &present),
                (None, None) => entry.raw(names) == general_name,
                _ => false,
            };
            if matches {
                return true;
            }
        }
    }
    false
}

/// Whether two serial number `INTEGER` contents denote the same value.
pub(crate) fn serials_match(a: &[u8], b: &[u8]) -> bool {
    tlv::integer_canonical(a) == tlv::integer_canonical(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cms::tlv::{
        TAG_CONTEXT_0, TAG_CONTEXT_3, TAG_INTEGER, TAG_NULL, TAG_OCTET_STRING, TAG_OID, TAG_SET,
        TAG_UTC_TIME, tlv, tlv_parts,
    };

    /// `Name { RDN { CN = cn } }`.
    fn name(cn: &str) -> Vec<u8> {
        let atv = tlv_parts(
            TAG_SEQUENCE,
            &[
                &tlv(TAG_OID, &[0x55, 0x04, 0x03]),
                &tlv(0x0C, cn.as_bytes()),
            ],
        );
        tlv(TAG_SEQUENCE, &tlv(TAG_SET, &atv))
    }

    /// A certificate-shaped DER (unsigned: nothing here checks signatures) with subject `cn`
    /// and, when given, a subjectAltName extension holding `san` (DER GeneralNames content).
    fn certificate(cn: &str, san: Option<&[u8]>) -> Vec<u8> {
        let algorithm = tlv_parts(
            TAG_SEQUENCE,
            &[
                &tlv(
                    TAG_OID,
                    &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B],
                ),
                &tlv(TAG_NULL, &[]),
            ],
        );
        let time = tlv(TAG_UTC_TIME, b"250101000000Z");
        let validity = tlv_parts(TAG_SEQUENCE, &[&time, &time]);
        let spki = tlv_parts(
            TAG_SEQUENCE,
            &[
                &tlv_parts(
                    TAG_SEQUENCE,
                    &[
                        &tlv(
                            TAG_OID,
                            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
                        ),
                        &tlv(TAG_NULL, &[]),
                    ],
                ),
                &tlv(TAG_BIT_STRING, &[0x00, 0x00]),
            ],
        );
        let mut tbs_parts = vec![
            tlv(TAG_CONTEXT_0, &tlv(TAG_INTEGER, &[2])),
            tlv(TAG_INTEGER, &[1]),
            algorithm.clone(),
            name("Test Root"),
            validity,
            name(cn),
            spki,
        ];
        if let Some(san) = san {
            let extension = tlv_parts(
                TAG_SEQUENCE,
                &[
                    &tlv(TAG_OID, &[0x55, 0x1D, 0x11]),
                    &tlv(TAG_OCTET_STRING, &tlv(TAG_SEQUENCE, san)),
                ],
            );
            tbs_parts.push(tlv(TAG_CONTEXT_3, &tlv(TAG_SEQUENCE, &extension)));
        }
        let tbs = tlv(TAG_SEQUENCE, &tbs_parts.concat());
        tlv_parts(
            TAG_SEQUENCE,
            &[&tbs, &algorithm, &tlv(TAG_BIT_STRING, &[0x00, 0x00])],
        )
    }

    #[test]
    fn tsa_names_match_the_subject_or_a_subject_alt_name() {
        let directory = |cn: &str| tlv(tlv::TAG_CONTEXT_4, &name(cn));
        let dns = |host: &str| tlv(0x82, host.as_bytes());
        let plain = certificate("Test TSA", None);
        assert!(decode(&plain).is_ok(), "the test certificate decodes");
        assert!(has_subject_name(&plain, &directory("Test TSA")));
        assert!(!has_subject_name(&plain, &directory("Another TSA")));
        assert!(!has_subject_name(&plain, &dns("tsa.example")));

        let san = [dns("tsa.example"), directory("Alias TSA")].concat();
        let with_san = certificate("Test TSA", Some(&san));
        assert!(decode(&with_san).is_ok());
        assert!(has_subject_name(&with_san, &directory("Test TSA")));
        assert!(has_subject_name(&with_san, &dns("tsa.example")));
        assert!(has_subject_name(&with_san, &directory("Alias TSA")));
        assert!(!has_subject_name(&with_san, &dns("other.example")));
        assert!(!has_subject_name(&with_san, &directory("Other")));
        // An rfc822Name with the same bytes is another name.
        assert!(!has_subject_name(&with_san, &tlv(0x81, b"tsa.example")));
        // M4 QA round 4 finding 2: both sides decode as OpenSSL's GENERAL_NAME does. A wanted
        // name that is no GeneralName matches nothing, even with the same bytes in the
        // subjectAltName, and a subjectAltName with an entry that does not decode names nothing.
        let unknown = tlv(0x89, b"tsa");
        let odd_san = certificate(
            "Test TSA",
            Some(&[dns("tsa.example"), unknown.clone()].concat()),
        );
        assert!(!has_subject_name(&odd_san, &unknown));
        assert!(!has_subject_name(&odd_san, &dns("tsa.example")));
        assert!(has_subject_name(&odd_san, &directory("Test TSA")));
        let surrogate_alias = tlv(
            tlv::TAG_CONTEXT_4,
            &tlv(
                TAG_SEQUENCE,
                &tlv(
                    TAG_SET,
                    &tlv_parts(
                        TAG_SEQUENCE,
                        &[
                            &tlv(TAG_OID, &[0x55, 0x04, 0x03]),
                            &tlv(0x1E, &[0xD8, 0x00]),
                        ],
                    ),
                ),
            ),
        );
        let surrogate_san = certificate("Test TSA", Some(&surrogate_alias));
        assert!(!has_subject_name(&surrogate_san, &surrogate_alias));
        // Garbage matches nothing and never panics.
        assert!(!has_subject_name(b"garbage", &dns("tsa.example")));
        assert!(!has_subject_name(&with_san, b"\x82"));
        assert!(!has_subject_name(&with_san, &tlv(tlv::TAG_CONTEXT_4, &[])));
    }

    /// One attribute: (attribute type OID content, value tag, value).
    type Attribute<'a> = (&'a [u8], u8, &'a [u8]);

    /// A `Name` of RDNs, each a list of attributes.
    fn name_of(rdns: &[&[Attribute<'_>]]) -> Vec<u8> {
        let rdns: Vec<Vec<u8>> = rdns
            .iter()
            .map(|entries| {
                let entries: Vec<Vec<u8>> = entries
                    .iter()
                    .map(|(oid, tag, value)| {
                        tlv_parts(TAG_SEQUENCE, &[&tlv(TAG_OID, oid), &tlv(*tag, value)])
                    })
                    .collect();
                tlv(TAG_SET, &entries.concat())
            })
            .collect();
        tlv(TAG_SEQUENCE, &rdns.concat())
    }

    const CN: &[u8] = &[0x55, 0x04, 0x03];
    const O: &[u8] = &[0x55, 0x04, 0x0A];
    const UTF8: u8 = 0x0C;
    const PRINTABLE: u8 = 0x13;
    const BMP: u8 = 0x1E;
    const UNIVERSAL: u8 = 0x1C;

    #[test]
    fn names_compare_as_openssl_x509_name_cmp() {
        // M4 QA round 2 finding 4: RFC 5280 §7.1 and OpenSSL's canonical comparison.
        let base = name_of(&[
            &[(O, UTF8, b"Folioxide Test PKI")],
            &[(CN, UTF8, b"Test TSA")],
        ]);
        let same = |other: &[u8]| assert!(names_match(&base, other), "{other:02X?}");
        let differs = |other: &[u8]| assert!(!names_match(&base, other), "{other:02X?}");
        same(&base);
        // Another string type.
        same(&name_of(&[
            &[(O, PRINTABLE, b"Folioxide Test PKI")],
            &[(CN, PRINTABLE, b"Test TSA")],
        ]));
        let bmp: Vec<u8> = "Test TSA"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        let ucs4: Vec<u8> = "Test TSA"
            .chars()
            .flat_map(|c| u32::from(c).to_be_bytes())
            .collect();
        same(&name_of(&[
            &[(O, UTF8, b"Folioxide Test PKI")],
            &[(CN, BMP, &bmp)],
        ]));
        same(&name_of(&[
            &[(O, UTF8, b"Folioxide Test PKI")],
            &[(CN, UNIVERSAL, &ucs4)],
        ]));
        // ASCII case, and white space at the ends and inside.
        same(&name_of(&[
            &[(O, UTF8, b"FOLIOXIDE test pki")],
            &[(CN, UTF8, b" \tTest \n\r  TSA ")],
        ]));
        // Non-minimal length octets.
        let mut long = name_of(&[
            &[(O, UTF8, b"Folioxide Test PKI")],
            &[(CN, UTF8, b"Test TSA")],
        ]);
        let content = long.split_off(2);
        let mut reencoded = vec![TAG_SEQUENCE, 0x81, u8::try_from(content.len()).unwrap()];
        reencoded.extend(content);
        same(&reencoded);

        // The RDN order, an RDN split or merged, another value, another type, another OID.
        differs(&name_of(&[
            &[(CN, UTF8, b"Test TSA")],
            &[(O, UTF8, b"Folioxide Test PKI")],
        ]));
        differs(&name_of(&[&[
            (O, UTF8, b"Folioxide Test PKI"),
            (CN, UTF8, b"Test TSA"),
        ]]));
        differs(&name_of(&[
            &[(O, UTF8, b"Folioxide Test PKI")],
            &[(CN, UTF8, b"Test TSA2")],
        ]));
        differs(&name_of(&[
            &[(O, UTF8, b"Folioxide Test PKI")],
            &[(CN, UTF8, b"TestTSA")],
        ]));
        differs(&name_of(&[
            &[(O, UTF8, b"Folioxide Test PKI")],
            &[(O, UTF8, b"Test TSA")],
        ]));
        // A NumericString or OCTET STRING is compared exactly, never folded.
        differs(&name_of(&[
            &[(O, UTF8, b"Folioxide Test PKI")],
            &[(CN, 0x12, b"Test TSA")],
        ]));
        differs(&name_of(&[
            &[(O, UTF8, b"Folioxide Test PKI")],
            &[(CN, 0x04, b"Test TSA")],
        ]));

        // Inside one RDN the order does not matter; a repeated attribute counts.
        let pair = name_of(&[&[(O, UTF8, b"a"), (CN, UTF8, b"b")]]);
        assert!(names_match(
            &pair,
            &name_of(&[&[(CN, UTF8, b"B"), (O, UTF8, b"A")]])
        ));
        assert!(!names_match(
            &pair,
            &name_of(&[&[(CN, UTF8, b"b"), (O, UTF8, b"a"), (O, UTF8, b"a")]])
        ));

        // Only ASCII is folded (OpenSSL lowercases ASCII only; RFC 4518 would fold more).
        let accented = name_of(&[&[(CN, UTF8, "É".as_bytes())]]);
        assert!(!names_match(
            &accented,
            &name_of(&[&[(CN, UTF8, "é".as_bytes())]])
        ));
        // A one-byte string beyond ASCII is read differently by OpenSSL (ISO 8859-1: 0xC9 is
        // É) and asn1crypto (T.61), so it is compared exactly; so is a T.61 '#'.
        assert!(!names_match(&accented, &name_of(&[&[(CN, 0x14, &[0xC9])]])));
        assert!(!names_match(
            &accented,
            &name_of(&[&[(CN, PRINTABLE, &[0xC9])]])
        ));
        let hash = name_of(&[&[(CN, UTF8, b"A#1")]]);
        assert!(!names_match(&hash, &name_of(&[&[(CN, 0x14, b"A#1")]])));
        assert!(names_match(&hash, &name_of(&[&[(CN, 0x16, b"a#1")]])));
        assert!(names_match(
            &name_of(&[&[(CN, UTF8, b"Teletex Name")]]),
            &name_of(&[&[(CN, 0x14, b"TELETEX NAME")]])
        ));

        // A character beyond the BMP: compared exactly, string type included (QA round 5
        // finding 34: asn1crypto, so pyHanko, does not fold a UTF-8 and a UCS-4 spelling).
        let emoji_utf8 = name_of(&[&[(CN, UTF8, "x\u{1F600}".as_bytes())]]);
        let emoji_ucs4: Vec<u8> = "x\u{1F600}"
            .chars()
            .flat_map(|c| u32::from(c).to_be_bytes())
            .collect();
        let emoji_universal = name_of(&[&[(CN, UNIVERSAL, &emoji_ucs4)]]);
        assert!(names_match(&emoji_utf8, &emoji_utf8));
        assert!(!names_match(&emoji_utf8, &emoji_universal));
        assert!(!names_match(
            &emoji_utf8,
            &name_of(&[&[(CN, UTF8, "X\u{1F600}".as_bytes())]])
        ));
        // A BMP character beyond ASCII still folds across string types.
        let accented_ucs4: Vec<u8> = "é"
            .chars()
            .flat_map(|c| u32::from(c).to_be_bytes())
            .collect();
        assert!(names_match(
            &name_of(&[&[(CN, UTF8, "é".as_bytes())]]),
            &name_of(&[&[(CN, UNIVERSAL, &accented_ucs4)]])
        ));

        // Empty names match each other; undecodable ones only themselves.
        assert!(names_match(&tlv(TAG_SEQUENCE, &[]), &[0x30, 0x81, 0x00]));
        let bad_utf8 = name_of(&[&[(CN, UTF8, &[0xFF])]]);
        assert!(names_match(&bad_utf8, &bad_utf8));
        assert!(!names_match(
            &bad_utf8,
            &name_of(&[&[(CN, PRINTABLE, &[0xFF])]])
        ));
        let surrogate = name_of(&[&[(CN, BMP, &[0xD8, 0x00])]]);
        assert_eq!(canonical_name(&surrogate), None);
        assert_eq!(canonical_name(&name_of(&[&[(CN, BMP, &[0x00])]])), None);
        assert_eq!(
            canonical_name(&name_of(&[&[(CN, UNIVERSAL, &[0, 0x11, 0, 0])]])),
            None
        );
        assert_eq!(canonical_name(&tlv(TAG_SEQUENCE, &tlv(TAG_SET, &[]))), None);
        assert_eq!(canonical_name(b"garbage"), None);
        assert_eq!(canonical_name(&tlv(TAG_SET, &[])), None);
        // More attributes than the limit: the bytes only.
        let many: Vec<Attribute<'_>> = vec![(CN, UTF8, &b"x"[..]); MAX_NAME_ATTRIBUTES + 1];
        let huge = name_of(&[&many]);
        assert_eq!(canonical_name(&huge), None);
        assert!(names_match(&huge, &huge));
    }

    #[test]
    fn text_folding_is_openssl_asn1_string_canon() {
        assert_eq!(fold_text(b""), b"");
        assert_eq!(fold_text(b" \t\n"), b"");
        assert_eq!(fold_text(b"  A  b\x0B\x0Cc  "), b"a b c");
        assert_eq!(fold_text("Ä  Ö".as_bytes()), "Ä Ö".as_bytes());
        assert_eq!(fold_text(b"x\x00y"), b"x\x00y");
    }
}
