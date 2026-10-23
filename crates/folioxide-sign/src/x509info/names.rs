//! Strict decoding of X.509 names as OpenSSL's ASN.1 templates read them (RFC 5280 §4.1.2.4,
//! §4.2.1.6; M4 QA round 4 findings 1 and 2): a `Name` ([`name_decodes`]) and a `GeneralName`
//! ([`general_name`], [`general_names`]).
//!
//! OpenSSL decodes every `Name` it meets into an `X509_NAME` and computes its canonical form at
//! once (`x509_name_ex_d2i`, `x509_name_canon`), which converts every string value to UTF-8; a
//! `GeneralName` is a CHOICE whose alternatives each have a fixed tag, form and content
//! (`GENERAL_NAME`, `OTHERNAME` and `EDIPARTYNAME` in `v3_genn.c`). A name it cannot decode
//! makes the structure that holds it undecodable: the whole timestamp token for the TSTInfo
//! `tsa` field, a certificate or a CRL of the token or an ESS `issuerSerial`; the extension for
//! a subjectAltName entry. Folioxide reads names the same way wherever it acts on them, so a
//! name Folioxide matches is one OpenSSL reads too.
//!
//! Every check is one bounded pass (depth [`MAX_DEPTH`]) over bytes already in memory.

use crate::cms::MAX_DEPTH;
use crate::cms::tlv::{self, Element};

/// The most entries [`general_names`] reads from one `GeneralNames`; a longer list does not
/// decode (fail closed: it names nothing, and a certificate extension holding it makes the path
/// untrusted).
pub(crate) const MAX_GENERAL_NAMES: usize = 256;

/// `IA5String`, `[n] IMPLICIT`: rfc822Name `[1]`, dNSName `[2]`, uniformResourceIdentifier `[6]`.
const IMPLICIT_IA5_CHOICES: [u8; 3] = [0x81, 0x82, 0x86];
/// `otherName [0] IMPLICIT SEQUENCE`.
const OTHER_NAME: u8 = 0xA0;
/// `x400Address [3] IMPLICIT ORAddress`.
const X400_ADDRESS: u8 = 0xA3;
/// `directoryName [4] EXPLICIT Name`.
const DIRECTORY_NAME: u8 = tlv::TAG_CONTEXT_4;
/// `ediPartyName [5] IMPLICIT SEQUENCE`.
const EDI_PARTY_NAME: u8 = 0xA5;
/// `iPAddress [7] IMPLICIT OCTET STRING`.
const IP_ADDRESS: u8 = 0x87;
/// `registeredID [8] IMPLICIT OBJECT IDENTIFIER`.
const REGISTERED_ID: u8 = 0x88;

/// Whether an attribute value's identifier octet `tag` is one OpenSSL's `X509_NAME_ENTRY`
/// accepts (`ASN1_PRINTABLE`: the string types of `B_ASN1_PRINTABLE`, BIT STRING, SEQUENCE and
/// the types `ASN1_tag2bit` calls unknown): a name with an INTEGER, an OCTET STRING, a time or
/// a VisibleString as a value does not decode there (QA round 1 finding F6, round 3 finding 3).
fn printable_value(tag: u8) -> bool {
    tag & 0xC0 == 0
        && matches!(
            tag & 0x1F,
            3 | 7 | 8 | 9 | 11 | 12 | 13 | 14 | 15 | 16 | 18 | 19 | 20 | 22 | 28 | 29 | 30
        )
}

/// Whether the DER `Name` `name` decodes as OpenSSL's `X509_NAME`; see
/// [`name_element_decodes`].
pub(crate) fn name_decodes(name: &[u8]) -> bool {
    tlv::read_exact(name, MAX_DEPTH).is_ok_and(|element| name_element_decodes(name, &element, 0))
}

/// Whether the `Name` `element` of `input` (read at `depth`) decodes as OpenSSL's `X509_NAME`:
///
/// - a `SEQUENCE OF` `SET OF` `AttributeTypeAndValue`, each a `SEQUENCE` of an OBJECT
///   IDENTIFIER and one value (RFC 5280 §4.1.2.4);
/// - every value of a type `X509_NAME_ENTRY` accepts ([`printable_value`]);
/// - every primitive inside a valid encoding of its universal type, and every UTF8String,
///   BMPString and UniversalString text OpenSSL converts to UTF-8 for the canonical form
///   ([`tlv::check_primitives`], [`tlv::string_converts`]: a BMPString with a surrogate code
///   unit is "illegal characters" there; QA round 4 finding 1).
///
/// Anything else fails.
pub(crate) fn name_element_decodes(input: &[u8], element: &Element, depth: usize) -> bool {
    element.tag == tlv::TAG_SEQUENCE
        && tlv::check_primitives(input, element, depth, MAX_DEPTH).is_ok()
        && tlv::children(input, element, depth, MAX_DEPTH).all(|rdn| {
            rdn.is_ok_and(|rdn| {
                rdn.tag == tlv::TAG_SET
                    && tlv::children(input, &rdn, depth + 1, MAX_DEPTH).all(|atv| {
                        atv.ok()
                            .filter(|atv| atv.tag == tlv::TAG_SEQUENCE)
                            .and_then(|atv| {
                                let parts =
                                    tlv::children_vec(input, &atv, depth + 2, MAX_DEPTH, 2).ok()?;
                                match parts.as_slice() {
                                    [oid, value] => {
                                        Some(oid.tag == tlv::TAG_OID && printable_value(value.tag))
                                    }
                                    _ => None,
                                }
                            })
                            .unwrap_or(false)
                    })
            })
        })
}

/// Whether `element` (of `input`, read at `depth`) is an explicit tag that holds exactly one
/// element, and that element.
fn explicit_one(input: &[u8], element: &Element, depth: usize) -> Option<Element> {
    if !element.is_constructed() {
        return None;
    }
    let inner = tlv::children_vec(input, element, depth, MAX_DEPTH, 1).ok()?;
    match inner.as_slice() {
        [one] => Some(*one),
        _ => None,
    }
}

/// Whether `element` is a `DirectoryString` (RFC 5280 §4.1.2.4): a TeletexString,
/// PrintableString, UniversalString, UTF8String or BMPString, primitive or constructed from
/// segments (OpenSSL's `DIRECTORYSTRING`, `B_ASN1_DIRECTORYSTRING`).
fn directory_string(element: &Element) -> bool {
    matches!(element.tag & !0x20, 0x14 | 0x13 | 0x1C | 0x0C | 0x1E)
}

/// Checks that `element` (of `input`, read at `depth`) is a `GeneralName` (RFC 5280 §4.2.1.6)
/// as OpenSSL's `GENERAL_NAME` template decodes it, and returns what is wrong otherwise:
///
/// ```text
/// GeneralName ::= CHOICE {
///     otherName                 [0] IMPLICIT SEQUENCE { type-id OBJECT IDENTIFIER,
///                                                       value [0] EXPLICIT ANY },
///     rfc822Name                [1] IMPLICIT IA5String,
///     dNSName                   [2] IMPLICIT IA5String,
///     x400Address               [3] IMPLICIT ORAddress,
///     directoryName             [4] EXPLICIT Name,
///     ediPartyName              [5] IMPLICIT SEQUENCE {
///                                   nameAssigner [0] EXPLICIT DirectoryString OPTIONAL,
///                                   partyName    [1] EXPLICIT DirectoryString },
///     uniformResourceIdentifier [6] IMPLICIT IA5String,
///     iPAddress                 [7] IMPLICIT OCTET STRING,
///     registeredID              [8] IMPLICIT OBJECT IDENTIFIER }
/// ```
///
/// - the IA5Strings, the OCTET STRING and the OBJECT IDENTIFIER are primitive (OpenSSL also
///   takes constructed BER segments for the strings; Folioxide does not, which is stricter),
///   the OBJECT IDENTIFIERs valid (X.690 §8.19.2);
/// - the SEQUENCEs and the explicit tags are constructed, every explicit tag holds exactly one
///   element, and the SEQUENCEs hold exactly their fields in order;
/// - an ORAddress is not decoded, as in OpenSSL (`d.x400Address` is kept as a SEQUENCE);
/// - a directoryName's `Name` passes [`name_element_decodes`];
/// - every primitive inside is a valid encoding of its universal type
///   ([`tlv::check_primitives`]).
///
/// Any other identifier octet (a universal or application tag, a context tag above `[8]`, the
/// other form of a listed one) is no GeneralName: OpenSSL fails with "no matching choice type",
/// "wrong tag" or "explicit tag not constructed", and the structure holding the name with it
/// (M4 QA round 4 finding 2).
pub(crate) fn general_name(
    input: &[u8],
    element: &Element,
    depth: usize,
) -> Result<(), &'static str> {
    const NOT_A_CHOICE: &str = "a GeneralName that is none of the choices of RFC 5280 §4.2.1.6 \
                                (a universal or unknown tag, or the wrong form)";
    tlv::check_primitives(input, element, depth, MAX_DEPTH)
        .map_err(|_| "a GeneralName that holds an invalid encoding")?;
    match element.tag {
        OTHER_NAME => {
            const BAD: &str = "an otherName that is not an OBJECT IDENTIFIER and a [0] EXPLICIT \
                               value";
            let parts = tlv::children_vec(input, element, depth, MAX_DEPTH, 2).map_err(|_| BAD)?;
            let [type_id, value] = parts.as_slice() else {
                return Err(BAD);
            };
            if type_id.tag != tlv::TAG_OID
                || value.tag != tlv::TAG_CONTEXT_0
                || explicit_one(input, value, depth + 1).is_none()
            {
                return Err(BAD);
            }
            Ok(())
        }
        tag if IMPLICIT_IA5_CHOICES.contains(&tag) => Ok(()),
        IP_ADDRESS => Ok(()),
        REGISTERED_ID if tlv::valid_oid(element.content(input)) => Ok(()),
        REGISTERED_ID => Err("a registeredID that is not a valid OBJECT IDENTIFIER"),
        X400_ADDRESS => Ok(()),
        DIRECTORY_NAME => match explicit_one(input, element, depth) {
            Some(name) if name_element_decodes(input, &name, depth + 1) => Ok(()),
            _ => Err("a directoryName that is not one Name that decodes"),
        },
        EDI_PARTY_NAME => {
            const BAD: &str = "an ediPartyName that is not an optional [0] and a [1] \
                               DirectoryString";
            let parts = tlv::children_vec(input, element, depth, MAX_DEPTH, 2).map_err(|_| BAD)?;
            let (assigner, party) = match parts.as_slice() {
                [party] => (None, party),
                [assigner, party] => (Some(assigner), party),
                _ => return Err(BAD),
            };
            let holds_string = |tag: u8, part: &Element| {
                part.tag == tag
                    && explicit_one(input, part, depth + 1)
                        .is_some_and(|string| directory_string(&string))
            };
            let assigner_ok = assigner.is_none_or(|a| holds_string(tlv::TAG_CONTEXT_0, a));
            if !assigner_ok || !holds_string(tlv::TAG_CONTEXT_1, party) {
                return Err(BAD);
            }
            Ok(())
        }
        _ => Err(NOT_A_CHOICE),
    }
}

/// The entries of the DER `GeneralNames` `der` (`SEQUENCE OF GeneralName`, RFC 5280
/// §4.2.1.6, as OpenSSL's `GENERAL_NAMES` decodes it: an empty list decodes), each checked with
/// [`general_name`]; `None` when `der` is not exactly that, or holds more than
/// [`MAX_GENERAL_NAMES`] entries.
pub(crate) fn general_names(der: &[u8]) -> Option<Vec<Element>> {
    let sequence = tlv::read_exact(der, MAX_DEPTH).ok()?;
    if sequence.tag != tlv::TAG_SEQUENCE {
        return None;
    }
    general_names_in(der, &sequence, 0)
}

/// [`general_names`] for the element `sequence` of `input` (read at `depth`), whose tag the
/// caller chose (`SEQUENCE`, or an implicit context tag).
pub(crate) fn general_names_in(
    input: &[u8],
    sequence: &Element,
    depth: usize,
) -> Option<Vec<Element>> {
    if !sequence.is_constructed() {
        return None;
    }
    let entries = tlv::children_vec(input, sequence, depth, MAX_DEPTH, MAX_GENERAL_NAMES).ok()?;
    entries
        .iter()
        .all(|entry| general_name(input, entry, depth + 1).is_ok())
        .then_some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Name { RDN { CN = value } }` with the whole value TLV `value`.
    fn name(value: &[u8]) -> Vec<u8> {
        let atv = tlv::tlv_parts(
            tlv::TAG_SEQUENCE,
            &[&tlv::tlv(tlv::TAG_OID, &[0x55, 0x04, 0x03]), value],
        );
        tlv::tlv(tlv::TAG_SEQUENCE, &tlv::tlv(tlv::TAG_SET, &atv))
    }

    #[test]
    fn name_values_are_strings_openssl_converts() {
        assert!(name_decodes(&name(&[0x0C, 0x01, b'a'])));
        assert!(name_decodes(&name(&[0x13, 0x01, b'a'])));
        assert!(name_decodes(&name(&[0x1E, 0x02, 0, b'a'])));
        assert!(name_decodes(&name(&[0x1E, 0x02, 0xFF, 0xFE])));
        assert!(name_decodes(&name(&[0x1C, 0x04, 0, 0x01, 0xF6, 0x00])));
        assert!(name_decodes(&tlv::tlv(tlv::TAG_SEQUENCE, &[])));
        for bad in [
            &[0x02, 0x01, 0x01][..],
            &[0x04, 0x01, b'a'],
            &[
                0x17, 0x0D, b'2', b'6', b'1', b'0', b'1', b'0', b'1', b'2', b'0', b'0', b'0', b'0',
                b'Z',
            ],
            &[0x80, 0x01, b'a'],
            &[0x1A, 0x01, b'a'],
            // QA round 4 finding 1: what ASN1_STRING_to_UTF8 cannot convert.
            &[0x1E, 0x02, 0xD8, 0x00],
            &[0x1E, 0x04, 0xD8, 0x3D, 0xDE, 0x00],
            &[0x1E, 0x04, 0xDC, 0x00, 0xD8, 0x00],
            &[0x1E, 0x01, 0x41],
            &[0x1C, 0x04, 0, 0, 0xDF, 0xFF],
            &[0x1C, 0x04, 0, 0x11, 0, 0],
            &[0x0C, 0x03, 0xED, 0xA0, 0x80],
        ] {
            assert!(!name_decodes(&name(bad)), "{bad:02x?}");
        }
        assert!(!name_decodes(b"\x30\x03\x02\x01\x01"));
        // The structure too: Name SEQUENCE, RDN SET, AttributeTypeAndValue SEQUENCE.
        let atv = tlv::tlv_parts(
            tlv::TAG_SEQUENCE,
            &[
                &tlv::tlv(tlv::TAG_OID, &[0x55, 0x04, 0x03]),
                &[0x0C, 0x01, b'a'],
            ],
        );
        let rdn = tlv::tlv(tlv::TAG_SET, &atv);
        assert!(name_decodes(&tlv::tlv(tlv::TAG_SEQUENCE, &rdn)));
        assert!(!name_decodes(&tlv::tlv(tlv::TAG_SET, &rdn)));
        assert!(!name_decodes(&tlv::tlv(
            tlv::TAG_SEQUENCE,
            &tlv::tlv(tlv::TAG_SEQUENCE, &atv)
        )));
        let mut atv_as_set = atv;
        atv_as_set[0] = tlv::TAG_SET;
        assert!(!name_decodes(&tlv::tlv(
            tlv::TAG_SEQUENCE,
            &tlv::tlv(tlv::TAG_SET, &atv_as_set)
        )));
    }

    fn decodes(gn: &[u8]) -> Result<(), &'static str> {
        let element = tlv::read_exact(gn, MAX_DEPTH).map_err(|_| "tlv")?;
        general_name(gn, &element, 0)
    }

    #[test]
    fn general_names_decode_as_openssl_reads_them() {
        let oid = tlv::tlv(tlv::TAG_OID, &[0x2A, 0x03, 0x04]);
        let cn = name(&[0x0C, 0x03, b'T', b'S', b'A']);
        let utf8 = tlv::tlv(0x0C, b"party");
        let accepted: Vec<Vec<u8>> = vec![
            // otherName with a value of any type, even a context-tagged one.
            tlv::tlv(OTHER_NAME, &[oid.clone(), tlv::tlv(0xA0, &utf8)].concat()),
            tlv::tlv(
                OTHER_NAME,
                &[oid.clone(), tlv::tlv(0xA0, &[0x81, 0x00])].concat(),
            ),
            tlv::tlv(0x81, b"tsa@example.org"),
            tlv::tlv(0x82, b"tsa.example.org"),
            tlv::tlv(0x86, b"https://tsa.example.org/"),
            tlv::tlv(0x87, &[127, 0, 0, 1]),
            tlv::tlv(0x88, &[0x2A, 0x03, 0x04]),
            tlv::tlv(X400_ADDRESS, &tlv::tlv(tlv::TAG_SEQUENCE, &[])),
            tlv::tlv(DIRECTORY_NAME, &cn),
            tlv::tlv(EDI_PARTY_NAME, &tlv::tlv(0xA1, &utf8)),
            tlv::tlv(
                EDI_PARTY_NAME,
                &[tlv::tlv(0xA0, &tlv::tlv(0x13, b"a")), tlv::tlv(0xA1, &utf8)].concat(),
            ),
        ];
        for gn in &accepted {
            assert_eq!(decodes(gn), Ok(()), "{gn:02x?}");
        }
        let refused: Vec<(&str, Vec<u8>)> = vec![
            ("universal null", vec![0x05, 0x00]),
            ("universal integer", vec![0x02, 0x01, 0x01]),
            ("universal utf8", tlv::tlv(0x0C, b"tsa")),
            ("context [9]", tlv::tlv(0x89, b"x")),
            ("context [10] constructed", tlv::tlv(0xAA, &utf8)),
            ("application", tlv::tlv(0x41, b"x")),
            ("high tag", vec![0x9F, 0x20, 0x00]),
            (
                "otherName junk type",
                tlv::tlv(
                    OTHER_NAME,
                    &[tlv::tlv(0x02, &[1]), tlv::tlv(0xA0, &utf8)].concat(),
                ),
            ),
            ("otherName without value", tlv::tlv(OTHER_NAME, &oid)),
            (
                "otherName value not explicit",
                tlv::tlv(OTHER_NAME, &[oid.clone(), utf8.clone()].concat()),
            ),
            (
                "otherName value primitive [0]",
                tlv::tlv(OTHER_NAME, &[oid.clone(), tlv::tlv(0x80, b"x")].concat()),
            ),
            (
                "otherName two values",
                tlv::tlv(
                    OTHER_NAME,
                    &[
                        oid.clone(),
                        tlv::tlv(0xA0, &[utf8.clone(), utf8.clone()].concat()),
                    ]
                    .concat(),
                ),
            ),
            ("otherName primitive", tlv::tlv(0x80, &oid)),
            (
                "rfc822Name constructed",
                tlv::tlv(0xA1, &tlv::tlv(0x16, b"x")),
            ),
            ("x400Address primitive", tlv::tlv(0x83, b"x")),
            ("directoryName primitive", tlv::tlv(0x84, &cn)),
            (
                "directoryName two names",
                tlv::tlv(DIRECTORY_NAME, &[cn.clone(), cn.clone()].concat()),
            ),
            (
                "directoryName surrogate",
                tlv::tlv(DIRECTORY_NAME, &name(&[0x1E, 0x02, 0xD8, 0x00])),
            ),
            (
                "directoryName not a name",
                tlv::tlv(DIRECTORY_NAME, &tlv::tlv(tlv::TAG_SET, &[])),
            ),
            (
                "ediPartyName junk",
                tlv::tlv(EDI_PARTY_NAME, &tlv::tlv(0x02, &[1])),
            ),
            (
                "ediPartyName without partyName",
                tlv::tlv(EDI_PARTY_NAME, &tlv::tlv(0xA0, &utf8)),
            ),
            (
                "ediPartyName integer party",
                tlv::tlv(EDI_PARTY_NAME, &tlv::tlv(0xA1, &[0x02, 0x01, 0x01])),
            ),
            (
                "ediPartyName ia5 party",
                tlv::tlv(EDI_PARTY_NAME, &tlv::tlv(0xA1, &tlv::tlv(0x16, b"x"))),
            ),
            ("ediPartyName primitive", tlv::tlv(0x85, b"x")),
            (
                "ediPartyName three",
                tlv::tlv(
                    EDI_PARTY_NAME,
                    &[
                        tlv::tlv(0xA0, &utf8),
                        tlv::tlv(0xA1, &utf8),
                        tlv::tlv(0xA1, &utf8),
                    ]
                    .concat(),
                ),
            ),
            (
                "ediPartyName swapped",
                tlv::tlv(
                    EDI_PARTY_NAME,
                    &[tlv::tlv(0xA1, &utf8), tlv::tlv(0xA0, &utf8)].concat(),
                ),
            ),
            ("registeredID constructed", tlv::tlv(0xA8, &oid)),
            ("registeredID invalid", tlv::tlv(0x88, &[0x80, 0x01])),
            (
                "iPAddress constructed",
                tlv::tlv(0xA7, &tlv::tlv(0x04, &[1])),
            ),
            (
                "invalid primitive inside",
                tlv::tlv(
                    OTHER_NAME,
                    &[oid.clone(), tlv::tlv(0xA0, &[0x02, 0x02, 0x00, 0x01])].concat(),
                ),
            ),
        ];
        for (why, gn) in &refused {
            assert!(decodes(gn).is_err(), "{why}: {gn:02x?}");
        }

        // GeneralNames: a SEQUENCE of them, each decoding; empty decodes, the limit holds.
        let list = |entries: &[Vec<u8>]| tlv::tlv(tlv::TAG_SEQUENCE, &entries.concat());
        assert_eq!(
            general_names(&list(&accepted)).map(|e| e.len()),
            Some(accepted.len())
        );
        assert_eq!(general_names(&list(&[])).map(|e| e.len()), Some(0));
        assert!(general_names(&list(&[accepted[0].clone(), vec![0x05, 0x00]])).is_none());
        assert!(general_names(&tlv::tlv(tlv::TAG_SET, &accepted[2])).is_none());
        assert!(general_names(b"\x30\x05\x82").is_none());
        let many = vec![tlv::tlv(0x82, b"x"); MAX_GENERAL_NAMES + 1];
        assert!(general_names(&list(&many)).is_none());
        assert!(general_names(&list(&many[1..])).is_some());
    }
}
