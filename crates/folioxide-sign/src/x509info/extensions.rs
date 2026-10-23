//! The certificate extensions path validation decodes (M4 QA round 4 finding 5; RFC 5280 §4.2):
//! every extension a certificate of the path carries whose type Folioxide, pyHanko or OpenSSL
//! knows must decode as RFC 5280 defines it, critical or not, and the constraints Folioxide does
//! not process make the path untrusted whether they are critical or not.
//!
//! pyhanko-certvalidator parses the extensions of every certificate it validates (an
//! undecodable one fails the path: asn1crypto's `Certificate` parses every extension it has an
//! attribute for, among them `subjectDirectoryAttributes`, `privateKeyUsagePeriod` and the TLS
//! feature), and OpenSSL's `ossl_x509v3_cache_extensions` decodes the basic constraints, proxy
//! certificate information, key usages, the Netscape certificate type, key identifiers,
//! alternative names, name constraints, CRL distribution points and the RFC 3779 IP address and
//! AS identifier blocks of every certificate of the chain and marks it invalid when one does not
//! decode (`EXFLAG_INVALID`). Folioxide reads the union of both sets ([`DECODED`]; M4 final fix
//! round 2, finding 1, which found the last seven missing) as a whitelist of shapes with its
//! bounded TLV reader (BER accepted, as both do), the general names with
//! [`names::general_name`](super::names::general_name), every primitive with
//! [`tlv::check_primitives`]. An extension type outside the table is not decoded (a critical
//! one is refused by [`KNOWN_CRITICAL_EXTENSIONS`](super::KNOWN_CRITICAL_EXTENSIONS)); neither
//! reference decodes one either, so nothing is accepted that either refuses for its value.
//!
//! A critical extension OpenSSL does not handle ([`unhandled_critical`]) is a defect of the same
//! weight: OpenSSL refuses every chain with it, so it makes a TSA certificate unsuitable and a
//! path untrusted (M4 closing round, findings 8 and 11).

use der::oid::ObjectIdentifier;
use x509_cert::ext::Extension;

use super::cert::{self, CertParts, RawProfileCertificate};
use super::names::{general_name, general_names_in};
use crate::cms::MAX_DEPTH;
use crate::cms::tlv::{self, Element};

/// The constraints Folioxide does not process (RFC 5280 §6.1.4 (a), (g)–(i), §6.1.5 (b)): a
/// certificate authority of the path that carries one is never trusted, whether the extension
/// is critical or not, and neither is a signer with `policyConstraints` (its
/// `requireExplicitPolicy` takes effect at the end of the path). pyhanko-certvalidator and
/// OpenSSL apply them (a non-critical `nameConstraints` excluding the signer's name makes the
/// path invalid there; M4 QA round 4 finding 5), so ignoring one would be more lenient than
/// both; refusing a path that satisfies one is stricter, deliberately.
///
/// `inhibitAnyPolicy` is not among them: without `policyConstraints` on the path and without an
/// initial explicit policy (Folioxide and pyHanko require none) the explicit-policy counter
/// never reaches 0, so it cannot make a path invalid (§6.1.5 (g)); it must still decode.
/// `policyMappings` is, as §6.1.4 (a) refuses one that maps `anyPolicy` whatever else holds.
pub(crate) const UNPROCESSED_CONSTRAINTS: [(&str, &str); 3] = [
    ("2.5.29.30", "nameConstraints"),
    ("2.5.29.33", "policyMappings"),
    ("2.5.29.36", "policyConstraints"),
];

/// `policyConstraints`, which also constrains the end of the path (RFC 5280 §6.1.5 (b)).
pub(crate) const POLICY_CONSTRAINTS: &str = "2.5.29.36";

/// The extensions whose path processing Folioxide does not implement and that make OpenSSL
/// refuse a chain on their own, on ANY certificate of the path, the signer and the TSA
/// included (M4 final fix round 2, finding 1): a path with one is never trusted, critical or
/// not.
///
/// - The RFC 3779 IP address and AS identifier blocks: OpenSSL (`X509v3_addr_validate_path`,
///   `X509v3_asid_validate_path`, run whenever the end certificate carries one) refuses a chain
///   whose resources are not canonical or not nested in every issuer's (`X509_V_ERR_INVALID_
///   EXTENSION`, `X509_V_ERR_UNNESTED_RESOURCE`).
/// - `proxyCertInfo` (RFC 3820): OpenSSL refuses a chain with a proxy certificate unless the
///   caller allows them (`X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED`; `openssl ts -verify`
///   does not), and RFC 3820 §4 path validation is another algorithm.
///
/// pyhanko-certvalidator knows none of them, so a path that carries one is trusted there:
/// refusing it is stricter than pyHanko, deliberately (no document signer or TSA certificate
/// is a proxy certificate or names Internet number resources).
pub(crate) const UNPROCESSED_ON_ANY_CERTIFICATE: [(&str, &str); 3] = [
    ("1.3.6.1.5.5.7.1.7", "ipAddrBlocks (RFC 3779)"),
    ("1.3.6.1.5.5.7.1.8", "autonomousSysIds (RFC 3779)"),
    ("1.3.6.1.5.5.7.1.14", "proxyCertInfo (RFC 3820)"),
];

/// `proxyCertInfo` (RFC 3820 §3.8).
const PROXY_CERT_INFO: &str = "1.3.6.1.5.5.7.1.14";
/// `basicConstraints` (RFC 5280 §4.2.1.9).
const BASIC_CONSTRAINTS: &str = "2.5.29.19";
/// `subjectAltName` and `issuerAltName` (RFC 5280 §4.2.1.6, §4.2.1.7).
const ALTERNATIVE_NAMES: [&str; 2] = ["2.5.29.17", "2.5.29.18"];

/// The extension types whose values are decoded, with their names (RFC 5280 §4.2.1 and
/// §4.2.2, RFC 3739 §3.2.6, RFC 6960 §4.2.2.2.1; and since M4 final fix round 2, finding 1,
/// the ones asn1crypto or OpenSSL decode beyond RFC 5280: RFC 3280 §4.2.1.4, RFC 7633 §6,
/// RFC 3779 §2.2.3 and §3.2.3, RFC 3820 §3.8, the Netscape certificate type).
const DECODED: [(&str, &str); 25] = [
    ("2.5.29.9", "subjectDirectoryAttributes"),
    ("2.5.29.14", "subjectKeyIdentifier"),
    ("2.5.29.15", "keyUsage"),
    ("2.5.29.16", "privateKeyUsagePeriod"),
    ("2.5.29.17", "subjectAltName"),
    ("2.5.29.18", "issuerAltName"),
    ("2.5.29.19", "basicConstraints"),
    ("2.5.29.30", "nameConstraints"),
    ("2.5.29.31", "cRLDistributionPoints"),
    ("2.5.29.32", "certificatePolicies"),
    ("2.5.29.33", "policyMappings"),
    ("2.5.29.35", "authorityKeyIdentifier"),
    ("2.5.29.36", "policyConstraints"),
    ("2.5.29.37", "extKeyUsage"),
    ("2.5.29.46", "freshestCRL"),
    ("2.5.29.54", "inhibitAnyPolicy"),
    ("1.3.6.1.5.5.7.1.1", "authorityInfoAccess"),
    ("1.3.6.1.5.5.7.1.3", "qcStatements"),
    ("1.3.6.1.5.5.7.1.7", "ipAddrBlocks"),
    ("1.3.6.1.5.5.7.1.8", "autonomousSysIds"),
    ("1.3.6.1.5.5.7.1.11", "subjectInfoAccess"),
    ("1.3.6.1.5.5.7.1.14", "proxyCertInfo"),
    ("1.3.6.1.5.5.7.1.24", "tlsFeature"),
    ("1.3.6.1.5.5.7.48.1.5", "ocspNoCheck"),
    ("2.16.840.1.113730.1.1", "nsCertType"),
];

/// The name of a decoded extension type (dotted OID), if it is one.
pub(crate) fn decoded_name(dotted: &str) -> Option<&'static str> {
    DECODED
        .iter()
        .find(|(oid, _)| *oid == dotted)
        .map(|(_, name)| *name)
}

/// Why an extension value does not decode.
type Shape = Result<(), &'static str>;

/// The children of `element`, at most `max`, or `what`.
fn fields(
    input: &[u8],
    element: &Element,
    depth: usize,
    max: usize,
    what: &'static str,
) -> Result<Vec<Element>, &'static str> {
    if !element.is_constructed() {
        return Err(what);
    }
    tlv::children_vec(input, element, depth, MAX_DEPTH, max).map_err(|_| what)
}

/// Whether `content` is a valid INTEGER content (X.690 §8.3.2: not empty, minimal), for an
/// implicitly tagged INTEGER that [`tlv::check_primitives`] cannot see.
fn integer(content: &[u8]) -> bool {
    !content.is_empty() && tlv::integer_canonical(content).len() == content.len()
}

/// Whether the INTEGER content `content` is non-negative.
fn non_negative(content: &[u8]) -> bool {
    content.first().is_some_and(|&b| b & 0x80 == 0)
}

/// `SEQUENCE OF` elements that each pass `item` (at most `MAX_ITEMS`).
fn sequence_of(
    input: &[u8],
    element: &Element,
    depth: usize,
    what: &'static str,
    item: impl Fn(&Element) -> Shape,
) -> Shape {
    const MAX_ITEMS: usize = 1024;
    if element.tag != tlv::TAG_SEQUENCE {
        return Err(what);
    }
    for child in fields(input, element, depth, MAX_ITEMS, what)? {
        item(&child)?;
    }
    Ok(())
}

/// `GeneralNames` under the identifier octet `tag` (a `SEQUENCE`, or an implicit context tag).
fn general_names_tagged(input: &[u8], element: &Element, depth: usize, tag: u8) -> Shape {
    if element.tag != tag {
        return Err("a GeneralNames with the wrong tag");
    }
    general_names_in(input, element, depth)
        .map(|_| ())
        .ok_or("a GeneralNames whose entries do not decode")
}

/// `KeyIdentifier ::= OCTET STRING`, primitive or constructed.
fn octet_string(input: &[u8], element: &Element, depth: usize) -> Shape {
    tlv::octet_string_value(input, element, depth, MAX_DEPTH)
        .map(|_| ())
        .map_err(|_| "not an OCTET STRING")
}

/// `AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] KeyIdentifier OPTIONAL,
/// authorityCertIssuer [1] GeneralNames OPTIONAL, authorityCertSerialNumber [2]
/// CertificateSerialNumber OPTIONAL }`, implicit tags, in order (OpenSSL `AUTHORITY_KEYID`).
fn authority_key_identifier(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not a keyIdentifier, authorityCertIssuer and serial number";
    if element.tag != tlv::TAG_SEQUENCE {
        return Err(BAD);
    }
    let parts = fields(input, element, 0, 3, BAD)?;
    let mut parts = parts.iter().peekable();
    // keyIdentifier [0] IMPLICIT OCTET STRING: primitive only (a constructed one is BER that
    // OpenSSL reads from context segments; stricter).
    parts.next_if(|p| p.tag == tlv::TAG_CONTEXT_0_PRIMITIVE);
    if let Some(issuer) = parts.next_if(|p| p.tag == tlv::TAG_CONTEXT_1) {
        general_names_tagged(input, issuer, 1, tlv::TAG_CONTEXT_1)?;
    }
    if let Some(serial) = parts.next_if(|p| p.tag == 0x82)
        && !integer(serial.content(input))
    {
        return Err("an authorityCertSerialNumber that is not a valid INTEGER");
    }
    match parts.next() {
        None => Ok(()),
        Some(_) => Err(BAD),
    }
}

/// `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX)
/// OPTIONAL }`; a negative `pathLenConstraint` is invalid (OpenSSL `EXFLAG_INVALID`).
fn basic_constraints(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not an optional cA BOOLEAN and pathLenConstraint INTEGER";
    if element.tag != tlv::TAG_SEQUENCE {
        return Err(BAD);
    }
    let parts = fields(input, element, 0, 2, BAD)?;
    let mut parts = parts.iter().peekable();
    parts.next_if(|p| p.tag == 0x01);
    if let Some(path_len) = parts.next_if(|p| p.tag == tlv::TAG_INTEGER)
        && !non_negative(path_len.content(input))
    {
        return Err("a negative pathLenConstraint");
    }
    match parts.next() {
        None => Ok(()),
        Some(_) => Err(BAD),
    }
}

/// `NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees OPTIONAL,
/// excludedSubtrees [1] GeneralSubtrees OPTIONAL }` with `GeneralSubtree ::= SEQUENCE { base
/// GeneralName, minimum [0] BaseDistance DEFAULT 0, maximum [1] BaseDistance OPTIONAL }`.
fn name_constraints(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not permitted and excluded subtrees";
    if element.tag != tlv::TAG_SEQUENCE {
        return Err(BAD);
    }
    let parts = fields(input, element, 0, 2, BAD)?;
    let mut parts = parts.iter().peekable();
    for tag in [tlv::TAG_CONTEXT_0, tlv::TAG_CONTEXT_1] {
        let Some(subtrees) = parts.next_if(|p| p.tag == tag) else {
            continue;
        };
        for subtree in fields(input, subtrees, 1, 1024, BAD)? {
            if subtree.tag != tlv::TAG_SEQUENCE {
                return Err(BAD);
            }
            let inner = fields(input, &subtree, 2, 3, BAD)?;
            let mut inner = inner.iter();
            let base = inner.next().ok_or(BAD)?;
            general_name(input, base, 3)?;
            let mut last = 0x7F_u8;
            for distance in inner {
                let order = match distance.tag {
                    0x80 => 0,
                    0x81 => 1,
                    _ => return Err(BAD),
                };
                if (last != 0x7F && order <= last) || !integer(distance.content(input)) {
                    return Err(BAD);
                }
                last = order;
            }
        }
    }
    match parts.next() {
        None => Ok(()),
        Some(_) => Err(BAD),
    }
}

/// `CRLDistributionPoints ::= SEQUENCE OF DistributionPoint` (also `FreshestCRL`), with
/// `DistributionPoint ::= SEQUENCE { distributionPoint [0] DistributionPointName OPTIONAL,
/// reasons [1] ReasonFlags OPTIONAL, cRLIssuer [2] GeneralNames OPTIONAL }` and
/// `DistributionPointName ::= CHOICE { fullName [0] GeneralNames, nameRelativeToCRLIssuer [1]
/// RelativeDistinguishedName }` (OpenSSL `DIST_POINT`, `DIST_POINT_NAME`).
fn distribution_points(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not a list of DistributionPoints";
    sequence_of(input, element, 0, BAD, |point| {
        if point.tag != tlv::TAG_SEQUENCE {
            return Err(BAD);
        }
        let parts = fields(input, point, 1, 3, BAD)?;
        let mut parts = parts.iter().peekable();
        if let Some(name) = parts.next_if(|p| p.tag == tlv::TAG_CONTEXT_0) {
            let inner = fields(input, name, 2, 1, BAD)?;
            let [choice] = inner.as_slice() else {
                return Err(BAD);
            };
            match choice.tag {
                tlv::TAG_CONTEXT_0 => general_names_tagged(input, choice, 3, tlv::TAG_CONTEXT_0)?,
                tlv::TAG_CONTEXT_1 => {
                    // A SET OF AttributeTypeAndValue: each an OID and one value.
                    for atv in fields(input, choice, 3, 256, BAD)? {
                        let pair = fields(input, &atv, 4, 2, BAD)?;
                        if atv.tag != tlv::TAG_SEQUENCE
                            || !matches!(pair.as_slice(), [oid, _] if oid.tag == tlv::TAG_OID)
                        {
                            return Err(BAD);
                        }
                    }
                }
                _ => return Err(BAD),
            }
        }
        if let Some(reasons) = parts.next_if(|p| p.tag == 0x81)
            && !reasons
                .content(input)
                .first()
                .is_some_and(|&unused| unused <= 7)
        {
            return Err("reasons that are not a valid BIT STRING");
        }
        if let Some(issuer) = parts.next_if(|p| p.tag == tlv::TAG_CONTEXT_2) {
            general_names_tagged(input, issuer, 2, tlv::TAG_CONTEXT_2)?;
        }
        match parts.next() {
            None => Ok(()),
            Some(_) => Err(BAD),
        }
    })
}

/// `CertificatePolicies ::= SEQUENCE OF PolicyInformation` (RFC 5280 §4.2.1.4), read as the ESS
/// `policies` are ([`crate::tsp::shape::policies`]).
fn certificate_policies(input: &[u8], element: &Element) -> Shape {
    crate::tsp::shape::policies(input, element, 0)
}

/// `PolicyMappings ::= SEQUENCE OF SEQUENCE { issuerDomainPolicy OID, subjectDomainPolicy OID }`.
fn policy_mappings(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not a list of policy OID pairs";
    sequence_of(input, element, 0, BAD, |mapping| {
        let pair = fields(input, mapping, 1, 2, BAD)?;
        match pair.as_slice() {
            [a, b]
                if mapping.tag == tlv::TAG_SEQUENCE
                    && a.tag == tlv::TAG_OID
                    && b.tag == tlv::TAG_OID =>
            {
                Ok(())
            }
            _ => Err(BAD),
        }
    })
}

/// `PolicyConstraints ::= SEQUENCE { requireExplicitPolicy [0] SkipCerts OPTIONAL,
/// inhibitPolicyMapping [1] SkipCerts OPTIONAL }`, `SkipCerts ::= INTEGER (0..MAX)`.
fn policy_constraints(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not optional requireExplicitPolicy and inhibitPolicyMapping counts";
    if element.tag != tlv::TAG_SEQUENCE {
        return Err(BAD);
    }
    let parts = fields(input, element, 0, 2, BAD)?;
    let mut parts = parts.iter().peekable();
    for tag in [0x80, 0x81] {
        if let Some(count) = parts.next_if(|p| p.tag == tag)
            && !(integer(count.content(input)) && non_negative(count.content(input)))
        {
            return Err(BAD);
        }
    }
    match parts.next() {
        None => Ok(()),
        Some(_) => Err(BAD),
    }
}

/// `SEQUENCE OF SEQUENCE { OID, GeneralName }`: `AuthorityInfoAccessSyntax` and
/// `SubjectInfoAccessSyntax` (RFC 5280 §4.2.2.1, §4.2.2.2).
fn access_descriptions(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not a list of AccessDescriptions";
    sequence_of(input, element, 0, BAD, |description| {
        let pair = fields(input, description, 1, 2, BAD)?;
        match pair.as_slice() {
            [method, location]
                if description.tag == tlv::TAG_SEQUENCE && method.tag == tlv::TAG_OID =>
            {
                general_name(input, location, 2)
            }
            _ => Err(BAD),
        }
    })
}

/// `QCStatements ::= SEQUENCE OF SEQUENCE { statementId OID, statementInfo ANY OPTIONAL }`
/// (RFC 3739 §3.2.6).
fn qc_statements(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not a list of QCStatements";
    sequence_of(input, element, 0, BAD, |statement| {
        let parts = fields(input, statement, 1, 2, BAD)?;
        match parts.first() {
            Some(id) if statement.tag == tlv::TAG_SEQUENCE && id.tag == tlv::TAG_OID => Ok(()),
            _ => Err(BAD),
        }
    })
}

/// `SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute` with `Attribute ::=
/// SEQUENCE { type AttributeType, values SET OF AttributeValue }` (RFC 5280 §4.2.1.8; asn1crypto
/// `SubjectDirectoryAttributes`). An empty list is accepted, as asn1crypto accepts it; the
/// values are not looked into beyond their primitives.
fn subject_directory_attributes(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not a list of Attributes";
    sequence_of(input, element, 0, BAD, |attribute| {
        let pair = fields(input, attribute, 1, 2, BAD)?;
        match pair.as_slice() {
            [kind, values]
                if attribute.tag == tlv::TAG_SEQUENCE
                    && kind.tag == tlv::TAG_OID
                    && values.tag == tlv::TAG_SET =>
            {
                Ok(())
            }
            _ => Err(BAD),
        }
    })
}

/// `PrivateKeyUsagePeriod ::= SEQUENCE { notBefore [0] GeneralizedTime OPTIONAL, notAfter [1]
/// GeneralizedTime OPTIONAL }` (RFC 3280 §4.2.1.4, X.509 §9.2.2.5; implicit tags, in order;
/// asn1crypto `PrivateKeyUsagePeriod`). A time is primitive and at least `YYYYMMDDHHMMSSZ`
/// long, as a universal GeneralizedTime must be ([`tlv::check_primitives`]).
fn private_key_usage_period(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not optional notBefore and notAfter GeneralizedTimes";
    if element.tag != tlv::TAG_SEQUENCE {
        return Err(BAD);
    }
    let parts = fields(input, element, 0, 2, BAD)?;
    let mut parts = parts.iter().peekable();
    for tag in [0x80, 0x81] {
        if let Some(time) = parts.next_if(|p| p.tag == tag)
            && time.content(input).len() < 15
        {
            return Err("a private key usage time that is too short");
        }
    }
    match parts.next() {
        None => Ok(()),
        Some(_) => Err(BAD),
    }
}

/// `Features ::= SEQUENCE OF INTEGER` (RFC 7633 §6, the TLS feature extension; asn1crypto
/// `Features`).
fn tls_features(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not a list of INTEGERs";
    sequence_of(input, element, 0, BAD, |feature| {
        (feature.tag == tlv::TAG_INTEGER).then_some(()).ok_or(BAD)
    })
}

/// `IPAddrBlocks ::= SEQUENCE OF IPAddressFamily` (RFC 3779 §2.2.3), as OpenSSL's template
/// reads it: `IPAddressFamily ::= SEQUENCE { addressFamily OCTET STRING, ipAddressChoice
/// IPAddressChoice }`, `IPAddressChoice ::= CHOICE { inherit NULL, addressesOrRanges SEQUENCE
/// OF IPAddressOrRange }`, `IPAddressOrRange ::= CHOICE { addressPrefix BIT STRING,
/// addressRange SEQUENCE { min BIT STRING, max BIT STRING } }`. Whether the blocks are
/// canonical and nested in the issuers' is path processing, which Folioxide does not do
/// ([`UNPROCESSED_ON_ANY_CERTIFICATE`]).
fn ip_addr_blocks(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not a list of IPAddressFamily";
    const MAX_ITEMS: usize = 1024;
    sequence_of(input, element, 0, BAD, |family| {
        let parts = fields(input, family, 1, 2, BAD)?;
        let [address_family, choice] = parts.as_slice() else {
            return Err(BAD);
        };
        if family.tag != tlv::TAG_SEQUENCE {
            return Err(BAD);
        }
        octet_string(input, address_family, 2)?;
        match choice.tag {
            tlv::TAG_NULL => Ok(()),
            tlv::TAG_SEQUENCE => {
                for item in fields(input, choice, 2, MAX_ITEMS, BAD)? {
                    match item.tag {
                        tlv::TAG_BIT_STRING => {}
                        tlv::TAG_SEQUENCE => {
                            let bounds = fields(input, &item, 3, 2, BAD)?;
                            if !matches!(bounds.as_slice(), [min, max]
                                if min.tag == tlv::TAG_BIT_STRING && max.tag == tlv::TAG_BIT_STRING)
                            {
                                return Err(BAD);
                            }
                        }
                        _ => return Err(BAD),
                    }
                }
                Ok(())
            }
            _ => Err(BAD),
        }
    })
}

/// `ASIdentifiers ::= SEQUENCE { asnum [0] EXPLICIT ASIdentifierChoice OPTIONAL, rdi [1]
/// EXPLICIT ASIdentifierChoice OPTIONAL }` (RFC 3779 §3.2.3), as OpenSSL's template reads it:
/// `ASIdentifierChoice ::= CHOICE { inherit NULL, asIdsOrRanges SEQUENCE OF ASIdOrRange }`,
/// `ASIdOrRange ::= CHOICE { id INTEGER, range SEQUENCE { min INTEGER, max INTEGER } }`.
fn as_identifiers(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not optional asnum and rdi ASIdentifierChoices";
    const MAX_ITEMS: usize = 1024;
    if element.tag != tlv::TAG_SEQUENCE {
        return Err(BAD);
    }
    let parts = fields(input, element, 0, 2, BAD)?;
    let mut parts = parts.iter().peekable();
    for tag in [tlv::TAG_CONTEXT_0, tlv::TAG_CONTEXT_1] {
        let Some(explicit) = parts.next_if(|p| p.tag == tag) else {
            continue;
        };
        let inner = fields(input, explicit, 1, 1, BAD)?;
        let [choice] = inner.as_slice() else {
            return Err(BAD);
        };
        match choice.tag {
            tlv::TAG_NULL => {}
            tlv::TAG_SEQUENCE => {
                for id in fields(input, choice, 2, MAX_ITEMS, BAD)? {
                    match id.tag {
                        tlv::TAG_INTEGER => {}
                        tlv::TAG_SEQUENCE => {
                            let bounds = fields(input, &id, 3, 2, BAD)?;
                            if !matches!(bounds.as_slice(), [min, max]
                                if min.tag == tlv::TAG_INTEGER && max.tag == tlv::TAG_INTEGER)
                            {
                                return Err(BAD);
                            }
                        }
                        _ => return Err(BAD),
                    }
                }
            }
            _ => return Err(BAD),
        }
    }
    match parts.next() {
        None => Ok(()),
        Some(_) => Err(BAD),
    }
}

/// `ProxyCertInfoExtension ::= SEQUENCE { pCPathLenConstraint INTEGER (0..MAX) OPTIONAL,
/// proxyPolicy ProxyPolicy }` with `ProxyPolicy ::= SEQUENCE { policyLanguage OBJECT
/// IDENTIFIER, policy OCTET STRING OPTIONAL }` (RFC 3820 §3.8; OpenSSL
/// `PROXY_CERT_INFO_EXTENSION`, `PROXY_POLICY`).
fn proxy_cert_info(input: &[u8], element: &Element) -> Shape {
    const BAD: &str = "not an optional path length and a ProxyPolicy";
    if element.tag != tlv::TAG_SEQUENCE {
        return Err(BAD);
    }
    let parts = fields(input, element, 0, 2, BAD)?;
    let mut parts = parts.iter().peekable();
    parts.next_if(|p| p.tag == tlv::TAG_INTEGER);
    let policy = parts.next().ok_or(BAD)?;
    if policy.tag != tlv::TAG_SEQUENCE {
        return Err(BAD);
    }
    match fields(input, policy, 1, 2, BAD)?.as_slice() {
        [language] if language.tag == tlv::TAG_OID => {}
        [language, body] if language.tag == tlv::TAG_OID => octet_string(input, body, 2)?,
        _ => return Err(BAD),
    }
    match parts.next() {
        None => Ok(()),
        Some(_) => Err(BAD),
    }
}

/// Whether the `basicConstraints` value `value` decodes with `cA` TRUE (any non-zero BOOLEAN
/// octet, as BER reads it).
fn says_ca(value: &[u8]) -> bool {
    let Ok(element) = tlv::read_exact(value, MAX_DEPTH) else {
        return false;
    };
    let Ok(parts) = tlv::children_vec(value, &element, 0, MAX_DEPTH, 2) else {
        return false;
    };
    parts
        .first()
        .is_some_and(|ca| ca.tag == 0x01 && ca.content(value).iter().any(|&b| b != 0))
}

/// Checks the value (the `extnValue` octets) of an extension of type `dotted` against its
/// shape; an extension type Folioxide does not decode passes. The value must be exactly one
/// element whose primitives are valid encodings ([`tlv::check_primitives`]).
///
/// # Errors
/// What is wrong, as a short phrase.
pub(crate) fn value_decodes(dotted: &str, value: &[u8]) -> Shape {
    if decoded_name(dotted).is_none() {
        return Ok(());
    }
    let element = tlv::read_exact(value, MAX_DEPTH).map_err(|_| "not one ASN.1 element")?;
    tlv::check_primitives(value, &element, 0, MAX_DEPTH)?;
    match dotted {
        "2.5.29.9" => subject_directory_attributes(value, &element),
        "2.5.29.14" => octet_string(value, &element, 0),
        // keyUsage and nsCertType: a primitive BIT STRING (OpenSSL `ASN1_BIT_STRING`).
        "2.5.29.15" | "2.16.840.1.113730.1.1" if element.tag == tlv::TAG_BIT_STRING => Ok(()),
        "2.5.29.15" | "2.16.840.1.113730.1.1" => Err("not a BIT STRING"),
        "2.5.29.16" => private_key_usage_period(value, &element),
        "2.5.29.17" | "2.5.29.18" => general_names_tagged(value, &element, 0, tlv::TAG_SEQUENCE),
        "2.5.29.19" => basic_constraints(value, &element),
        "2.5.29.30" => name_constraints(value, &element),
        "2.5.29.31" | "2.5.29.46" => distribution_points(value, &element),
        "2.5.29.32" => certificate_policies(value, &element),
        "2.5.29.33" => policy_mappings(value, &element),
        "2.5.29.35" => authority_key_identifier(value, &element),
        "2.5.29.36" => policy_constraints(value, &element),
        "2.5.29.37" => sequence_of(value, &element, 0, "not a list of OIDs", |purpose| {
            (purpose.tag == tlv::TAG_OID)
                .then_some(())
                .ok_or("not a list of OIDs")
        }),
        "2.5.29.54" if element.tag == tlv::TAG_INTEGER && non_negative(element.content(value)) => {
            Ok(())
        }
        "2.5.29.54" => Err("not a non-negative INTEGER"),
        "1.3.6.1.5.5.7.1.1" | "1.3.6.1.5.5.7.1.11" => access_descriptions(value, &element),
        "1.3.6.1.5.5.7.1.3" => qc_statements(value, &element),
        "1.3.6.1.5.5.7.1.7" => ip_addr_blocks(value, &element),
        "1.3.6.1.5.5.7.1.8" => as_identifiers(value, &element),
        "1.3.6.1.5.5.7.1.14" => proxy_cert_info(value, &element),
        "1.3.6.1.5.5.7.1.24" => tls_features(value, &element),
        "1.3.6.1.5.5.7.48.1.5" if element.tag == tlv::TAG_NULL => Ok(()),
        "1.3.6.1.5.5.7.48.1.5" => Err("not a NULL"),
        _ => Ok(()),
    }
}

/// The defects of a certificate's extension list that make OpenSSL's
/// `ossl_x509v3_cache_extensions` mark the certificate invalid (`EXFLAG_INVALID`) or
/// pyhanko-certvalidator refuse it, one phrase each, for "… has `phrase`": an extension type
/// that occurs more than once (RFC 5280 §4.2: "A certificate MUST NOT include more than one
/// instance of a particular extension"), an extension of a type Folioxide decodes whose value
/// does not decode ([`value_decodes`]), and a `proxyCertInfo` in a certificate whose
/// `basicConstraints` says `cA` or that carries an alternative name (RFC 3820 §3.2, §3.5, §3.7: a
/// proxy certificate is neither; OpenSSL marks it invalid). Empty when there is none.
///
/// Path validation refuses such a certificate as untrusted; a TSA certificate with one makes its
/// token invalid ([`check_tsa_certificate`](super::check_tsa_certificate); manager ruling R-22
/// (c), M4 QA round 5 finding 37).
pub(crate) fn integrity_defects(extensions: &[Extension]) -> Vec<String> {
    let mut defects = Vec::new();
    let mut seen: Vec<&ObjectIdentifier> = Vec::new();
    let (mut proxy, mut ca, mut alternative_name) = (false, false, false);
    for extension in extensions {
        if seen.contains(&&extension.extn_id) {
            defects.push(format!(
                "the extension {} more than once",
                extension.extn_id
            ));
        }
        seen.push(&extension.extn_id);
        let dotted = extension.extn_id.to_string();
        let value = extension.extn_value.as_bytes();
        match value_decodes(&dotted, value) {
            Err(why) => {
                let name = decoded_name(&dotted).unwrap_or("an");
                defects.push(format!("a {name} extension that does not decode: {why}"));
            }
            Ok(()) if dotted == PROXY_CERT_INFO => proxy = true,
            Ok(()) if dotted == BASIC_CONSTRAINTS && says_ca(value) => ca = true,
            Ok(()) => {}
        }
        alternative_name |= ALTERNATIVE_NAMES.contains(&dotted.as_str());
    }
    // OpenSSL: a decodable proxyCertInfo with EXFLAG_CA or a subject or issuer alternative name
    // (present, whether it decodes or not) is EXFLAG_INVALID.
    if proxy && (ca || alternative_name) {
        defects.push(
            "a proxyCertInfo extension although it is a certificate authority or carries an \
             alternative name (RFC 3820 §3.2, §3.5, §3.7)"
                .to_owned(),
        );
    }
    defects
}

/// The extension types OpenSSL 3.0 handles when they are critical: the `supported_nids` of
/// `X509_supported_extension` (crypto/x509/v3_purp.c; confirmed with `openssl verify` of
/// OpenSSL 3.0.13 for every type Folioxide decodes). `ossl_x509v3_cache_extensions` sets
/// `EXFLAG_CRITICAL` on a certificate with any other critical extension, and OpenSSL then
/// refuses every chain that holds it ("unhandled critical extension",
/// `X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION`), `openssl ts -verify` included.
const OPENSSL_HANDLED_CRITICAL: [&str; 15] = [
    "2.16.840.1.113730.1.1", // nsCertType
    "2.5.29.15",             // keyUsage
    "2.5.29.17",             // subjectAltName
    "2.5.29.19",             // basicConstraints
    "2.5.29.32",             // certificatePolicies
    "2.5.29.31",             // cRLDistributionPoints
    "2.5.29.37",             // extKeyUsage
    "1.3.6.1.5.5.7.1.7",     // ipAddrBlocks (RFC 3779)
    "1.3.6.1.5.5.7.1.8",     // autonomousSysIds (RFC 3779)
    "1.3.6.1.5.5.7.48.1.5",  // ocspNoCheck
    "2.5.29.36",             // policyConstraints
    "1.3.6.1.5.5.7.1.14",    // proxyCertInfo
    "2.5.29.30",             // nameConstraints
    "2.5.29.33",             // policyMappings
    "2.5.29.54",             // inhibitAnyPolicy
];

/// The extension types RFC 5280 says conforming CAs MUST mark non-critical, with the section:
/// the key identifiers (§4.2.1.1, §4.2.1.2), the freshest CRL (§4.2.1.15) and the information
/// access extensions (§4.2.2.1, §4.2.2.2).
const NEVER_CRITICAL: [(&str, &str); 5] = [
    ("2.5.29.35", "§4.2.1.1"),
    ("2.5.29.14", "§4.2.1.2"),
    ("2.5.29.46", "§4.2.1.15"),
    ("1.3.6.1.5.5.7.1.1", "§4.2.2.1"),
    ("1.3.6.1.5.5.7.1.11", "§4.2.2.2"),
];

/// Whether OpenSSL handles the extension type `dotted` when it is critical
/// ([`OPENSSL_HANDLED_CRITICAL`]).
pub(crate) fn openssl_handles_critical(dotted: &str) -> bool {
    OPENSSL_HANDLED_CRITICAL.contains(&dotted)
}

/// The critical extensions of a certificate that OpenSSL does not handle
/// ([`OPENSSL_HANDLED_CRITICAL`]), one phrase each, for "… has `phrase`": an unknown or private
/// extension, and a known one OpenSSL does not process, such as a critical
/// `subjectKeyIdentifier`, `authorityKeyIdentifier`, `authorityInfoAccess`, `freshestCRL` or
/// `qcStatements`. Empty when there is none (M4 closing round, findings 8 and 11).
///
/// OpenSSL refuses every chain with such a certificate, whatever the trust anchors, so a TSA
/// certificate with one makes its token invalid
/// ([`check_tsa_certificate`](super::check_tsa_certificate), as for the defects of
/// [`integrity_defects`]: `openssl ts -verify` fails where Folioxide called the token valid
/// and trusted), and path validation refuses any certificate below the anchor with one, the
/// document signer's included. pyhanko-certvalidator processes some of them (it trusts a
/// critical key identifier or `authorityInfoAccess`), so this is stricter than pyHanko and
/// equal to OpenSSL; RFC 5280 says CAs MUST mark several of them non-critical
/// ([`NEVER_CRITICAL`]).
pub(crate) fn unhandled_critical(extensions: &[Extension]) -> Vec<String> {
    extensions
        .iter()
        .filter(|extension| extension.critical)
        .filter_map(|extension| {
            let dotted = extension.extn_id.to_string();
            if openssl_handles_critical(&dotted) {
                return None;
            }
            let Some(name) = decoded_name(&dotted) else {
                return Some(format!("an unknown critical extension {dotted}"));
            };
            let rfc = NEVER_CRITICAL
                .iter()
                .find(|(oid, _)| *oid == dotted)
                .map(|(_, section)| {
                    format!(", and RFC 5280 {section} says it MUST be non-critical")
                })
                .unwrap_or_default();
            Some(format!(
                "a critical {name} extension, which OpenSSL does not handle (unhandled critical \
                 extension){rfc}"
            ))
        })
        .collect()
}

/// `id-ce-subjectKeyIdentifier` (RFC 5280 §4.2.1.2).
const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
/// `id-ce-authorityKeyIdentifier` (RFC 5280 §4.2.1.1).
const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";

/// The first `GeneralName` of an `authorityCertIssuer` (RFC 5280 §4.2.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AuthorityIssuer {
    /// A `directoryName`: the whole `Name` TLV inside its explicit tag.
    Directory(Vec<u8>),
    /// Another choice, or an empty list: nothing an issuer's issuer name can equal.
    Other,
}

/// What one `AuthorityKeyIdentifier` extension says about the certificate's issuer (RFC 5280
/// §4.2.1.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AuthorityKeyId {
    /// `keyIdentifier [0]`: its octets.
    pub(crate) key_id: Option<Vec<u8>>,
    /// `authorityCertIssuer [1]`: its first entry.
    pub(crate) cert_issuer: Option<AuthorityIssuer>,
    /// `authorityCertSerialNumber [2]`: the INTEGER content octets.
    pub(crate) cert_serial: Option<Vec<u8>>,
}

/// The `AuthorityKeyIdentifier` of the extension value `value`, or `None` when it does not
/// decode ([`value_decodes`]).
fn authority_key_id(value: &[u8]) -> Option<AuthorityKeyId> {
    value_decodes(AUTHORITY_KEY_IDENTIFIER, value).ok()?;
    let element = tlv::read_exact(value, MAX_DEPTH).ok()?;
    let mut out = AuthorityKeyId::default();
    for part in tlv::children_vec(value, &element, 0, MAX_DEPTH, 3).ok()? {
        match part.tag {
            tlv::TAG_CONTEXT_0_PRIMITIVE => out.key_id = Some(part.content(value).to_vec()),
            tlv::TAG_CONTEXT_1 => {
                let names = general_names_in(value, &part, 1)?;
                out.cert_issuer = Some(match names.first() {
                    // directoryName [4] EXPLICIT Name.
                    Some(first) if first.tag == tlv::TAG_CONTEXT_4 => {
                        let inner = tlv::children_vec(value, first, 2, MAX_DEPTH, 1).ok()?;
                        match inner.as_slice() {
                            [name] => AuthorityIssuer::Directory(name.raw(value).to_vec()),
                            _ => return None,
                        }
                    }
                    _ => AuthorityIssuer::Other,
                });
            }
            0x82 => out.cert_serial = Some(part.content(value).to_vec()),
            _ => return None,
        }
    }
    Some(out)
}

/// The key identifiers of one certificate (RFC 5280 §4.2.1.1, §4.2.1.2), read for issuer
/// matching ([`KeyIds::mismatch`]).
#[derive(Clone, Debug, Default)]
pub(crate) struct KeyIds {
    /// Every `authorityKeyIdentifier` extension that decodes. One that does not decode, or a
    /// second one, already makes the certificate unusable on a path ([`integrity_defects`]),
    /// so it constrains no issuer here.
    authority: Vec<AuthorityKeyId>,
    /// Every `subjectKeyIdentifier` value; `None` for one that does not decode, which equals
    /// no key identifier.
    subject: Vec<Option<Vec<u8>>>,
}

impl KeyIds {
    /// The key identifiers of `certificate`.
    pub(crate) fn of(certificate: &RawProfileCertificate) -> KeyIds {
        let mut ids = KeyIds::default();
        let Some(extensions) = certificate.tbs_certificate().extensions() else {
            return ids;
        };
        for extension in extensions {
            let value = extension.extn_value.as_bytes();
            match extension.extn_id.to_string().as_str() {
                AUTHORITY_KEY_IDENTIFIER => ids.authority.extend(authority_key_id(value)),
                SUBJECT_KEY_IDENTIFIER => ids.subject.push(
                    tlv::read_exact(value, MAX_DEPTH)
                        .ok()
                        .and_then(|e| tlv::octet_string_value(value, &e, 0, MAX_DEPTH).ok()),
                ),
                _ => {}
            }
        }
        ids
    }

    /// The key identifiers of the DER certificate `der`; none when it does not decode.
    pub(crate) fn of_der(der: &[u8]) -> KeyIds {
        cert::decode(der).map_or_else(|_| KeyIds::default(), |c| KeyIds::of(&c))
    }

    /// Why the certificate whose identifiers are `issuer` (with the raw parts `issuer_parts`)
    /// is not the issuer that this certificate's `authorityKeyIdentifier` describes, or `None`
    /// when it may be (manager ruling R-22 (a), M4 QA round 5 finding 32). The rules are the
    /// union of OpenSSL's `X509_check_akid` and pyhanko-certvalidator's issuer filter
    /// (`find_potential_issuers`, `is_potential_issuer_of`), so the edge is never accepted
    /// where either refuses it:
    ///
    /// - a `keyIdentifier` must equal every `subjectKeyIdentifier` the issuer carries (both);
    /// - an `authorityCertSerialNumber` must equal the issuer's serial number (OpenSSL);
    /// - an `authorityCertIssuer` needs an `authorityCertSerialNumber` (pyHanko compares the
    ///   pair; X.509 requires both or neither), and its first entry must be a `directoryName`
    ///   byte-identical to the issuer's own issuer name (pyHanko hashes the first entry and the
    ///   issuer name; OpenSSL compares the first `directoryName` canonically, which accepts
    ///   whatever the bytes accept).
    pub(crate) fn mismatch(
        &self,
        issuer: &KeyIds,
        issuer_parts: &CertParts<'_>,
    ) -> Option<&'static str> {
        for aki in &self.authority {
            if let Some(key_id) = &aki.key_id {
                for ski in &issuer.subject {
                    match ski {
                        None => {
                            return Some(
                                "the issuer's subjectKeyIdentifier, which its keyIdentifier \
                                 must equal, does not decode",
                            );
                        }
                        Some(ski) if ski != key_id => {
                            return Some(
                                "its keyIdentifier is not the issuer's subjectKeyIdentifier",
                            );
                        }
                        Some(_) => {}
                    }
                }
            }
            if let Some(serial) = &aki.cert_serial
                && !cert::serials_match(serial, issuer_parts.serial_content)
            {
                return Some("its authorityCertSerialNumber is not the issuer's serial number");
            }
            match &aki.cert_issuer {
                None => {}
                Some(_) if aki.cert_serial.is_none() => {
                    return Some("its authorityCertIssuer comes without authorityCertSerialNumber");
                }
                Some(AuthorityIssuer::Directory(name))
                    if name.as_slice() == issuer_parts.issuer => {}
                Some(_) => {
                    return Some("its authorityCertIssuer does not name the issuer's own issuer");
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cms::tlv::tlv;

    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(tlv::TAG_SEQUENCE, &parts.concat())
    }

    #[test]
    fn known_extensions_decode_as_rfc_5280_defines_them() {
        let oid = tlv(tlv::TAG_OID, &[0x2A, 0x03, 0x04]);
        let dns = tlv(0x82, b"example.org");
        let uri = tlv(0x86, b"http://example.org/crl");
        let integer = |v: u8| tlv(tlv::TAG_INTEGER, &[v]);
        let good: Vec<(&str, Vec<u8>)> = vec![
            ("2.5.29.14", tlv(tlv::TAG_OCTET_STRING, &[1, 2, 3])),
            ("2.5.29.15", tlv(tlv::TAG_BIT_STRING, &[0x07, 0x80])),
            ("2.5.29.17", seq(&[dns.clone(), uri.clone()])),
            ("2.5.29.18", seq(&[])),
            ("2.5.29.19", seq(&[vec![0x01, 0x01, 0xFF], integer(0)])),
            ("2.5.29.19", seq(&[])),
            (
                "2.5.29.30",
                seq(&[tlv(
                    tlv::TAG_CONTEXT_1,
                    &seq(&[dns.clone(), tlv(0x80, &[0])]),
                )]),
            ),
            (
                "2.5.29.31",
                seq(&[seq(&[tlv(
                    tlv::TAG_CONTEXT_0,
                    &tlv(tlv::TAG_CONTEXT_0, &uri),
                )])]),
            ),
            ("2.5.29.32", seq(&[seq(std::slice::from_ref(&oid))])),
            ("2.5.29.33", seq(&[seq(&[oid.clone(), oid.clone()])])),
            (
                "2.5.29.35",
                seq(&[
                    tlv(0x80, &[1, 2]),
                    tlv(tlv::TAG_CONTEXT_1, &dns),
                    tlv(0x82, &[5]),
                ]),
            ),
            ("2.5.29.35", seq(&[tlv(0x80, &[1, 2])])),
            ("2.5.29.36", seq(&[tlv(0x80, &[0])])),
            ("2.5.29.37", seq(std::slice::from_ref(&oid))),
            ("2.5.29.46", seq(&[seq(&[])])),
            ("2.5.29.54", integer(0)),
            (
                "1.3.6.1.5.5.7.1.1",
                seq(&[seq(&[oid.clone(), uri.clone()])]),
            ),
            ("1.3.6.1.5.5.7.1.3", seq(&[seq(std::slice::from_ref(&oid))])),
            ("1.3.6.1.5.5.7.48.1.5", vec![0x05, 0x00]),
            // Final fix round 2, finding 1: the types asn1crypto or OpenSSL decode beyond these.
            ("2.5.29.9", seq(&[])),
            (
                "2.5.29.9",
                seq(&[seq(&[
                    oid.clone(),
                    tlv(tlv::TAG_SET, &tlv(0x18, b"19700101000000Z")),
                ])]),
            ),
            ("2.5.29.16", seq(&[])),
            (
                "2.5.29.16",
                seq(&[tlv(0x80, b"20260101000000Z"), tlv(0x81, b"20270101000000Z")]),
            ),
            ("2.5.29.16", seq(&[tlv(0x81, b"20270101000000Z")])),
            ("1.3.6.1.5.5.7.1.24", seq(&[integer(5)])),
            ("1.3.6.1.5.5.7.1.24", seq(&[])),
            (
                "2.16.840.1.113730.1.1",
                tlv(tlv::TAG_BIT_STRING, &[0x07, 0x80]),
            ),
            ("1.3.6.1.5.5.7.1.7", seq(&[])),
            (
                "1.3.6.1.5.5.7.1.7",
                seq(&[
                    seq(&[tlv(tlv::TAG_OCTET_STRING, &[0, 1]), vec![0x05, 0x00]]),
                    seq(&[
                        tlv(tlv::TAG_OCTET_STRING, &[0, 2]),
                        seq(&[
                            tlv(tlv::TAG_BIT_STRING, &[0x00, 0x20, 0x01]),
                            seq(&[
                                tlv(tlv::TAG_BIT_STRING, &[0x00, 0x20, 0x02]),
                                tlv(tlv::TAG_BIT_STRING, &[0x00, 0x20, 0x03]),
                            ]),
                        ]),
                    ]),
                ]),
            ),
            ("1.3.6.1.5.5.7.1.8", seq(&[])),
            (
                "1.3.6.1.5.5.7.1.8",
                seq(&[
                    tlv(
                        tlv::TAG_CONTEXT_0,
                        &seq(&[integer(5), seq(&[integer(7), integer(9)])]),
                    ),
                    tlv(tlv::TAG_CONTEXT_1, &[0x05, 0x00]),
                ]),
            ),
            (
                "1.3.6.1.5.5.7.1.14",
                seq(&[seq(std::slice::from_ref(&oid))]),
            ),
            (
                "1.3.6.1.5.5.7.1.14",
                seq(&[
                    integer(1),
                    seq(&[oid.clone(), tlv(tlv::TAG_OCTET_STRING, b"policy")]),
                ]),
            ),
            // Not decoded: anything goes.
            ("1.2.3.4", b"junk".to_vec()),
        ];
        for (dotted, value) in &good {
            assert_eq!(
                value_decodes(dotted, value),
                Ok(()),
                "{dotted}: {value:02x?}"
            );
        }
        let junk = integer(5);
        let bad: Vec<(&str, Vec<u8>)> = vec![
            ("2.5.29.14", junk.clone()),
            ("2.5.29.14", b"\x04\x05\x01".to_vec()),
            ("2.5.29.15", junk.clone()),
            ("2.5.29.17", junk.clone()),
            ("2.5.29.17", seq(&[dns.clone(), vec![0x05, 0x00]])),
            ("2.5.29.17", seq(&[tlv(0x84, b"x")])),
            (
                "2.5.29.17",
                [seq(std::slice::from_ref(&dns)), vec![0x00]].concat(),
            ),
            ("2.5.29.19", junk.clone()),
            ("2.5.29.19", seq(&[integer(0x80)])),
            ("2.5.29.19", seq(&[integer(1), vec![0x01, 0x01, 0xFF]])),
            ("2.5.29.30", junk.clone()),
            (
                "2.5.29.30",
                seq(&[tlv(tlv::TAG_CONTEXT_0, &seq(&[vec![0x05, 0x00]]))]),
            ),
            (
                "2.5.29.30",
                seq(&[tlv(tlv::TAG_CONTEXT_2, &seq(std::slice::from_ref(&dns)))]),
            ),
            ("2.5.29.31", junk.clone()),
            ("2.5.29.31", seq(&[seq(&[tlv(tlv::TAG_CONTEXT_0, &uri)])])),
            ("2.5.29.32", seq(std::slice::from_ref(&junk))),
            ("2.5.29.33", seq(&[seq(std::slice::from_ref(&oid))])),
            ("2.5.29.35", junk.clone()),
            ("2.5.29.35", seq(&[tlv(tlv::TAG_CONTEXT_1, &[0x05, 0x00])])),
            ("2.5.29.35", seq(&[tlv(0x82, &[0, 1])])),
            ("2.5.29.35", seq(&[tlv(0x82, &[5]), tlv(0x80, &[1])])),
            ("2.5.29.36", seq(&[tlv(0x82, &[0])])),
            ("2.5.29.37", seq(std::slice::from_ref(&junk))),
            ("2.5.29.54", tlv(tlv::TAG_INTEGER, &[0xFF])),
            (
                "1.3.6.1.5.5.7.1.1",
                seq(&[seq(&[oid.clone(), vec![0x05, 0x00]])]),
            ),
            (
                "1.3.6.1.5.5.7.1.3",
                seq(&[seq(std::slice::from_ref(&junk))]),
            ),
            ("1.3.6.1.5.5.7.48.1.5", junk.clone()),
            // QA's junk for the seven types of finding 1 (r8-ext-*-{junk-null,empty,junk-oid,
            // trailing}), and their neighbours.
            ("2.5.29.9", vec![0x05, 0x00]),
            ("2.5.29.9", Vec::new()),
            ("2.5.29.9", tlv(tlv::TAG_OID, &[0x2A, 0x03, 0x04])),
            ("2.5.29.9", seq(&[seq(std::slice::from_ref(&oid))])),
            ("2.5.29.9", seq(&[seq(&[oid.clone(), seq(&[])])])),
            ("2.5.29.16", vec![0x05, 0x00]),
            ("2.5.29.16", seq(&[tlv(0x80, b"2026")])),
            (
                "2.5.29.16",
                seq(&[tlv(0x81, b"20270101000000Z"), tlv(0x80, b"20260101000000Z")]),
            ),
            ("2.5.29.16", seq(&[tlv(0x18, b"20260101000000Z")])),
            ("1.3.6.1.5.5.7.1.24", vec![0x05, 0x00]),
            ("1.3.6.1.5.5.7.1.24", seq(std::slice::from_ref(&oid))),
            ("2.16.840.1.113730.1.1", vec![0x05, 0x00]),
            ("2.16.840.1.113730.1.1", Vec::new()),
            (
                "2.16.840.1.113730.1.1",
                tlv(tlv::TAG_OID, &[0x2A, 0x03, 0x04]),
            ),
            ("2.16.840.1.113730.1.1", vec![0x03, 0x00]),
            (
                "2.16.840.1.113730.1.1",
                [tlv(tlv::TAG_BIT_STRING, &[0x07, 0x80]), vec![0x00]].concat(),
            ),
            ("1.3.6.1.5.5.7.1.7", vec![0x05, 0x00]),
            ("1.3.6.1.5.5.7.1.7", Vec::new()),
            ("1.3.6.1.5.5.7.1.7", tlv(tlv::TAG_OID, &[0x2A, 0x03, 0x04])),
            (
                "1.3.6.1.5.5.7.1.7",
                seq(&[seq(&[tlv(tlv::TAG_OCTET_STRING, &[0, 1])])]),
            ),
            (
                "1.3.6.1.5.5.7.1.7",
                seq(&[seq(&[tlv(tlv::TAG_OCTET_STRING, &[0, 1]), integer(5)])]),
            ),
            (
                "1.3.6.1.5.5.7.1.7",
                seq(&[seq(&[
                    tlv(tlv::TAG_OCTET_STRING, &[0, 1]),
                    seq(&[seq(&[tlv(tlv::TAG_BIT_STRING, &[0x00])])]),
                ])]),
            ),
            ("1.3.6.1.5.5.7.1.8", vec![0x05, 0x00]),
            ("1.3.6.1.5.5.7.1.8", Vec::new()),
            ("1.3.6.1.5.5.7.1.8", tlv(tlv::TAG_OID, &[0x2A, 0x03, 0x04])),
            ("1.3.6.1.5.5.7.1.8", seq(&[tlv(tlv::TAG_CONTEXT_0, &junk)])),
            (
                "1.3.6.1.5.5.7.1.8",
                seq(&[
                    tlv(tlv::TAG_CONTEXT_1, &[0x05, 0x00]),
                    tlv(tlv::TAG_CONTEXT_0, &[0x05, 0x00]),
                ]),
            ),
            ("1.3.6.1.5.5.7.1.14", vec![0x05, 0x00]),
            ("1.3.6.1.5.5.7.1.14", Vec::new()),
            ("1.3.6.1.5.5.7.1.14", tlv(tlv::TAG_OID, &[0x2A, 0x03, 0x04])),
            ("1.3.6.1.5.5.7.1.14", seq(&[])),
            ("1.3.6.1.5.5.7.1.14", [seq(&[]), vec![0x00]].concat()),
            ("1.3.6.1.5.5.7.1.14", seq(&[integer(1)])),
            (
                "1.3.6.1.5.5.7.1.14",
                seq(&[seq(&[oid.clone(), integer(1)])]),
            ),
            (
                "1.3.6.1.5.5.7.1.14",
                seq(&[seq(std::slice::from_ref(&oid)), integer(1)]),
            ),
            // An invalid primitive inside an otherwise fine shape.
            ("2.5.29.37", seq(&[tlv(tlv::TAG_OID, &[0x80, 0x01])])),
        ];
        for (dotted, value) in &bad {
            assert!(
                value_decodes(dotted, value).is_err(),
                "{dotted}: {value:02x?}"
            );
        }
        assert_eq!(decoded_name("2.5.29.30"), Some("nameConstraints"));
        assert_eq!(decoded_name("1.2.3"), None);
    }

    #[test]
    fn critical_extensions_openssl_does_not_handle() {
        // M4 closing round, findings 8 and 11: the supported_nids of OpenSSL 3.0's
        // X509_supported_extension, and nothing else, may be critical.
        let extension = |dotted: &str, critical: bool| Extension {
            extn_id: ObjectIdentifier::new_unwrap(dotted),
            critical,
            extn_value: der::asn1::OctetString::new(vec![0x05, 0x00]).unwrap(),
        };
        for dotted in OPENSSL_HANDLED_CRITICAL {
            assert!(openssl_handles_critical(dotted), "{dotted}");
            assert!(
                unhandled_critical(&[extension(dotted, true)]).is_empty(),
                "{dotted}"
            );
        }
        for (dotted, phrase) in [
            (
                "2.5.29.14",
                "a critical subjectKeyIdentifier extension, which OpenSSL does not handle \
                 (unhandled critical extension), and RFC 5280 §4.2.1.2 says it MUST be \
                 non-critical",
            ),
            (
                "2.5.29.35",
                "a critical authorityKeyIdentifier extension, which OpenSSL does not handle \
                 (unhandled critical extension), and RFC 5280 §4.2.1.1 says it MUST be \
                 non-critical",
            ),
            (
                "1.3.6.1.5.5.7.1.3",
                "a critical qcStatements extension, which OpenSSL does not handle (unhandled \
                 critical extension)",
            ),
            (
                "1.3.6.1.4.1.32473.1",
                "an unknown critical extension 1.3.6.1.4.1.32473.1",
            ),
        ] {
            assert!(!openssl_handles_critical(dotted), "{dotted}");
            assert_eq!(
                unhandled_critical(&[extension(dotted, true)]),
                [phrase.to_owned()],
                "{dotted}"
            );
            // Not critical: nothing to say.
            assert!(unhandled_critical(&[extension(dotted, false)]).is_empty());
        }
        // Each one is named.
        let two = [
            extension("2.5.29.46", true),
            extension("2.5.29.15", true),
            extension("1.3.6.1.5.5.7.1.1", true),
        ];
        assert_eq!(unhandled_critical(&two).len(), 2);
    }
}
