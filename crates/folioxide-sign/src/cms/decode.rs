//! Parsing `ContentInfo(SignedData)` with raw slices (M3 brief §4.3 "Parsing for verification").
//!
//! The walk uses the bounded BER reader in [`tlv`]; typed decoding happens later and only on
//! leaves. The signed attributes are kept byte for byte: `der` would re-sort an unsorted `SET OF`
//! while decoding, which changes the bytes the signature covers.

use folioxide_syntax::ErrorCode;

use super::tlv::{
    self, Element, TAG_CONTEXT_0, TAG_CONTEXT_0_PRIMITIVE, TAG_CONTEXT_1, TAG_INTEGER, TAG_OID,
    TAG_SEQUENCE, TAG_SET, TlvError,
};
use super::{
    AlgorithmId, MAX_ATTRIBUTES, MAX_CERTIFICATES, MAX_DEPTH, ParsedCms, ParsedSignerInfo,
    SignerIdentifier,
};
use crate::algorithms::oid;
use crate::error::{Error, Result};

/// The most SignerInfos [`parse`] accepts (a verifier rejects more than one anyway).
const MAX_SIGNER_INFOS: usize = 64;

/// A parse failure: malformed bytes, with code `Syntax`.
pub(crate) fn malformed(what: impl std::fmt::Display) -> Error {
    Error::Syntax(folioxide_syntax::Error::new(
        ErrorCode::Syntax,
        format!("malformed CMS: {what}"),
    ))
}

/// A parse failure: a limit was exceeded, with code `LimitExceeded`.
fn limit(what: impl std::fmt::Display) -> Error {
    Error::Syntax(folioxide_syntax::Error::new(
        ErrorCode::LimitExceeded,
        format!("CMS limit exceeded: {what}"),
    ))
}

fn from_tlv(err: TlvError) -> Error {
    match err {
        TlvError::TooDeep => limit(format!("nesting deeper than {MAX_DEPTH}")),
        TlvError::Malformed(what) => malformed(what),
    }
}

/// See [`super::parse()`].
pub(crate) fn parse(cms: &[u8]) -> Result<ParsedCms> {
    let content_info = tlv::read(cms, 0, cms.len(), 0, MAX_DEPTH).map_err(from_tlv)?;
    if content_info.tag != TAG_SEQUENCE {
        return Err(malformed("ContentInfo is not a SEQUENCE"));
    }
    let mut fields = Fields::new(cms, &content_info, 0);
    let content_type = oid_string(cms, &fields.expect(TAG_OID, "contentType")?)?;
    let mut parsed = ParsedCms {
        content_type,
        econtent_type: None,
        econtent: None,
        signer_infos: Vec::new(),
        certificates: Vec::new(),
        raw: content_info.start..content_info.end,
    };
    if parsed.content_type != oid::ID_SIGNED_DATA {
        // Not a signature; verify_detached reports NotSignedData.
        return Ok(parsed);
    }
    let explicit = fields.expect(TAG_CONTEXT_0, "content [0]")?;
    fields.finish()?;
    let mut inner = Fields::new(cms, &explicit, 1);
    let signed_data = inner.expect(TAG_SEQUENCE, "SignedData")?;
    inner.finish()?;

    // SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
    //   certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT OPTIONAL, signerInfos SET }
    let depth = 2;
    let mut fields = Fields::new(cms, &signed_data, depth);
    fields.expect(TAG_INTEGER, "SignedData.version")?;
    fields.expect(TAG_SET, "digestAlgorithms")?;
    let encap = fields.expect(TAG_SEQUENCE, "encapContentInfo")?;
    {
        let mut encap_fields = Fields::new(cms, &encap, depth + 1);
        parsed.econtent_type = Some(oid_string(
            cms,
            &encap_fields.expect(TAG_OID, "eContentType")?,
        )?);
        if let Some(explicit) = encap_fields.optional(TAG_CONTEXT_0)? {
            let mut content = Fields::new(cms, &explicit, depth + 2);
            let octets = content.next_any("eContent")?;
            parsed.econtent = Some(
                tlv::octet_string_value(cms, &octets, depth + 3, MAX_DEPTH).map_err(from_tlv)?,
            );
            content.finish()?;
        }
        encap_fields.finish()?;
    }
    if let Some(certificates) = fields.optional(TAG_CONTEXT_0)? {
        for (count, choice) in tlv::children(cms, &certificates, depth + 1, MAX_DEPTH).enumerate() {
            if count >= MAX_CERTIFICATES {
                return Err(limit(format!("more than {MAX_CERTIFICATES} certificates")));
            }
            let choice = choice.map_err(from_tlv)?;
            // CertificateChoices: only `certificate` (a SEQUENCE) is kept (RFC 5652 §10.2.2).
            if choice.tag == TAG_SEQUENCE {
                parsed.certificates.push(choice.raw(cms).to_vec());
            }
        }
    }
    fields.optional(TAG_CONTEXT_1)?;
    let signer_infos = fields.expect(TAG_SET, "signerInfos")?;
    fields.finish()?;
    for (count, signer_info) in tlv::children(cms, &signer_infos, depth + 1, MAX_DEPTH).enumerate()
    {
        if count >= MAX_SIGNER_INFOS {
            return Err(limit(format!("more than {MAX_SIGNER_INFOS} SignerInfos")));
        }
        let signer_info = signer_info.map_err(from_tlv)?;
        parsed
            .signer_infos
            .push(parse_signer_info(cms, &signer_info, depth + 2)?);
    }
    Ok(parsed)
}

/// `SignerInfo` (RFC 5652 §5.3) at `depth`.
fn parse_signer_info(cms: &[u8], element: &Element, depth: usize) -> Result<ParsedSignerInfo> {
    if element.tag != TAG_SEQUENCE {
        return Err(malformed("SignerInfo is not a SEQUENCE"));
    }
    let mut fields = Fields::new(cms, element, depth);
    let version = small_integer(cms, &fields.expect(TAG_INTEGER, "SignerInfo.version")?)?;
    let sid_element = fields.next_any("sid")?;
    let sid = match sid_element.tag {
        TAG_SEQUENCE => {
            let mut parts = Fields::new(cms, &sid_element, depth + 1);
            let issuer = parts.expect(TAG_SEQUENCE, "sid issuer")?;
            let serial = parts.expect(TAG_INTEGER, "sid serialNumber")?;
            parts.finish()?;
            SignerIdentifier::IssuerAndSerialNumber {
                issuer: issuer.raw(cms).to_vec(),
                serial: serial.raw(cms).to_vec(),
            }
        }
        TAG_CONTEXT_0_PRIMITIVE => {
            SignerIdentifier::SubjectKeyIdentifier(sid_element.content(cms).to_vec())
        }
        TAG_CONTEXT_0 => {
            // A constructed [0] IMPLICIT OCTET STRING (BER).
            let mut key_id = Vec::new();
            for segment in tlv::children(cms, &sid_element, depth + 1, MAX_DEPTH) {
                let segment = segment.map_err(from_tlv)?;
                key_id.extend(
                    tlv::octet_string_value(cms, &segment, depth + 2, MAX_DEPTH)
                        .map_err(from_tlv)?,
                );
            }
            SignerIdentifier::SubjectKeyIdentifier(key_id)
        }
        _ => return Err(malformed("unknown SignerIdentifier")),
    };
    let digest_algorithm = algorithm_id(
        cms,
        &fields.expect(TAG_SEQUENCE, "digestAlgorithm")?,
        depth + 1,
    )?;
    let signed_attrs = match fields.optional(TAG_CONTEXT_0)? {
        Some(attrs) => {
            check_attributes(cms, &attrs, depth + 1)?;
            Some(attrs.raw(cms).to_vec())
        }
        None => None,
    };
    let signature_algorithm = algorithm_id(
        cms,
        &fields.expect(TAG_SEQUENCE, "signatureAlgorithm")?,
        depth + 1,
    )?;
    let signature_element = fields.next_any("signature")?;
    let signature =
        tlv::octet_string_value(cms, &signature_element, depth + 1, MAX_DEPTH).map_err(from_tlv)?;
    let unsigned_attrs = match fields.optional(TAG_CONTEXT_1)? {
        Some(attrs) => {
            check_attributes(cms, &attrs, depth + 1)?;
            Some(attrs.raw(cms).to_vec())
        }
        None => None,
    };
    fields.finish()?;
    Ok(ParsedSignerInfo {
        version,
        sid,
        digest_algorithm,
        signed_attrs,
        signature_algorithm,
        signature,
        unsigned_attrs,
        raw: element.start..element.end,
    })
}

/// Checks that an attribute set is `SET OF Attribute` with at most [`MAX_ATTRIBUTES`] entries,
/// each `SEQUENCE { attrType OID, attrValues SET }` (RFC 5652 §5.3).
fn check_attributes(cms: &[u8], set: &Element, depth: usize) -> Result<()> {
    for (count, attribute) in tlv::children(cms, set, depth, MAX_DEPTH).enumerate() {
        if count >= MAX_ATTRIBUTES {
            return Err(limit(format!("more than {MAX_ATTRIBUTES} attributes")));
        }
        let attribute = attribute.map_err(from_tlv)?;
        if attribute.tag != TAG_SEQUENCE {
            return Err(malformed("an attribute is not a SEQUENCE"));
        }
        let mut fields = Fields::new(cms, &attribute, depth + 1);
        fields.expect(TAG_OID, "attrType")?;
        fields.expect(TAG_SET, "attrValues")?;
        fields.finish()?;
    }
    Ok(())
}

/// The attributes of a raw `signedAttrs`/`unsignedAttrs` element: `(attrType content octets,
/// [value TLVs])`, in order. The element must have passed [`check_attributes`] (it did, if it
/// came from [`parse`]); anything malformed is skipped.
pub(crate) fn attributes(raw: &[u8]) -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
    let Ok(set) = tlv::read_exact(raw, MAX_DEPTH) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for attribute in tlv::children(raw, &set, 0, MAX_DEPTH).take(MAX_ATTRIBUTES) {
        let Ok(attribute) = attribute else { break };
        let mut fields = tlv::children(raw, &attribute, 1, MAX_DEPTH);
        let (Some(Ok(attr_type)), Some(Ok(values))) = (fields.next(), fields.next()) else {
            continue;
        };
        let values = tlv::children(raw, &values, 2, MAX_DEPTH)
            .filter_map(|value| value.ok().map(|v| v.raw(raw).to_vec()))
            .collect();
        out.push((attr_type.content(raw).to_vec(), values));
    }
    out
}

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }`.
pub(crate) fn algorithm_id(input: &[u8], element: &Element, depth: usize) -> Result<AlgorithmId> {
    let mut fields = Fields::new(input, element, depth);
    let algorithm = oid_string(input, &fields.expect(TAG_OID, "algorithm")?)?;
    let parameters = fields.next_optional_any()?.map(|p| p.raw(input).to_vec());
    fields.finish()?;
    Ok(AlgorithmId {
        oid: algorithm,
        parameters,
    })
}

/// The dotted form of an `OBJECT IDENTIFIER` element (X.690 §8.19). Arcs above `u128` are kept
/// as `?`, so an exotic OID never makes a CMS unreadable; it only never matches a known OID.
pub(crate) fn oid_string(input: &[u8], element: &Element) -> Result<String> {
    if element.tag != TAG_OID {
        return Err(malformed("expected an OBJECT IDENTIFIER"));
    }
    oid_to_string(element.content(input)).ok_or_else(|| malformed("invalid OBJECT IDENTIFIER"))
}

/// The dotted form of OID content octets, or `None` when they are not valid.
pub(crate) fn oid_to_string(content: &[u8]) -> Option<String> {
    if content.is_empty() || content.last().is_some_and(|&b| b & 0x80 != 0) {
        return None;
    }
    let mut arcs: Vec<String> = Vec::new();
    let mut value: Option<u128> = Some(0);
    let mut first = true;
    let mut started = false;
    for &byte in content {
        if !started && byte == 0x80 {
            // X.690 §8.19.2: no leading 0x80 octet in a subidentifier.
            return None;
        }
        started = true;
        value = value
            .and_then(|v| v.checked_mul(128))
            .and_then(|v| v.checked_add(u128::from(byte & 0x7F)));
        if byte & 0x80 == 0 {
            match (first, value) {
                (true, Some(v)) => {
                    let (a, b) = match v {
                        0..=39 => (0, v),
                        40..=79 => (1, v - 40),
                        _ => (2, v - 80),
                    };
                    arcs.push(a.to_string());
                    arcs.push(b.to_string());
                }
                (true, None) => {
                    arcs.push("2".into());
                    arcs.push("?".into());
                }
                (false, Some(v)) => arcs.push(v.to_string()),
                (false, None) => arcs.push("?".into()),
            }
            first = false;
            started = false;
            value = Some(0);
        }
    }
    Some(arcs.join("."))
}

/// A small non-negative `INTEGER` (a version number).
fn small_integer(input: &[u8], element: &Element) -> Result<u32> {
    let content = tlv::integer_canonical(element.content(input));
    if content.is_empty() || content.len() > 4 || content.first().is_some_and(|&b| b & 0x80 != 0) {
        return Err(malformed("version is not a small INTEGER"));
    }
    Ok(content
        .iter()
        .fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
}

/// Sequential access to the children of a constructed element.
struct Fields<'a> {
    children: std::iter::Peekable<tlv::Children<'a>>,
}

impl<'a> Fields<'a> {
    fn new(input: &'a [u8], parent: &Element, parent_depth: usize) -> Fields<'a> {
        Fields {
            children: tlv::children(input, parent, parent_depth, MAX_DEPTH).peekable(),
        }
    }

    fn next_any(&mut self, what: &str) -> Result<Element> {
        match self.children.next() {
            Some(child) => child.map_err(from_tlv),
            None => Err(malformed(format!("{what} is missing"))),
        }
    }

    fn next_optional_any(&mut self) -> Result<Option<Element>> {
        self.children.next().transpose().map_err(from_tlv)
    }

    fn expect(&mut self, tag: u8, what: &str) -> Result<Element> {
        let child = self.next_any(what)?;
        if child.tag == tag {
            Ok(child)
        } else {
            Err(malformed(format!("{what} has the wrong type")))
        }
    }

    fn optional(&mut self, tag: u8) -> Result<Option<Element>> {
        match self.children.peek() {
            Some(Ok(child)) if child.tag == tag => self.next_any("").map(Some),
            Some(Err(_)) => self.next_any("").map(Some),
            _ => Ok(None),
        }
    }

    fn finish(mut self) -> Result<()> {
        match self.children.next() {
            None => Ok(()),
            Some(Err(err)) => Err(from_tlv(err)),
            Some(Ok(_)) => Err(malformed("unexpected extra element")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oids() {
        assert_eq!(
            oid_to_string(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]).as_deref(),
            Some(oid::ID_SIGNED_DATA)
        );
        assert_eq!(
            oid_to_string(&[0x2B, 0x81, 0x04, 0x00, 0x22]).as_deref(),
            Some(oid::SECP384R1)
        );
        assert_eq!(oid_to_string(&[0x88, 0x37]).as_deref(), Some("2.999"));
        assert_eq!(oid_to_string(&[]), None);
        assert_eq!(oid_to_string(&[0x2A, 0x86]), None);
        assert_eq!(oid_to_string(&[0x2A, 0x80, 0x01]), None);
        let mut huge = vec![0x2A];
        huge.extend([0xFF; 20]);
        huge.push(0x7F);
        assert_eq!(oid_to_string(&huge).as_deref(), Some("1.2.?"));
    }

    #[test]
    fn not_signed_data_parses_without_signers() {
        // ContentInfo { id-data }
        let ci = [
            0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
        ];
        let parsed = parse(&ci).unwrap();
        assert_eq!(parsed.content_type, oid::ID_DATA);
        assert!(parsed.signer_infos.is_empty());
        assert_eq!(parsed.raw, 0..ci.len());
    }

    #[test]
    fn padding_after_the_element_is_ignored() {
        let mut ci = vec![
            0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
        ];
        ci.extend([0u8; 16]);
        assert_eq!(parse(&ci).unwrap().raw, 0..13);
    }

    #[test]
    fn errors_have_codes() {
        let err = parse(b"garbage").unwrap_err();
        assert_eq!(err.code(), ErrorCode::Syntax);
        let mut deep = Vec::new();
        for _ in 0..40 {
            deep.extend([0x30, 0x80]);
        }
        deep.extend([0u8; 80]);
        assert_eq!(parse(&deep).unwrap_err().code(), ErrorCode::LimitExceeded);
    }
}
