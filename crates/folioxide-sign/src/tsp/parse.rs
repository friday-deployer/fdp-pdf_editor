//! Decoding RFC 3161 structures with the bounded TLV reader of [`cms::tlv`](crate::cms::tlv)
//! (M4 brief §4.1 "Parsing"): `TimeStampReq` (strict DER: Folioxide wrote it),
//! `TimeStampResp` and `TSTInfo` (BER or DER), and `genTime` with Folioxide's own parser (R-3).
//!
//! Every slice is bounds-checked, the depth is bounded by [`MAX_DEPTH`], the number of strings
//! in a `PKIFreeText` by [`MAX_STATUS_STRINGS`], and every failure is an
//! [`Error::TimestampInvalid`] naming the part that does not decode. Nothing here panics.

use std::fmt;

use super::{
    Accuracy, GenTime, MessageImprint, PkiStatus, PkiStatusInfo, TimeStampReq, TimeStampResp,
};
use crate::algorithms::DigestAlgorithm;
use crate::cms::decode::algorithm_id;
use crate::cms::tlv::{self, Element, TlvError};
use crate::cms::{AlgorithmId, MAX_DEPTH, oid_to_string};
use crate::error::{Error, Result};
use crate::x509info::names;

/// The most `UTF8String`s read from a `PKIFreeText`.
pub(crate) const MAX_STATUS_STRINGS: usize = 16;

/// The DER `BOOLEAN` tag (X.690 §8.2).
pub(super) const TAG_BOOLEAN: u8 = 0x01;
/// `UTF8String`, primitive.
const TAG_UTF8_STRING: u8 = 0x0C;
/// `UTF8String`, constructed (BER only).
const TAG_UTF8_STRING_CONSTRUCTED: u8 = 0x2C;
/// `[0]` primitive (`Accuracy.millis`, implicit).
const TAG_CONTEXT_0_PRIMITIVE: u8 = 0x80;
/// `[1]` primitive (`Accuracy.micros`, implicit).
const TAG_CONTEXT_1_PRIMITIVE: u8 = 0x81;

/// A [`Error::TimestampInvalid`] with `what`.
pub(super) fn invalid(what: impl fmt::Display) -> Error {
    Error::TimestampInvalid(what.to_string())
}

fn from_tlv(what: &str, err: TlvError) -> Error {
    invalid(format!("{what}: {err}"))
}

/// Sequential access to the children of a constructed element.
struct Fields<'a> {
    input: &'a [u8],
    children: std::iter::Peekable<tlv::Children<'a>>,
    /// The structure, for messages ("TSTInfo").
    what: &'static str,
}

impl<'a> Fields<'a> {
    fn new(input: &'a [u8], parent: &Element, depth: usize, what: &'static str) -> Fields<'a> {
        Fields {
            input,
            children: tlv::children(input, parent, depth, MAX_DEPTH).peekable(),
            what,
        }
    }

    fn next(&mut self, field: &str) -> Result<Element> {
        match self.children.next() {
            Some(Ok(child)) => Ok(child),
            Some(Err(err)) => Err(from_tlv(&format!("{} {field}", self.what), err)),
            None => Err(invalid(format!("{}: {field} is missing", self.what))),
        }
    }

    fn expect(&mut self, tag: u8, field: &str) -> Result<Element> {
        let child = self.next(field)?;
        if child.tag == tag {
            Ok(child)
        } else {
            Err(invalid(format!(
                "{}: {field} has the wrong type",
                self.what
            )))
        }
    }

    /// The next child when it has `tag`.
    fn optional(&mut self, tag: u8) -> Result<Option<Element>> {
        match self.children.peek() {
            Some(Ok(child)) if child.tag == tag => self.next("").map(Some),
            Some(Err(_)) => self.next("").map(Some),
            _ => Ok(None),
        }
    }

    fn finish(mut self) -> Result<()> {
        match self.children.next() {
            None => Ok(()),
            Some(Err(err)) => Err(from_tlv(self.what, err)),
            Some(Ok(_)) => Err(invalid(format!(
                "{}: unexpected element after the last field",
                self.what
            ))),
        }
    }

    fn content(&self, element: &Element) -> &'a [u8] {
        element.content(self.input)
    }
}

/// The value of a small non-negative `INTEGER` (a version number).
fn small_unsigned(content: &[u8], what: &str) -> Result<u32> {
    let value = tlv::integer_canonical(content);
    if value.is_empty() || value.len() > 4 || value.first().is_some_and(|&b| b & 0x80 != 0) {
        return Err(invalid(format!(
            "{what} is not a small non-negative INTEGER"
        )));
    }
    // At most four octets, so nothing is shifted out.
    Ok(value.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)))
}

/// The value of an `INTEGER` that fits in an `i64`.
fn integer_i64(content: &[u8], what: &str) -> Result<i64> {
    let value = tlv::integer_canonical(content);
    if value.is_empty() || value.len() > 8 {
        return Err(invalid(format!(
            "{what} is not an INTEGER that fits 64 bits"
        )));
    }
    let negative = value.first().is_some_and(|&b| b & 0x80 != 0);
    let mut bytes = if negative { [0xFF; 8] } else { [0; 8] };
    let start = 8 - value.len();
    if let Some(tail) = bytes.get_mut(start..) {
        tail.copy_from_slice(value);
    }
    Ok(i64::from_be_bytes(bytes))
}

/// The dotted form of an `OBJECT IDENTIFIER` element.
fn oid(input: &[u8], element: &Element, what: &str) -> Result<String> {
    oid_to_string(element.content(input))
        .ok_or_else(|| invalid(format!("{what} is not a valid OBJECT IDENTIFIER")))
}

/// `MessageImprint ::= SEQUENCE { hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET
/// STRING }`: the raw algorithm and the hash.
pub(crate) fn imprint_parts(
    input: &[u8],
    element: &Element,
    depth: usize,
    what: &'static str,
) -> Result<(AlgorithmId, Vec<u8>)> {
    let mut fields = Fields::new(input, element, depth, what);
    let algorithm_element = fields.expect(tlv::TAG_SEQUENCE, "hashAlgorithm")?;
    let algorithm = algorithm_id(input, &algorithm_element, depth + 1)
        .map_err(|err| invalid(format!("{what}: hashAlgorithm: {err}")))?;
    let hashed = fields.next("hashedMessage")?;
    let hashed = tlv::octet_string_value(input, &hashed, depth + 1, MAX_DEPTH)
        .map_err(|err| from_tlv(&format!("{what} hashedMessage"), err))?;
    fields.finish()?;
    Ok((algorithm, hashed))
}

/// Whether AlgorithmIdentifier parameters are absent or `NULL` (RFC 5754 §2 allows either for
/// SHA-2; M4 brief §4.2 step 4).
pub(crate) fn null_or_absent(parameters: Option<&[u8]>) -> bool {
    parameters.is_none_or(|p| p == [tlv::TAG_NULL, 0x00])
}

// ---- TimeStampReq ------------------------------------------------------------------------------

/// See [`TimeStampReq::from_der`].
pub(super) fn request(der: &[u8]) -> Result<TimeStampReq> {
    let what = "the timestamp request";
    let outer = tlv::read_exact(der, MAX_DEPTH).map_err(|e| from_tlv(what, e))?;
    if outer.tag != tlv::TAG_SEQUENCE {
        return Err(invalid("the timestamp request is not a SEQUENCE"));
    }
    if !tlv::is_der_tree(der, &outer, 0, MAX_DEPTH) {
        return Err(invalid(
            "the timestamp request is not DER (indefinite or non-minimal lengths)",
        ));
    }
    let mut fields = Fields::new(der, &outer, 0, "TimeStampReq");
    let version = fields.expect(tlv::TAG_INTEGER, "version")?;
    if small_unsigned(fields.content(&version), "TimeStampReq version")? != 1 {
        return Err(invalid("TimeStampReq: the version is not 1"));
    }
    let imprint = fields.expect(tlv::TAG_SEQUENCE, "messageImprint")?;
    let (algorithm, hashed) = imprint_parts(der, &imprint, 1, "TimeStampReq messageImprint")?;
    let digest = DigestAlgorithm::from_oid(&algorithm.oid).ok_or_else(|| {
        invalid(format!(
            "TimeStampReq: the hash algorithm {} is not supported",
            algorithm.oid
        ))
    })?;
    if !null_or_absent(algorithm.parameters.as_deref()) {
        return Err(invalid(
            "TimeStampReq: the hash algorithm has parameters other than NULL",
        ));
    }
    if hashed.len() != digest.output_len() {
        return Err(invalid(format!(
            "TimeStampReq: the {digest} hash has {} bytes, not {}",
            hashed.len(),
            digest.output_len()
        )));
    }
    let policy = match fields.optional(tlv::TAG_OID)? {
        Some(element) => Some(oid(der, &element, "TimeStampReq reqPolicy")?),
        None => None,
    };
    let nonce = match fields.optional(tlv::TAG_INTEGER)? {
        Some(element) => {
            let content = element.content(der);
            if content.is_empty()
                || tlv::integer_canonical(content) != content
                || content.first().is_some_and(|&b| b & 0x80 != 0)
            {
                return Err(invalid(
                    "TimeStampReq: the nonce is not a minimal non-negative INTEGER",
                ));
            }
            Some(content.to_vec())
        }
        None => None,
    };
    let cert_req = match fields.optional(TAG_BOOLEAN)? {
        // DER: TRUE is FF, and FALSE (the DEFAULT) is omitted (X.690 §11.1, §11.5).
        Some(element) if element.content(der) == [0xFF] => true,
        Some(_) => {
            return Err(invalid(
                "TimeStampReq: certReq is not DER (only TRUE, as FF, may be written)",
            ));
        }
        None => false,
    };
    if fields.optional(tlv::TAG_CONTEXT_0)?.is_some() {
        return Err(invalid(
            "TimeStampReq: extensions are not supported (Folioxide writes none)",
        ));
    }
    fields.finish()?;
    Ok(TimeStampReq {
        imprint: MessageImprint::new(digest, hashed),
        policy,
        nonce,
        cert_req,
    })
}

// ---- TimeStampResp -----------------------------------------------------------------------------

/// See [`TimeStampResp::from_der`].
pub(super) fn response(der: &[u8]) -> Result<TimeStampResp> {
    let what = "the timestamp response";
    let outer = tlv::read_exact(der, MAX_DEPTH).map_err(|e| from_tlv(what, e))?;
    if outer.tag != tlv::TAG_SEQUENCE {
        return Err(invalid("the timestamp response is not a SEQUENCE"));
    }
    let mut fields = Fields::new(der, &outer, 0, "TimeStampResp");
    let status = fields.expect(tlv::TAG_SEQUENCE, "status")?;
    let status = status_info(der, &status, 1)?;
    let token = fields
        .optional(tlv::TAG_SEQUENCE)?
        .map(|element| element.raw(der).to_vec());
    fields.finish()?;
    Ok(TimeStampResp { status, token })
}

/// `PKIStatusInfo ::= SEQUENCE { status PKIStatus, statusString PKIFreeText OPTIONAL, failInfo
/// PKIFailureInfo OPTIONAL }` (RFC 3161 §2.4.2).
fn status_info(input: &[u8], element: &Element, depth: usize) -> Result<PkiStatusInfo> {
    let mut fields = Fields::new(input, element, depth, "PKIStatusInfo");
    let status = fields.expect(tlv::TAG_INTEGER, "status")?;
    let status = match integer_i64(fields.content(&status), "PKIStatusInfo status")? {
        0 => PkiStatus::Granted,
        1 => PkiStatus::GrantedWithMods,
        2 => PkiStatus::Rejection,
        3 => PkiStatus::Waiting,
        4 => PkiStatus::RevocationWarning,
        5 => PkiStatus::RevocationNotification,
        other => PkiStatus::Unknown(other),
    };
    let mut status_string = Vec::new();
    if let Some(free_text) = fields.optional(tlv::TAG_SEQUENCE)? {
        for text in tlv::children(input, &free_text, depth + 1, MAX_DEPTH) {
            let text = text.map_err(|e| from_tlv("PKIFreeText", e))?;
            if status_string.len() >= MAX_STATUS_STRINGS {
                return Err(invalid(format!(
                    "PKIFreeText has more than {MAX_STATUS_STRINGS} strings"
                )));
            }
            let bytes = utf8_string(input, &text, depth + 2)?;
            status_string.push(String::from_utf8_lossy(&bytes).into_owned());
        }
    }
    let fail_info = match fields.optional(tlv::TAG_BIT_STRING)? {
        Some(bits) => Some(fail_info_bits(bits.content(input))?),
        None => None,
    };
    fields.finish()?;
    Ok(PkiStatusInfo {
        status,
        status_string,
        fail_info,
    })
}

/// A `UTF8String`, primitive or (BER) constructed from primitive segments.
fn utf8_string(input: &[u8], element: &Element, depth: usize) -> Result<Vec<u8>> {
    match element.tag {
        TAG_UTF8_STRING => Ok(element.content(input).to_vec()),
        TAG_UTF8_STRING_CONSTRUCTED => {
            let mut out = Vec::new();
            for segment in tlv::children(input, element, depth, MAX_DEPTH) {
                let segment = segment.map_err(|e| from_tlv("PKIFreeText", e))?;
                out.extend(utf8_string(input, &segment, depth + 1)?);
            }
            Ok(out)
        }
        _ => Err(invalid("PKIFreeText holds something other than UTF8String")),
    }
}

/// `PKIFailureInfo` (a primitive BIT STRING) as bits: bit `i` of the result is named bit `i`
/// (the most significant bit of the first content octet after the unused-bits octet is bit 0,
/// X.690 §8.6.2). Bits from 32 on are dropped.
fn fail_info_bits(content: &[u8]) -> Result<u32> {
    let Some((&unused, bits)) = content.split_first() else {
        return Err(invalid("PKIFailureInfo is an empty BIT STRING"));
    };
    if unused > 7 || (bits.is_empty() && unused != 0) {
        return Err(invalid("PKIFailureInfo is not a valid BIT STRING"));
    }
    let mut out = 0u32;
    for (octet_index, &octet) in bits.iter().enumerate().take(4) {
        for bit in 0..8u32 {
            if octet & (0x80 >> bit) != 0 {
                // Lossless: octet_index < 4.
                out |= 1 << (octet_index as u32 * 8 + bit);
            }
        }
    }
    Ok(out)
}

// ---- TSTInfo -----------------------------------------------------------------------------------

/// A decoded `TSTInfo` whose imprint algorithm may be one Folioxide does not implement
/// (verification reports that as `UnsupportedAlgorithm`, M4 brief §5 V7b step 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawTstInfo {
    pub version: u32,
    pub policy: String,
    pub imprint_algorithm: AlgorithmId,
    pub hashed_message: Vec<u8>,
    pub serial: Vec<u8>,
    pub gen_time: GenTime,
    pub accuracy: Option<Accuracy>,
    pub ordering: bool,
    pub nonce: Option<Vec<u8>>,
    pub tsa_name: Option<String>,
    /// `tsa` is present but is not a `directoryName` Folioxide can read.
    pub tsa_name_unreadable: bool,
    /// The `GeneralName` of `tsa`, whole (without the `[0]` around it), when present: what
    /// must name the TSA certificate (RFC 3161 §2.4.2).
    pub tsa_general_name: Option<Vec<u8>>,
    pub has_extensions: bool,
}

impl RawTstInfo {
    /// The public [`TstInfo`](super::TstInfo); `None` when the imprint algorithm is not one
    /// Folioxide implements.
    pub(crate) fn to_tst_info(&self) -> Option<super::TstInfo> {
        let digest = DigestAlgorithm::from_oid(&self.imprint_algorithm.oid)?;
        Some(super::TstInfo {
            version: self.version,
            policy: self.policy.clone(),
            imprint: MessageImprint::new(digest, self.hashed_message.clone()),
            serial: self.serial.clone(),
            gen_time: self.gen_time,
            accuracy: self.accuracy.clone(),
            ordering: self.ordering,
            nonce: self.nonce.clone(),
            tsa_name: self.tsa_name.clone(),
            has_extensions: self.has_extensions,
        })
    }
}

/// Decodes a BER or DER `TSTInfo` (RFC 3161 §2.4.2):
///
/// ```text
/// TSTInfo ::= SEQUENCE { version INTEGER, policy TSAPolicyId, messageImprint MessageImprint,
///     serialNumber INTEGER, genTime GeneralizedTime, accuracy Accuracy OPTIONAL,
///     ordering BOOLEAN DEFAULT FALSE, nonce INTEGER OPTIONAL, tsa [0] GeneralName OPTIONAL,
///     extensions [1] IMPLICIT Extensions OPTIONAL }
/// ```
pub(crate) fn tst_info(der: &[u8]) -> Result<RawTstInfo> {
    let outer = tlv::read_exact(der, MAX_DEPTH).map_err(|e| from_tlv("TSTInfo", e))?;
    if outer.tag != tlv::TAG_SEQUENCE {
        return Err(invalid("TSTInfo is not a SEQUENCE"));
    }
    let mut fields = Fields::new(der, &outer, 0, "TSTInfo");
    let version = fields.expect(tlv::TAG_INTEGER, "version")?;
    let version = small_unsigned(fields.content(&version), "TSTInfo version")?;
    let policy = fields.expect(tlv::TAG_OID, "policy")?;
    let policy = oid(der, &policy, "TSTInfo policy")?;
    let imprint = fields.expect(tlv::TAG_SEQUENCE, "messageImprint")?;
    let (imprint_algorithm, hashed_message) =
        imprint_parts(der, &imprint, 1, "TSTInfo messageImprint")?;
    let serial = fields.expect(tlv::TAG_INTEGER, "serialNumber")?;
    let serial = fields.content(&serial).to_vec();
    if serial.is_empty() {
        return Err(invalid("TSTInfo: serialNumber is empty"));
    }
    let gen_time = fields.expect(tlv::TAG_GENERALIZED_TIME, "genTime")?;
    let gen_time = GenTime::parse(fields.content(&gen_time))?;
    let accuracy = match fields.optional(tlv::TAG_SEQUENCE)? {
        Some(element) => Some(accuracy(der, &element, 1)?),
        None => None,
    };
    let ordering = match fields.optional(TAG_BOOLEAN)? {
        Some(element) => match element.content(der) {
            [value] => *value != 0,
            _ => return Err(invalid("TSTInfo: ordering is not a BOOLEAN")),
        },
        None => false,
    };
    let nonce = match fields.optional(tlv::TAG_INTEGER)? {
        Some(element) if !element.content(der).is_empty() => Some(element.content(der).to_vec()),
        Some(_) => return Err(invalid("TSTInfo: the nonce is an empty INTEGER")),
        None => None,
    };
    let (tsa_name, tsa_name_unreadable, tsa_general_name) =
        match fields.optional(tlv::TAG_CONTEXT_0)? {
            Some(element) => {
                // tsa [0] EXPLICIT GeneralName (a CHOICE is always tagged explicitly, X.680
                // §31.2.7): exactly one element inside.
                let inner = tlv::children_vec(der, &element, 1, MAX_DEPTH, 1)
                    .map_err(|_| invalid("TSTInfo: tsa is not one GeneralName"))?;
                let [general_name] = inner.as_slice() else {
                    return Err(invalid("TSTInfo: tsa is not one GeneralName"));
                };
                // Every choice as OpenSSL's GENERAL_NAME template decodes it (QA round 1 finding
                // F6, round 4 finding 2: an unknown tag, a universal one or a choice with the
                // wrong form or content makes `ts -verify` refuse the whole token).
                if let Err(why) = names::general_name(der, general_name, 2) {
                    return Err(invalid(format!(
                        "TSTInfo: tsa is a GeneralName that does not decode: {why}"
                    )));
                }
                let raw = general_name.raw(der).to_vec();
                match directory_name(der, &element) {
                    Some(name) => (Some(name), false, Some(raw)),
                    None => (None, true, Some(raw)),
                }
            }
            None => (None, false, None),
        };
    let has_extensions = match fields.optional(tlv::TAG_CONTEXT_1)? {
        Some(element) => {
            extensions(der, &element, 1)?;
            true
        }
        None => false,
    };
    fields.finish()?;
    Ok(RawTstInfo {
        version,
        policy,
        imprint_algorithm,
        hashed_message,
        serial,
        gen_time,
        accuracy,
        ordering,
        nonce,
        tsa_name,
        tsa_name_unreadable,
        tsa_general_name,
        has_extensions,
    })
}

/// `extensions [1] IMPLICIT Extensions` of a TSTInfo (RFC 3161 §2.4.2, which takes `Extensions`
/// from RFC 5280 §4.1): `Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension`, `Extension ::=
/// SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING
/// }`, read as a whitelist. OpenSSL decodes them with its `X509_EXTENSION` template and refuses
/// the whole token when they do not decode, so a `[1]` holding anything else (a GeneralName, a
/// bare OCTET STRING, an INTEGER as extnID, a fourth field) is malformed (QA round 3 finding 4;
/// Folioxide only looked for the tag). The extensions are not interpreted: RFC 3161 defines
/// none, and neither OpenSSL nor pyHanko acts on one.
fn extensions(input: &[u8], element: &Element, depth: usize) -> Result<()> {
    let mut empty = true;
    for extension in tlv::children(input, element, depth, MAX_DEPTH) {
        let extension = extension.map_err(|e| from_tlv("TSTInfo extensions", e))?;
        if extension.tag != tlv::TAG_SEQUENCE {
            return Err(invalid("TSTInfo: an extensions entry is not an Extension"));
        }
        let mut fields = Fields::new(input, &extension, depth + 1, "TSTInfo extension");
        let id = fields.expect(tlv::TAG_OID, "extnID")?;
        oid(input, &id, "TSTInfo extension extnID")?;
        fields.optional(TAG_BOOLEAN)?;
        let value = fields.next("extnValue")?;
        tlv::octet_string_value(input, &value, depth + 2, MAX_DEPTH)
            .map_err(|e| from_tlv("TSTInfo extension extnValue", e))?;
        fields.finish()?;
        empty = false;
    }
    if empty {
        return Err(invalid(
            "TSTInfo: extensions is empty (RFC 5280 §4.1: SIZE (1..MAX))",
        ));
    }
    Ok(())
}

/// `Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER (1..999) OPTIONAL,
/// micros [1] INTEGER (1..999) OPTIONAL }` (implicit tags, RFC 3161 Appendix B module
/// `IMPLICIT TAGS`).
fn accuracy(input: &[u8], element: &Element, depth: usize) -> Result<Accuracy> {
    let mut fields = Fields::new(input, element, depth, "Accuracy");
    let seconds = match fields.optional(tlv::TAG_INTEGER)? {
        Some(element) => {
            let value = integer_i64(element.content(input), "Accuracy seconds")?;
            Some(u64::try_from(value).map_err(|_| invalid("Accuracy seconds is negative"))?)
        }
        None => None,
    };
    let sub_second = |element: Option<Element>, what: &str| -> Result<Option<u16>> {
        match element {
            Some(element) => {
                // [0]/[1] IMPLICIT INTEGER: minimal, as X.690 §8.3.2 and OpenSSL require (the
                // generic check of the token cannot see an implicitly tagged INTEGER).
                let content = element.content(input);
                if tlv::integer_canonical(content).len() != content.len() {
                    return Err(invalid(format!("{what} is not a minimal INTEGER")));
                }
                let value = integer_i64(content, what)?;
                u16::try_from(value)
                    .ok()
                    .filter(|v| *v <= 999)
                    .map(Some)
                    .ok_or_else(|| invalid(format!("{what} is not between 0 and 999")))
            }
            None => Ok(None),
        }
    };
    let millis = sub_second(fields.optional(TAG_CONTEXT_0_PRIMITIVE)?, "Accuracy millis")?;
    let micros = sub_second(fields.optional(TAG_CONTEXT_1_PRIMITIVE)?, "Accuracy micros")?;
    fields.finish()?;
    Ok(Accuracy {
        seconds,
        millis,
        micros,
    })
}

/// The RFC 4514 text of a `tsa [0] EXPLICIT GeneralName` that is a `directoryName [4]
/// EXPLICIT Name` (RFC 5280 §4.2.1.6); `None` for any other name or one that does not decode.
fn directory_name(input: &[u8], tsa: &Element) -> Option<String> {
    use der::Decode as _;
    let mut children = tlv::children(input, tsa, 1, MAX_DEPTH);
    let general_name = children.next()?.ok()?;
    if children.next().is_some() || general_name.tag != tlv::TAG_CONTEXT_4 {
        return None;
    }
    let mut inner = tlv::children(input, &general_name, 2, MAX_DEPTH);
    let name = inner.next()?.ok()?;
    if inner.next().is_some() {
        return None;
    }
    x509_cert::name::Name::from_der(name.raw(input))
        .ok()
        .map(|name| name.to_string())
}

// ---- genTime -----------------------------------------------------------------------------------

/// See [`GenTime::parse`]: `YYYYMMDDhhmmss[.f{1,9}]Z`.
pub(super) fn gen_time(text: &[u8]) -> Result<GenTime> {
    let bad = |why: &str| {
        invalid(format!(
            "genTime {:?} is not YYYYMMDDhhmmss[.fraction]Z: {why}",
            String::from_utf8_lossy(text.get(..text.len().min(40)).unwrap_or_default())
        ))
    };
    let (Some(head), Some(rest)) = (text.get(..14), text.get(14..)) else {
        return Err(bad("too short"));
    };
    if !head.iter().all(u8::is_ascii_digit) {
        return Err(bad("the date and time are not digits"));
    }
    let number = |range: std::ops::Range<usize>| -> i64 {
        head.get(range)
            .unwrap_or_default()
            .iter()
            .fold(0i64, |acc, &d| acc * 10 + i64::from(d - b'0'))
    };
    let (year, month, day) = (number(0..4), number(4..6), number(6..8));
    let (hour, minute, second) = (number(8..10), number(10..12), number(12..14));
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return Err(bad("no such date"));
    }
    if hour > 23 || minute > 59 {
        return Err(bad("no such time"));
    }
    if second > 59 {
        return Err(bad("the seconds are above 59"));
    }
    let (fraction, fraction_digits) = match rest {
        [b'Z'] => (0u32, 0u8),
        [b'.', digits @ .., b'Z'] => {
            if digits.is_empty() || digits.len() > 9 {
                return Err(bad("the fraction has no digit or more than nine"));
            }
            if !digits.iter().all(u8::is_ascii_digit) {
                return Err(bad("the fraction is not digits"));
            }
            let value = digits
                .iter()
                .fold(0u32, |acc, &d| acc * 10 + u32::from(d - b'0'));
            // Lossless: at most nine digits.
            let len = digits.len() as u32;
            (value * 10u32.pow(9 - len), digits.len() as u8)
        }
        [b'.', ..] | [b',', ..] => return Err(bad("the fraction does not end in Z")),
        _ => {
            return Err(bad(
                "the time does not end in Z (a time zone offset or none)",
            ));
        }
    };
    let days = crate::x509info::days_since_epoch(year, month, day);
    Ok(GenTime {
        unix_seconds: days * 86_400 + hour * 3600 + minute * 60 + second,
        nanos: fraction,
        fraction_digits,
    })
}

/// The number of days in `month` of the proleptic Gregorian `year`.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_info_bits_are_numbered_from_the_top() {
        // badAlg (0) and badRequest (2): 1010 0000, 5 unused bits.
        assert_eq!(fail_info_bits(&[5, 0xA0]).unwrap(), 0b101);
        // systemFailure (25): third octet... bit 25 is octet 3, bit 1.
        assert_eq!(fail_info_bits(&[6, 0, 0, 0, 0x40]).unwrap(), 1 << 25);
        assert_eq!(fail_info_bits(&[0]).unwrap(), 0);
        assert!(fail_info_bits(&[]).is_err());
        assert!(fail_info_bits(&[8, 0]).is_err());
        assert!(fail_info_bits(&[1]).is_err());
    }

    #[test]
    fn integers() {
        assert_eq!(integer_i64(&[0x00, 0x80], "x").unwrap(), 128);
        assert_eq!(integer_i64(&[0xFF], "x").unwrap(), -1);
        assert_eq!(integer_i64(&[0x7F; 8], "x").unwrap(), 0x7F7F_7F7F_7F7F_7F7F);
        assert!(integer_i64(&[0x01; 9], "x").is_err());
        assert!(integer_i64(&[], "x").is_err());
        assert_eq!(small_unsigned(&[0x00, 0x01], "x").unwrap(), 1);
        assert!(small_unsigned(&[0x80], "x").is_err());
        assert!(small_unsigned(&[1, 2, 3, 4, 5], "x").is_err());
    }

    #[test]
    fn extensions_are_a_list_of_extensions() {
        let check = |content: &[u8]| {
            let element = tlv::tlv(tlv::TAG_CONTEXT_1, content);
            let parsed = tlv::read_exact(&element, MAX_DEPTH).unwrap();
            extensions(&element, &parsed, 1)
        };
        let oid = tlv::tlv(tlv::TAG_OID, &[0x2A, 0x03]);
        let value = tlv::tlv(tlv::TAG_OCTET_STRING, &[0x05, 0x00]);
        let extension = |parts: &[&[u8]]| tlv::tlv_parts(tlv::TAG_SEQUENCE, parts);
        let critical = [TAG_BOOLEAN, 0x01, 0xFF];
        // One, two, critical, and a BER (constructed) extnValue.
        assert!(check(&extension(&[&oid, &value])).is_ok());
        assert!(
            check(
                &[
                    extension(&[&oid, &value]),
                    extension(&[&oid, &critical, &value])
                ]
                .concat()
            )
            .is_ok()
        );
        let ber_value = [&[0x24, 0x80][..], &value, &[0, 0]].concat();
        assert!(check(&extension(&[&oid, &ber_value])).is_ok());
        // Refused (QA round 3 finding 4).
        for (content, why) in [
            (Vec::new(), "extensions is empty"),
            (tlv::tlv(tlv::TAG_OCTET_STRING, b"zz"), "not an Extension"),
            (
                extension(&[&tlv::tlv(tlv::TAG_INTEGER, &[1]), &value]),
                "extnID",
            ),
            (
                extension(&[&oid, &value, &[0x05, 0x00]]),
                "after the last field",
            ),
            (
                extension(&[&oid, &tlv::tlv(tlv::TAG_INTEGER, &[1])]),
                "extnValue",
            ),
            (extension(&[&oid]), "extnValue is missing"),
            (extension(&[&oid, &critical]), "extnValue"),
            (
                extension(&[&tlv::tlv(tlv::TAG_OID, &[0x80, 0x01]), &value]),
                "OBJECT IDENTIFIER",
            ),
            (vec![0x30, 0x05, 0x06], "TSTInfo extensions"),
        ] {
            let err = check(&content).unwrap_err().to_string();
            assert!(err.contains(why), "{why}: {err}");
        }
    }

    #[test]
    fn days_per_month() {
        assert_eq!(days_in_month(2024, 2), 29);
        assert_eq!(days_in_month(1900, 2), 28);
        assert_eq!(days_in_month(2000, 2), 29);
        assert_eq!(days_in_month(2026, 13), 0);
    }
}
