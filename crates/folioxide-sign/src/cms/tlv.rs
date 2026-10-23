//! A bounded BER/DER TLV reader and a small DER writer (X.690).
//!
//! The reader keeps absolute byte offsets into the input, so callers can hand out raw slices
//! (signed attributes, certificates, `sid`) exactly as they were found: re-encoding them would
//! change the bytes a signature covers (M3 brief §4.3). It accepts:
//!
//! - definite lengths in short and long form, minimal or not (X.690 §8.1.3), and
//! - the BER indefinite form on constructed elements, ended by an end-of-contents octet pair
//!   (X.690 §8.1.3.6, §8.1.5),
//!
//! with every offset bounds-checked, every addition checked and the nesting depth bounded by the
//! caller's limit. It never panics.
//!
//! The writer emits DER: definite lengths in the minimal form (X.690 §10.1).

use std::fmt;

/// Universal `INTEGER`.
pub(crate) const TAG_INTEGER: u8 = 0x02;
/// Universal `BIT STRING`, primitive.
pub(crate) const TAG_BIT_STRING: u8 = 0x03;
/// Universal `OCTET STRING`, primitive.
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;
/// Universal `OCTET STRING`, constructed (BER only).
pub(crate) const TAG_OCTET_STRING_CONSTRUCTED: u8 = 0x24;
/// Universal `NULL`.
pub(crate) const TAG_NULL: u8 = 0x05;
/// Universal `OBJECT IDENTIFIER`.
pub(crate) const TAG_OID: u8 = 0x06;
/// Universal `UTCTime`.
pub(crate) const TAG_UTC_TIME: u8 = 0x17;
/// Universal `GeneralizedTime`.
pub(crate) const TAG_GENERALIZED_TIME: u8 = 0x18;
/// Universal `SEQUENCE`, constructed.
pub(crate) const TAG_SEQUENCE: u8 = 0x30;
/// Universal `SET`, constructed.
pub(crate) const TAG_SET: u8 = 0x31;
/// Context-specific `[0]`, constructed.
pub(crate) const TAG_CONTEXT_0: u8 = 0xA0;
/// Context-specific `[1]`, constructed.
pub(crate) const TAG_CONTEXT_1: u8 = 0xA1;
/// Context-specific `[2]`, constructed.
pub(crate) const TAG_CONTEXT_2: u8 = 0xA2;
/// Context-specific `[3]`, constructed.
pub(crate) const TAG_CONTEXT_3: u8 = 0xA3;
/// Context-specific `[4]`, constructed (`GeneralName.directoryName`, RFC 5280 §4.2.1.6).
pub(crate) const TAG_CONTEXT_4: u8 = 0xA4;
/// Context-specific `[0]`, primitive (`SignerIdentifier.subjectKeyIdentifier`, RFC 5652 §5.3).
pub(crate) const TAG_CONTEXT_0_PRIMITIVE: u8 = 0x80;

/// The constructed bit of an identifier octet (X.690 §8.1.2.5).
const CONSTRUCTED: u8 = 0x20;

/// Why the bytes are not a well-formed BER element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TlvError {
    /// The encoding is malformed; the text says where.
    Malformed(&'static str),
    /// The nesting is deeper than the caller's limit.
    TooDeep,
}

impl fmt::Display for TlvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlvError::Malformed(what) => write!(f, "malformed ASN.1: {what}"),
            TlvError::TooDeep => f.write_str("ASN.1 nesting is too deep"),
        }
    }
}

/// One BER element, as absolute offsets into the input it was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Element {
    /// The first identifier octet (class, constructed bit and a tag number below 31). For a
    /// high tag number (X.690 §8.1.2.4) the low five bits are all set.
    pub tag: u8,
    /// The offset of the first identifier octet.
    pub start: usize,
    /// The offset of the first content octet.
    pub content_start: usize,
    /// The offset just after the last content octet (before the end-of-contents octets of an
    /// indefinite-length element).
    pub content_end: usize,
    /// The offset just after the element (after the end-of-contents octets, if any).
    pub end: usize,
    /// The length uses the indefinite form.
    pub indefinite: bool,
    /// The length is definite and in the minimal form that DER requires (X.690 §10.1).
    pub minimal_length: bool,
}

impl Element {
    /// Whether the constructed bit is set.
    pub fn is_constructed(&self) -> bool {
        self.tag & CONSTRUCTED != 0
    }

    /// The whole element, identifier to end, as a slice of `input`.
    pub fn raw<'a>(&self, input: &'a [u8]) -> &'a [u8] {
        input.get(self.start..self.end).unwrap_or_default()
    }

    /// The content octets as a slice of `input` (for an indefinite-length element, the encoded
    /// children without the end-of-contents octets).
    pub fn content<'a>(&self, input: &'a [u8]) -> &'a [u8] {
        input
            .get(self.content_start..self.content_end)
            .unwrap_or_default()
    }

    /// Whether this element is DER-shaped at its own level: a definite, minimal length, and no
    /// constructed form for a universal type other than SEQUENCE and SET (X.690 §10.2).
    pub fn is_der_header(&self) -> bool {
        let universal_constructed = self.tag & 0xE0 == CONSTRUCTED;
        let structured = self.tag == TAG_SEQUENCE || self.tag == TAG_SET;
        self.minimal_length && !self.indefinite && !(universal_constructed && !structured)
    }
}

/// Reads one element that starts at `pos` and must end at or before `limit`.
///
/// `depth` is the nesting depth of this element (0 for the outermost); an element at a depth
/// above `max_depth` fails with [`TlvError::TooDeep`]. Indefinite-length elements are walked to
/// find their end, which reads their descendants at the following depths.
pub(crate) fn read(
    input: &[u8],
    pos: usize,
    limit: usize,
    depth: usize,
    max_depth: usize,
) -> Result<Element, TlvError> {
    if depth > max_depth {
        return Err(TlvError::TooDeep);
    }
    let limit = limit.min(input.len());
    let byte_at = |i: usize| -> Result<u8, TlvError> {
        if i < limit {
            input
                .get(i)
                .copied()
                .ok_or(TlvError::Malformed("truncated element"))
        } else {
            Err(TlvError::Malformed("truncated element"))
        }
    };

    let tag = byte_at(pos)?;
    let mut p = pos.checked_add(1).ok_or(TlvError::Malformed("offset"))?;
    if tag & 0x1F == 0x1F {
        // High tag number form (X.690 §8.1.2.4): base-128 octets, the last without bit 8. CMS
        // never uses them; they are read only to skip such elements.
        let mut octets = 0;
        loop {
            let b = byte_at(p)?;
            p += 1;
            octets += 1;
            if octets > 4 {
                return Err(TlvError::Malformed("tag number too large"));
            }
            if b & 0x80 == 0 {
                break;
            }
        }
    }

    let first = byte_at(p)?;
    p += 1;
    let constructed = tag & CONSTRUCTED != 0;
    if first == 0x80 {
        // Indefinite form: only for constructed encodings (X.690 §8.1.3.2 a).
        if !constructed {
            return Err(TlvError::Malformed(
                "indefinite length on a primitive element",
            ));
        }
        let content_start = p;
        let mut cursor = p;
        loop {
            if byte_at(cursor)? == 0 && byte_at(cursor + 1)? == 0 {
                return Ok(Element {
                    tag,
                    start: pos,
                    content_start,
                    content_end: cursor,
                    end: cursor + 2,
                    indefinite: true,
                    minimal_length: false,
                });
            }
            let child = read(input, cursor, limit, depth + 1, max_depth)?;
            cursor = child.end;
        }
    }

    let (len, minimal) = if first < 0x80 {
        (usize::from(first), true)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0x7F {
            return Err(TlvError::Malformed("reserved length octet"));
        }
        if count > std::mem::size_of::<usize>() {
            return Err(TlvError::Malformed("length too large"));
        }
        let mut len: usize = 0;
        let mut leading_zero = false;
        for i in 0..count {
            let b = byte_at(p)?;
            if i == 0 && b == 0 {
                leading_zero = true;
            }
            len = len
                .checked_mul(256)
                .and_then(|l| l.checked_add(usize::from(b)))
                .ok_or(TlvError::Malformed("length too large"))?;
            p += 1;
        }
        (len, !leading_zero && len >= 0x80)
    };
    let content_end = p
        .checked_add(len)
        .ok_or(TlvError::Malformed("length overflows"))?;
    if content_end > limit {
        return Err(TlvError::Malformed(
            "length past the end of the enclosing element",
        ));
    }
    Ok(Element {
        tag,
        start: pos,
        content_start: p,
        content_end,
        end: content_end,
        indefinite: false,
        minimal_length: minimal,
    })
}

/// Reads the single element that must fill `input` exactly.
pub(crate) fn read_exact(input: &[u8], max_depth: usize) -> Result<Element, TlvError> {
    let element = read(input, 0, input.len(), 0, max_depth)?;
    if element.end == input.len() {
        Ok(element)
    } else {
        Err(TlvError::Malformed("trailing bytes after the element"))
    }
}

/// The children of a constructed element, in order.
///
/// `parent_depth` is the depth of `parent`; the children are at `parent_depth + 1`.
pub(crate) fn children<'a>(
    input: &'a [u8],
    parent: &Element,
    parent_depth: usize,
    max_depth: usize,
) -> Children<'a> {
    Children {
        input,
        pos: parent.content_start,
        end: parent.content_end,
        depth: parent_depth + 1,
        max_depth,
        failed: !parent.is_constructed(),
    }
}

/// Iterator over the children of a constructed element; see [`children`].
pub(crate) struct Children<'a> {
    input: &'a [u8],
    pos: usize,
    end: usize,
    depth: usize,
    max_depth: usize,
    failed: bool,
}

impl Iterator for Children<'_> {
    type Item = Result<Element, TlvError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            self.failed = false;
            // Report a primitive "parent" once, then stop.
            self.pos = self.end;
            return Some(Err(TlvError::Malformed("expected a constructed element")));
        }
        if self.pos >= self.end {
            return None;
        }
        match read(self.input, self.pos, self.end, self.depth, self.max_depth) {
            Ok(element) => {
                self.pos = element.end;
                Some(Ok(element))
            }
            Err(err) => {
                self.pos = self.end;
                Some(Err(err))
            }
        }
    }
}

/// Collects the children of `parent`, failing when there are more than `max_count`.
pub(crate) fn children_vec(
    input: &[u8],
    parent: &Element,
    parent_depth: usize,
    max_depth: usize,
    max_count: usize,
) -> Result<Vec<Element>, TlvError> {
    let mut out = Vec::new();
    for child in children(input, parent, parent_depth, max_depth) {
        if out.len() >= max_count {
            return Err(TlvError::Malformed("too many elements"));
        }
        out.push(child?);
    }
    Ok(out)
}

/// The value of an OCTET STRING, primitive or (BER) constructed from primitive segments
/// (X.690 §8.7.3).
pub(crate) fn octet_string_value(
    input: &[u8],
    element: &Element,
    depth: usize,
    max_depth: usize,
) -> Result<Vec<u8>, TlvError> {
    match element.tag {
        TAG_OCTET_STRING => Ok(element.content(input).to_vec()),
        TAG_OCTET_STRING_CONSTRUCTED => {
            let mut out = Vec::new();
            for segment in children(input, element, depth, max_depth) {
                let segment = segment?;
                out.extend(octet_string_value(input, &segment, depth + 1, max_depth)?);
            }
            Ok(out)
        }
        _ => Err(TlvError::Malformed("expected an OCTET STRING")),
    }
}

/// Checks that `element` and everything inside it is DER-shaped: definite minimal lengths, no
/// constructed strings, and every SET's elements in DER order (X.690 §10, §11.6). It is a check
/// of the encoding rules a verifier like OpenSSL would trip over, not a full DER validator.
pub(crate) fn is_der_tree(input: &[u8], element: &Element, depth: usize, max_depth: usize) -> bool {
    is_der_tree_except(input, element, depth, max_depth, &[])
}

/// [`is_der_tree`], treating every element that spans exactly one of `opaque` (byte ranges in
/// `input`) as DER without looking at it: an embedded value whose encoding is someone else's,
/// such as a TSA's timestamp token (M4 brief §4.3, DECISIONS D13 D-12). Its encoding still
/// counts for the order of the `SET` that holds it.
pub(crate) fn is_der_tree_except(
    input: &[u8],
    element: &Element,
    depth: usize,
    max_depth: usize,
    opaque: &[std::ops::Range<usize>],
) -> bool {
    if opaque
        .iter()
        .any(|range| range.start == element.start && range.end == element.end)
    {
        return true;
    }
    if !element.is_der_header() {
        return false;
    }
    if !element.is_constructed() {
        return true;
    }
    let mut previous: Option<&[u8]> = None;
    let is_set = element.tag == TAG_SET;
    for child in children(input, element, depth, max_depth) {
        let Ok(child) = child else {
            return false;
        };
        if !is_der_tree_except(input, &child, depth + 1, max_depth, opaque) {
            return false;
        }
        let raw = child.raw(input);
        if is_set {
            if let Some(prev) = previous
                && der_set_order(prev, raw) == std::cmp::Ordering::Greater
            {
                return false;
            }
            previous = Some(raw);
        }
    }
    true
}

/// Whether every universal BOOLEAN in `element` (read at `depth`), itself included, is `00` or
/// `FF`, and every primitive universal BIT STRING has its unused bits set to zero (and no unused
/// bits when it is empty): the DER content rules of X.690 §11.1 and §11.2.1 (§8.6.2.3), which
/// [`is_der_tree`] does not look at. A verifier that decodes and re-encodes a value (OpenSSL's
/// `ASN1_TYPE` for an attribute value: `c2i_ASN1_BIT_STRING` clears the unused bits, a BOOLEAN
/// comes back as `FF`) changes any other encoding (M4 QA round 3 finding 2). One pass, depth
/// bounded by `max_depth`.
pub(crate) fn der_primitive_contents(
    input: &[u8],
    element: &Element,
    depth: usize,
    max_depth: usize,
) -> bool {
    let universal = element.tag & 0xC0 == 0 && element.tag & 0x1F != 0x1F;
    if !element.is_constructed() {
        if !universal {
            return true;
        }
        let content = element.content(input);
        return match element.tag & 0x1F {
            0x01 => matches!(content, [0x00] | [0xFF]),
            0x03 => match content.split_first() {
                Some((&0, _)) => true,
                Some((&unused, [.., last])) if unused <= 7 => {
                    last & !u8::MAX.checked_shl(u32::from(unused)).unwrap_or(0) == 0
                }
                _ => false,
            },
            _ => true,
        };
    }
    children(input, element, depth, max_depth)
        .all(|child| child.is_ok_and(|c| der_primitive_contents(input, &c, depth + 1, max_depth)))
}

/// Whether the content octets of a universal string of tag number `number` are text that
/// OpenSSL's `ASN1_STRING_to_UTF8` converts (`ASN1_mbstring_ncopy`, `is_unicode_valid`), as it
/// does for every value of every X.509 `Name` it decodes (`x509_name_canon`):
///
/// - a UTF8String is UTF-8 (RFC 3629: no surrogate, nothing above U+10FFFF, no overlong form);
/// - a BMPString is UCS-2, big-endian: an even length and **no code unit in D800–DFFF**, alone
///   or paired (OpenSSL reads one code unit per character, so a UTF-16 surrogate pair is two
///   illegal characters there; M4 QA round 4 finding 1);
/// - a UniversalString is UCS-4, big-endian: a multiple-of-four length and every value a
///   Unicode scalar value (at most 10FFFF, not a surrogate).
///
/// Non-characters (U+FFFE, U+FFFF) and NUL are characters there, so they pass. Every other
/// string type converts byte by byte and always passes.
pub(crate) fn string_converts(number: u8, content: &[u8]) -> bool {
    let scalar = |value: u32| value <= 0x10_FFFF && !(0xD800..=0xDFFF).contains(&value);
    match number {
        0x0C => std::str::from_utf8(content).is_ok(),
        0x1E => {
            content.len().is_multiple_of(2)
                && content.chunks_exact(2).all(|unit| match unit {
                    [hi, lo] => scalar(u32::from(u16::from_be_bytes([*hi, *lo]))),
                    _ => false,
                })
        }
        0x1C => {
            content.len().is_multiple_of(4)
                && content.chunks_exact(4).all(|quad| match quad {
                    [a, b, c, d] => scalar(u32::from_be_bytes([*a, *b, *c, *d])),
                    _ => false,
                })
        }
        _ => true,
    }
}

/// Checks that every element in `element` (read at `depth`), itself included, is an encoding
/// an ASN.1 decoder such as OpenSSL's accepts as far as the universal types go (X.690 §8, BER
/// or DER), and returns what is wrong otherwise:
///
/// - a BOOLEAN has one content octet (§8.2.1); an INTEGER or ENUMERATED is non-empty and has
///   no redundant leading octet (§8.3.2, §8.4); a NULL has no content (§8.8.2);
/// - an OBJECT IDENTIFIER has content, ends a subidentifier at its last octet and starts no
///   subidentifier with `0x80` (§8.19.2);
/// - a primitive BIT STRING has its unused-bits octet, at most 7 (§8.6.2);
/// - a UTF8String, BMPString or UniversalString is text OpenSSL converts to UTF-8
///   ([`string_converts`]: no surrogate in a BMPString, a Unicode scalar value in every
///   UniversalString character; OpenSSL converts them in every name it decodes, M4 QA round 4
///   finding 1, and the rule holds for every such string of the token, which is stricter than
///   OpenSSL outside names); a UTCTime has at least 13 and a GeneralizedTime at least 15
///   octets;
/// - none of the always-primitive types (BOOLEAN, INTEGER, NULL, OBJECT IDENTIFIER, REAL,
///   ENUMERATED, RELATIVE-OID) is constructed, SEQUENCE and SET are, and the segments of a
///   constructed string have the string's own type (§8.21);
/// - no end-of-contents octets stand inside a definite length (§8.1.5).
///
/// These are the checks of OpenSSL's `c2i_ASN1_INTEGER`, `c2i_ASN1_OBJECT`,
/// `c2i_ASN1_BIT_STRING`, `asn1_ex_c2i` and its name decoding (M4 QA round 1 finding F6). The contents of OCTET
/// STRINGs, of BIT STRINGs and of implicitly tagged primitives are not looked into: their type
/// is not known here. One pass, depth bounded by `max_depth`.
pub(crate) fn check_primitives(
    input: &[u8],
    element: &Element,
    depth: usize,
    max_depth: usize,
) -> Result<(), &'static str> {
    const UNIVERSAL_CLASS: u8 = 0x00;
    let universal = element.tag & 0xC0 == UNIVERSAL_CLASS && element.tag & 0x1F != 0x1F;
    let number = element.tag & 0x1F;
    if universal && !element.is_constructed() {
        let content = element.content(input);
        let ok = match number {
            0x00 => return Err("end-of-contents octets inside a definite length"),
            0x01 => content.len() == 1,
            0x02 | 0x0A => !content.is_empty() && integer_canonical(content).len() == content.len(),
            0x03 => content.first().is_some_and(|&unused| unused <= 7),
            0x05 => content.is_empty(),
            0x06 => valid_oid(content),
            0x0C | 0x1C | 0x1E => string_converts(number, content),
            0x10 | 0x11 => return Err("a primitive SEQUENCE or SET"),
            0x17 => content.len() >= 13,
            0x18 => content.len() >= 15,
            _ => true,
        };
        return if ok {
            Ok(())
        } else {
            Err(match number {
                0x01 => "a BOOLEAN that is not one octet",
                0x02 | 0x0A => "an empty or non-minimal INTEGER",
                0x03 => "a BIT STRING without a valid unused-bits octet",
                0x05 => "a NULL with content",
                0x06 => "an invalid OBJECT IDENTIFIER",
                0x0C => "a UTF8String that is not UTF-8",
                0x17 | 0x18 => "a time value that is too short",
                0x1E if content.len().is_multiple_of(2) => {
                    "a BMPString with a UTF-16 surrogate code unit, which OpenSSL cannot convert \
                     to UTF-8 (ASN1_mbstring_ncopy: illegal characters)"
                }
                0x1C if content.len().is_multiple_of(4) => {
                    "a UniversalString with a surrogate or a value above 10FFFF, which OpenSSL \
                     cannot convert to UTF-8 (ASN1_mbstring_ncopy: illegal characters)"
                }
                _ => "a string of the wrong length for its type",
            })
        };
    }
    if !element.is_constructed() {
        return Ok(());
    }
    if universal && matches!(number, 0x01 | 0x02 | 0x05 | 0x06 | 0x09 | 0x0A | 0x0D) {
        return Err("a constructed encoding of a type that is always primitive");
    }
    // The string types, whose BER constructed form is a list of segments (X.690 §8.21).
    let string = matches!(number, 0x03 | 0x04 | 0x0C | 0x12..=0x1C | 0x1E);
    let segments_of = (universal && string).then_some(number);
    for child in children(input, element, depth, max_depth) {
        let child = child.map_err(|err| match err {
            TlvError::Malformed(what) => what,
            TlvError::TooDeep => "nested too deep",
        })?;
        if let Some(number) = segments_of
            && (child.tag & 0xC0 != UNIVERSAL_CLASS || child.tag & 0x1F != number)
        {
            return Err("a constructed string with a segment of another type");
        }
        check_primitives(input, &child, depth + 1, max_depth)?;
    }
    Ok(())
}

/// Whether OBJECT IDENTIFIER content octets are valid (X.690 §8.19.2): not empty, the last
/// octet ends a subidentifier, and no subidentifier starts with `0x80`.
pub(crate) fn valid_oid(content: &[u8]) -> bool {
    let Some(&last) = content.last() else {
        return false;
    };
    let mut starts_subidentifier = true;
    for &byte in content {
        if starts_subidentifier && byte == 0x80 {
            return false;
        }
        starts_subidentifier = byte & 0x80 == 0;
    }
    last & 0x80 == 0
}

/// The order of two encodings in a DER `SET OF`: compared as octet strings, the shorter one
/// padded at its end with zero octets (X.690 §11.6).
pub(crate) fn der_set_order(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let len = a.len().max(b.len());
    let byte = |s: &[u8], i: usize| s.get(i).copied().unwrap_or(0);
    for i in 0..len {
        match byte(a, i).cmp(&byte(b, i)) {
            std::cmp::Ordering::Equal => continue,
            other => return other,
        }
    }
    std::cmp::Ordering::Equal
}

/// The content octets of an `INTEGER` with redundant leading octets removed (a leading `0x00`
/// before an octet below `0x80`, or `0xFF` before one at or above it, X.690 §8.3.2), so two
/// encodings of the same value compare equal.
pub(crate) fn integer_canonical(content: &[u8]) -> &[u8] {
    let mut value = content;
    while let [first, second, ..] = value {
        let redundant =
            (*first == 0x00 && second & 0x80 == 0) || (*first == 0xFF && second & 0x80 != 0);
        if !redundant {
            break;
        }
        value = value.get(1..).unwrap_or_default();
    }
    value
}

// ---------------------------------------------------------------------------------------------
// DER writer
// ---------------------------------------------------------------------------------------------

/// The number of octets a DER length takes (X.690 §8.1.3: short form below 128, else the
/// minimal long form).
pub(crate) fn length_len(len: usize) -> usize {
    if len < 0x80 {
        1
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        1 + (bytes.len() - skip)
    }
}

/// The total DER size of an element with a one-octet tag and `content_len` content octets.
pub(crate) fn tlv_len(content_len: usize) -> usize {
    1 + length_len(content_len) + content_len
}

/// Appends a DER identifier and length.
pub(crate) fn push_header(out: &mut Vec<u8>, tag: u8, len: usize) {
    out.push(tag);
    if len < 0x80 {
        // Lossless: len < 128.
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let significant = bytes.get(skip..).unwrap_or_default();
        // Lossless: at most size_of::<usize>() <= 16 length octets.
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
}

/// Appends the DER TLV `tag || length || content`.
pub(crate) fn push_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    push_header(out, tag, content.len());
    out.extend_from_slice(content);
}

/// The DER TLV `tag || length || content`.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tlv_len(content.len()));
    push_tlv(&mut out, tag, content);
    out
}

/// The DER TLV of `tag` around the concatenation of `parts`.
pub(crate) fn tlv_parts(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let len = parts.iter().map(|p| p.len()).sum();
    let mut out = Vec::with_capacity(tlv_len(len));
    push_header(&mut out, tag, len);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// The DER `INTEGER` of a non-negative big-endian magnitude: leading zeros removed, and one
/// zero octet added when the first octet has its high bit set (X.690 §8.3).
pub(crate) fn unsigned_integer(magnitude: &[u8]) -> Vec<u8> {
    let skip = magnitude.iter().take_while(|&&b| b == 0).count();
    let significant = magnitude.get(skip..).unwrap_or_default();
    let mut content = Vec::with_capacity(significant.len() + 1);
    if significant.first().is_none_or(|&b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(significant);
    tlv(TAG_INTEGER, &content)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPTH: usize = 32;

    #[test]
    fn reads_definite_short_and_long_forms() {
        let short = [0x04, 0x02, 0xAA, 0xBB];
        let el = read_exact(&short, DEPTH).unwrap();
        assert_eq!(el.tag, TAG_OCTET_STRING);
        assert_eq!(el.content(&short), [0xAA, 0xBB]);
        assert!(el.minimal_length && el.is_der_header());

        let mut long = vec![0x04, 0x81, 0x80];
        long.extend([7u8; 128]);
        let el = read_exact(&long, DEPTH).unwrap();
        assert_eq!(el.content(&long).len(), 128);
        assert!(el.minimal_length);

        // Non-minimal: a short length in long form, and a leading zero length octet.
        let lax = [0x04, 0x81, 0x01, 0xAA];
        let el = read_exact(&lax, DEPTH).unwrap();
        assert!(!el.minimal_length && !el.is_der_header());
        let lax = [0x04, 0x82, 0x00, 0x01, 0xAA];
        assert!(!read_exact(&lax, DEPTH).unwrap().minimal_length);
    }

    #[test]
    fn reads_indefinite_lengths() {
        // SEQUENCE (indefinite) { OCTET STRING 'A', SEQUENCE (indefinite) { NULL } } EOC
        let ber = [
            0x30, 0x80, 0x04, 0x01, b'A', 0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let el = read_exact(&ber, DEPTH).unwrap();
        assert!(el.indefinite && !el.is_der_header());
        assert_eq!(el.content_end, 11);
        assert_eq!(el.end, ber.len());
        let kids: Vec<Element> = children(&ber, &el, 0, DEPTH)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].content(&ber), b"A");
        assert!(kids[1].indefinite);
        assert_eq!(kids[1].raw(&ber), [0x30, 0x80, 0x05, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn rejects_malformed_input_without_panicking() {
        let cases: &[&[u8]] = &[
            &[],
            &[0x30],
            &[0x30, 0x05, 0x00],
            &[0x04, 0x80, 0x00, 0x00], // indefinite primitive
            &[0x30, 0x80, 0x05, 0x00], // missing EOC
            &[0x30, 0xFF],             // reserved length
            &[0x30, 0x89, 1, 1, 1, 1, 1, 1, 1, 1, 1], // 9 length octets
            &[0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00], // tag number too large
            &[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF], // length past the end
        ];
        for case in cases {
            assert!(read_exact(case, DEPTH).is_err(), "{case:02x?}");
        }
        assert!(
            read_exact(&[0x04, 0x00, 0x00], DEPTH).is_err(),
            "trailing bytes"
        );
    }

    #[test]
    fn depth_is_limited() {
        let mut nested = Vec::new();
        for _ in 0..40 {
            nested.extend([0x30, 0x80]);
        }
        nested.extend([0x00; 80]);
        assert_eq!(read_exact(&nested, DEPTH), Err(TlvError::TooDeep));
        assert!(read_exact(&nested, 64).is_ok());
    }

    #[test]
    fn constructed_octet_strings_are_joined() {
        let ber = [0x24, 0x80, 0x04, 0x02, 1, 2, 0x04, 0x01, 3, 0x00, 0x00];
        let el = read_exact(&ber, DEPTH).unwrap();
        assert_eq!(octet_string_value(&ber, &el, 0, DEPTH).unwrap(), [1, 2, 3]);
    }

    #[test]
    fn der_tree_checks_order_and_lengths() {
        let sorted = [0x31, 0x06, 0x04, 0x01, 0x01, 0x04, 0x01, 0x02];
        let unsorted = [0x31, 0x06, 0x04, 0x01, 0x02, 0x04, 0x01, 0x01];
        let check = |b: &[u8]| is_der_tree(b, &read_exact(b, DEPTH).unwrap(), 0, DEPTH);
        assert!(check(&sorted));
        assert!(!check(&unsorted));
        // SEQUENCE order is free.
        let mut seq = unsorted;
        seq[0] = TAG_SEQUENCE;
        assert!(check(&seq));
        assert!(!check(&[0x30, 0x81, 0x03, 0x04, 0x01, 0x01]));
        assert!(!check(&[0x24, 0x03, 0x04, 0x01, 0x01]));
    }

    #[test]
    fn der_contents_of_booleans_and_bit_strings() {
        let check = |b: &[u8]| der_primitive_contents(b, &read_exact(b, DEPTH).unwrap(), 0, DEPTH);
        // BOOLEAN TRUE is FF and FALSE 00 (X.690 §11.1), at any depth.
        assert!(check(&[0x01, 0x01, 0xFF]));
        assert!(check(&[0x01, 0x01, 0x00]));
        assert!(!check(&[0x01, 0x01, 0x01]));
        assert!(!check(&[0x30, 0x05, 0x31, 0x03, 0x01, 0x01, 0x01]));
        assert!(check(&[0x30, 0x05, 0x31, 0x03, 0x01, 0x01, 0xFF]));
        // BIT STRING: unused bits zero (§11.2.1), none when empty (§8.6.2.3).
        assert!(check(&[0x03, 0x01, 0x00]));
        assert!(check(&[0x03, 0x02, 0x00, 0xFF]));
        assert!(check(&[0x03, 0x02, 0x04, 0xF0]));
        assert!(!check(&[0x03, 0x02, 0x04, 0xF8]));
        assert!(check(&[0x03, 0x02, 0x07, 0x80]));
        assert!(!check(&[0x03, 0x02, 0x07, 0x81]));
        assert!(!check(&[0x03, 0x01, 0x03]));
        assert!(!check(&[0x03, 0x02, 0x08, 0x00]));
        assert!(!check(&[0x03, 0x00]));
        // Not universal: not looked into.
        assert!(check(&[0x81, 0x01, 0x01]));
        // A child that does not parse fails.
        assert!(!check(&[0x30, 0x02, 0x01, 0x05]));
    }

    #[test]
    fn primitives_are_checked_as_openssl_decodes_them() {
        let check = |b: &[u8]| check_primitives(b, &read_exact(b, DEPTH).unwrap(), 0, DEPTH);
        // A SEQUENCE of valid primitives, BER constructed string and indefinite length.
        let good = [
            0x30, 0x80, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01,
            0xFF, 0x05, 0x00, 0x06, 0x03, 0x2A, 0x86, 0x48, 0x03, 0x02, 0x07, 0x80, 0x24, 0x80,
            0x04, 0x01, 0x01, 0x00, 0x00, 0xA0, 0x02, 0x80, 0x00, 0x00, 0x00,
        ];
        assert_eq!(check(&good), Ok(()));
        for (bad, why) in [
            (&[0x30, 0x04, 0x01, 0x02, 0xFF, 0xFF][..], "boolean"),
            (&[0x30, 0x02, 0x02, 0x00][..], "empty integer"),
            (&[0x30, 0x04, 0x02, 0x02, 0x00, 0x01][..], "padded integer"),
            (&[0x30, 0x04, 0x02, 0x02, 0xFF, 0x80][..], "padded negative"),
            (
                &[0x30, 0x04, 0x0A, 0x02, 0x00, 0x05][..],
                "padded enumerated",
            ),
            (&[0x30, 0x03, 0x05, 0x01, 0x00][..], "null with content"),
            (&[0x30, 0x02, 0x06, 0x00][..], "empty oid"),
            (
                &[0x30, 0x04, 0x06, 0x02, 0x2A, 0x86][..],
                "oid open subidentifier",
            ),
            (&[0x30, 0x05, 0x06, 0x03, 0x2A, 0x80, 0x01][..], "oid 0x80"),
            (&[0x30, 0x02, 0x03, 0x00][..], "empty bit string"),
            (&[0x30, 0x03, 0x03, 0x01, 0x08][..], "unused bits"),
            (&[0x30, 0x02, 0x00, 0x00][..], "end of contents"),
            (&[0x30, 0x03, 0x1E, 0x01, 0x41][..], "odd bmp"),
            (&[0x30, 0x04, 0x0C, 0x02, 0xC3, 0x28][..], "invalid utf-8"),
            (
                &[0x30, 0x05, 0x0C, 0x03, 0xED, 0xA0, 0x80][..],
                "utf-8 surrogate",
            ),
            (&[0x30, 0x04, 0x17, 0x02, 0x32, 0x36][..], "short utc time"),
            (&[0x30, 0x02, 0x10, 0x00][..], "primitive sequence"),
            (
                &[0x30, 0x05, 0x22, 0x03, 0x02, 0x01, 0x01][..],
                "constructed integer",
            ),
            (
                &[0x30, 0x05, 0x24, 0x03, 0x02, 0x01, 0x01][..],
                "segment type",
            ),
        ] {
            assert!(check(bad).is_err(), "{why}: {bad:02x?}");
        }
        // M4 QA round 4 finding 1: BMPString and UniversalString values OpenSSL cannot convert.
        for (bad, why) in [
            (
                &[0x30, 0x04, 0x1E, 0x02, 0xD8, 0x00][..],
                "bmp lone high surrogate",
            ),
            (&[0x30, 0x04, 0x1E, 0x02, 0xDB, 0xFF][..], "bmp DBFF"),
            (
                &[0x30, 0x04, 0x1E, 0x02, 0xDC, 0x00][..],
                "bmp lone low surrogate",
            ),
            (&[0x30, 0x04, 0x1E, 0x02, 0xDF, 0xFF][..], "bmp DFFF"),
            (
                &[0x30, 0x06, 0x1E, 0x04, 0xD8, 0x3D, 0xDE, 0x00][..],
                "bmp surrogate pair",
            ),
            (
                &[0x30, 0x06, 0x1E, 0x04, 0xDC, 0x00, 0xD8, 0x00][..],
                "bmp low surrogate first",
            ),
            (
                &[0x30, 0x06, 0x1C, 0x04, 0x00, 0x00, 0xD8, 0x00][..],
                "ucs-4 surrogate",
            ),
            (
                &[0x30, 0x06, 0x1C, 0x04, 0x00, 0x11, 0x00, 0x00][..],
                "ucs-4 above 10FFFF",
            ),
            (
                &[0x30, 0x05, 0x1C, 0x03, 0x00, 0x00, 0x41][..],
                "ucs-4 length",
            ),
        ] {
            assert!(check(bad).is_err(), "{why}: {bad:02x?}");
        }
        let message = check(&[0x30, 0x04, 0x1E, 0x02, 0xD8, 0x00]).unwrap_err();
        assert!(message.contains("surrogate"), "{message}");
        // Non-characters, NUL, the last BMP and the last Unicode code point convert.
        for good in [
            &[0x30, 0x04, 0x1E, 0x02, 0xFF, 0xFE][..],
            &[0x30, 0x04, 0x1E, 0x02, 0x00, 0x00],
            &[0x30, 0x04, 0x1E, 0x02, 0xD7, 0xFF],
            &[0x30, 0x04, 0x1E, 0x02, 0xE0, 0x00],
            &[0x30, 0x06, 0x1C, 0x04, 0x00, 0x10, 0xFF, 0xFF],
            &[0x30, 0x06, 0x1C, 0x04, 0x00, 0x01, 0xF6, 0x00],
            &[0x30, 0x05, 0x0C, 0x03, 0xEF, 0xBF, 0xBE],
            &[0x30, 0x02, 0x1E, 0x00],
        ] {
            assert_eq!(check(good), Ok(()), "{good:02x?}");
        }
        assert!(string_converts(0x13, &[0xFF]) && string_converts(0x14, &[0xD8, 0x00]));
        // Implicitly tagged primitives and OCTET STRING contents are not looked into.
        assert_eq!(check(&[0x30, 0x04, 0x80, 0x00, 0x04, 0x00]), Ok(()));
        assert_eq!(check(&[0x30, 0x04, 0x04, 0x02, 0x02, 0x00]), Ok(()));
        assert!(valid_oid(&[0x2A]) && valid_oid(&[0x2A, 0x86, 0x48]));
        assert!(!valid_oid(&[0x80, 0x01]) && !valid_oid(&[0x86]));
    }

    #[test]
    fn set_order_pads_with_zeros() {
        use std::cmp::Ordering::*;
        assert_eq!(der_set_order(&[1, 2], &[1, 2, 0]), Equal);
        assert_eq!(der_set_order(&[1, 2], &[1, 3]), Less);
        assert_eq!(der_set_order(&[0x30, 0x3F], &[0x30, 0x39]), Greater);
    }

    #[test]
    fn integers() {
        assert_eq!(unsigned_integer(&[0x00, 0x00, 0x7F]), [0x02, 0x01, 0x7F]);
        assert_eq!(unsigned_integer(&[0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(unsigned_integer(&[]), [0x02, 0x01, 0x00]);
        assert_eq!(unsigned_integer(&[0, 0]), [0x02, 0x01, 0x00]);
        assert_eq!(integer_canonical(&[0x00, 0x00, 0x7F]), [0x7F]);
        assert_eq!(integer_canonical(&[0x00, 0x80]), [0x00, 0x80]);
        assert_eq!(integer_canonical(&[0xFF, 0xFF, 0x80]), [0x80]);
        assert_eq!(integer_canonical(&[0x00]), [0x00]);
    }

    #[test]
    fn writer_lengths() {
        for len in [0usize, 1, 127, 128, 255, 256, 65_535, 65_536] {
            let out = tlv(TAG_OCTET_STRING, &vec![0; len]);
            assert_eq!(out.len(), tlv_len(len), "{len}");
            let el = read_exact(&out, DEPTH).unwrap();
            assert!(el.minimal_length, "{len}");
            assert_eq!(el.content(&out).len(), len);
        }
        assert_eq!(
            tlv_parts(TAG_SEQUENCE, &[&[0x05, 0x00], &[0x05, 0x00]]),
            [0x30, 0x04, 0x05, 0x00, 0x05, 0x00]
        );
    }
}
