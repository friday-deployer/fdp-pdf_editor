//! XMP packets in the revisions after a signature (M4 brief §5 V10; M4 QA round 1, findings R4).
//!
//! pyHanko's `MetadataUpdateRule` accepts a changed `/Metadata` stream only when it parses with
//! lxml (`etree.fromstring`, entities not resolved) as XML whose root is
//! `{adobe:ns:meta/}xmpmeta`. Folioxide must not be more lenient (DECISIONS D10.1), so
//! [`scan`] is a real, namespace-aware XML 1.0 well-formedness check (XML 1.0 fifth edition,
//! Namespaces in XML 1.0), in **one linear pass** with bounded depth and attribute counts:
//!
//! - only legal characters (XML §2.2 `Char`), UTF-8;
//! - start tags `<Name (S Name Eq AttValue)* S? /?>` with quoted values that hold no `<`, no
//!   duplicate attribute (by name, and by namespace and local name), at most
//!   [`MAX_XML_ATTRIBUTES`] of them; end tags that match; at most [`MAX_XML_DEPTH`] levels;
//!   names of at most [`MAX_XML_NAME`] bytes (libxml2's limit; the packet itself is shorter
//!   than libxml2's 10,000,000-byte limit on one node, `MAX_XMP_BYTES`, M4 QA round 3);
//! - references only `&lt; &gt; &amp; &quot; &apos;` and character references to legal
//!   characters (no entity is declared: a document type declaration is refused, as pyHanko's
//!   `resolve_entities=False` parse cannot use one either);
//! - comments without `--`, processing instructions whose target is a name and not `xml` in any
//!   case, except the XML declaration (`version="1.0"`, optionally `encoding="UTF-8"` and
//!   `standalone` `yes` or `no`, §2.8) at the very start; CDATA sections only inside the root,
//!   no `]]>` in text, and nothing but white-space, comments and processing instructions outside
//!   the single root;
//! - character references with decimal or hexadecimal digits only (no sign, QA round 2);
//! - every prefix declared (`xmlns:p`, never to an empty value), every namespace name an RFC
//!   3986 URI-reference written without references, the reserved `xml` and `xmlns` bindings as
//!   Namespaces in XML 1.0 §3 has them (QA round 2, findings 18–20, from a differential fuzz
//!   against lxml), the root `xmpmeta` in the `adobe:ns:meta/` namespace.
//!
//! Where lxml accepts more (an XML declaration of version 1.1 or of another encoding, an
//! IP-literal host in a namespace name), Folioxide refuses: a stricter verdict only.
//!
//! The same pass writes the packet with the values of the document timestamp's bookkeeping
//! attributes emptied ([`XMP_BOOKKEEPING`]), so two packets compare equal when they differ only
//! there; the old masker rescanned every attribute for each one (QA finding: quadratic).

use std::collections::{HashMap, HashSet};

/// The deepest element nesting [`scan`] follows; a deeper packet is not XMP.
pub(super) const MAX_XML_DEPTH: usize = 256;

/// The most attributes one start tag may have; a tag with more is not XMP (stricter than lxml,
/// which has no such limit, and a bound on a hostile packet's work).
pub(super) const MAX_XML_ATTRIBUTES: usize = 1024;

/// The longest name (an element or attribute name, prefix included, or a processing
/// instruction's target) a packet may use: libxml2's `XML_MAX_NAME_LENGTH`, which lxml applies
/// without `huge_tree` (pyHanko parses `/Metadata` so; M4 QA round 3, finding 19: a 50,001-byte
/// name is "Name too long" there). libxml2 bounds each part of a qualified name, Folioxide the
/// whole name (stricter).
pub(super) const MAX_XML_NAME: usize = 50_000;

/// The XMP properties whose values a document timestamp's revision may rewrite (M4 brief §5
/// V10, class `DocTimeStamp`): `(namespace, local name)`. pyHanko's timestamper writes
/// `xmp:ModifyDate` and `pdf:Producer` as attributes of an `rdf:Description` that declares both
/// prefixes itself (`xmp_xml.py` `_populate_xmp_with_meta`); an attribute is masked only when
/// the start tag that carries it also binds its prefix to the namespace.
pub(super) const XMP_BOOKKEEPING: &[(&str, &str)] = &[
    ("http://ns.adobe.com/xap/1.0/", "ModifyDate"),
    ("http://ns.adobe.com/pdf/1.3/", "Producer"),
];

/// The namespace of the `xmpmeta` root (ISO 16684-1 §7.3).
const XMPMETA_NAMESPACE: &str = "adobe:ns:meta/";

/// The namespace the `xml` prefix is bound to (Namespaces in XML 1.0 §3).
const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";

/// Whether `data` is a well-formed XMP packet ([`scan`]).
pub(super) fn looks_like_xmp(data: &[u8]) -> bool {
    scan(data).is_some()
}

/// `data` (an XMP packet) with the values of its [`XMP_BOOKKEEPING`] attributes emptied; `None`
/// when `data` is not a well-formed XMP packet ([`scan`]).
pub(super) fn xmp_without_bookkeeping(data: &[u8]) -> Option<String> {
    scan(data)
}

/// Whether `c` is an XML `Char` (§2.2).
fn is_char(c: char) -> bool {
    matches!(c, '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}')
        || c >= '\u{10000}'
}

/// Whether `c` is white-space (`S`, §2.3).
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

/// Whether `c` may start a name (`NameStartChar`, §2.3; the colon is handled by the namespace
/// rules, which allow it only as the prefix separator).
fn is_name_start(c: char) -> bool {
    matches!(c,
        'A'..='Z' | '_' | 'a'..='z' | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}'
        | '\u{F8}'..='\u{2FF}' | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}'
        | '\u{200C}'..='\u{200D}' | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}'
        | '\u{3001}'..='\u{D7FF}' | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}'
        | '\u{10000}'..='\u{EFFFF}')
}

/// Whether `c` may continue a name (`NameChar`, §2.3, without the colon).
fn is_name_char(c: char) -> bool {
    is_name_start(c)
        || matches!(c, '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}

/// Whether `name` is an `NCName` (a name without a colon, Namespaces in XML §3).
fn is_ncname(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(is_name_start) && chars.all(is_name_char)
}

/// A qualified name split into its prefix (`""` for none) and local part; `None` unless it is
/// `NCName` or `NCName:NCName`.
fn split_qname(name: &str) -> Option<(&str, &str)> {
    match name.split_once(':') {
        Some((prefix, local)) => (is_ncname(prefix) && is_ncname(local)).then_some((prefix, local)),
        None => is_ncname(name).then_some(("", name)),
    }
}

/// The length of the name at the start of `text` (name characters and colons), 0 when there is
/// none.
fn name_len(text: &str) -> usize {
    text.char_indices()
        .find(|&(_, c)| !(is_name_char(c) || c == ':'))
        .map_or(text.len(), |(i, _)| i)
}

/// Whether the references (`&…;`) of `text` (character data or an attribute value) are all
/// predefined entities or character references to legal characters (§4.1, §4.6).
fn references_ok(text: &str) -> bool {
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        let Some(after) = rest.get(at + 1..) else {
            return false;
        };
        let Some(end) = after.find(';') else {
            return false;
        };
        let Some(body) = after.get(..end) else {
            return false;
        };
        let ok = if let Some(hex) = body.strip_prefix("#x") {
            // §4.1 CharRef: '&#x' [0-9a-fA-F]+ ';' (`u32::from_str_radix` also takes a sign:
            // QA round 2, finding 18, `&#x+41;`).
            !hex.is_empty()
                && hex.len() <= 8
                && hex.bytes().all(|b| b.is_ascii_hexdigit())
                && u32::from_str_radix(hex, 16)
                    .ok()
                    .and_then(char::from_u32)
                    .is_some_and(is_char)
        } else if let Some(decimal) = body.strip_prefix('#') {
            !decimal.is_empty()
                && decimal.len() <= 10
                && decimal.bytes().all(|b| b.is_ascii_digit())
                && decimal
                    .parse::<u32>()
                    .ok()
                    .and_then(char::from_u32)
                    .is_some_and(is_char)
        } else {
            matches!(body, "lt" | "gt" | "amp" | "quot" | "apos")
        };
        if !ok {
            return false;
        }
        rest = after.get(end + 1..).unwrap_or_default();
    }
    true
}

/// Whether `body` (what follows `<?xml` up to `?>`) is an XML declaration (XML 1.0 §2.8
/// `XMLDecl`): `S version Eq "1.0"`, then optionally `S encoding Eq "UTF-8"` (the packet is
/// read as UTF-8; any case) and `S standalone Eq ("yes" | "no")`, in that order, then optional
/// white-space; `Eq` is `S? = S?` and a value is in single or double quotes. Stricter than
/// lxml where it accepts more (a version `1.x` other than `1.0`, another encoding name).
fn is_xml_declaration(body: &str) -> bool {
    let mut rest = body;
    let pseudo = |name: &str, rest: &mut &str| -> Option<String> {
        let spaces = rest.bytes().take_while(|&b| is_space(b)).count();
        let after = rest.get(spaces..)?.strip_prefix(name)?;
        if spaces == 0 {
            return None;
        }
        let after = after.trim_start_matches(|c: char| c.is_ascii() && is_space(c as u8));
        let after = after.strip_prefix('=')?;
        let after = after.trim_start_matches(|c: char| c.is_ascii() && is_space(c as u8));
        let quote = after.chars().next().filter(|&q| q == '"' || q == '\'')?;
        let inner = after.get(1..)?;
        let close = inner.find(quote)?;
        let value = inner.get(..close)?.to_owned();
        *rest = inner.get(close + 1..)?;
        Some(value)
    };
    if pseudo("version", &mut rest).as_deref() != Some("1.0") {
        return false;
    }
    let mut probe = rest;
    if let Some(encoding) = pseudo("encoding", &mut probe) {
        if !encoding.eq_ignore_ascii_case("UTF-8") {
            return false;
        }
        rest = probe;
    }
    let mut probe = rest;
    if let Some(standalone) = pseudo("standalone", &mut probe) {
        if standalone != "yes" && standalone != "no" {
            return false;
        }
        rest = probe;
    }
    rest.bytes().all(is_space)
}

/// Whether `value` is an RFC 3986 URI-reference (§4.1: a URI with a scheme, or a relative
/// reference), as libxml2 (lxml, which pyHanko's `MetadataUpdateRule` uses) requires of a
/// namespace name (QA round 2, finding 20): ASCII only; percent signs only as `%` and two
/// hexadecimal digits; at most one `#` (the fragment); only the characters each part allows
/// (no white-space, control characters or `<>"\^`{|}`); a scheme `ALPHA *( ALPHA / DIGIT /
/// "+" / "-" / "." )`; an authority `[userinfo "@"] host [":" port]` with a port of one to
/// five digits (libxml2 refuses an empty port). Stricter than RFC 3986 and libxml2 in one more
/// point: an IP-literal host (`[…]`) is refused.
fn is_uri_reference(value: &str) -> bool {
    /// `unreserved / pct-encoded / sub-delims` and the bytes of `extra`.
    fn chars_ok(text: &str, extra: &[u8]) -> bool {
        let bytes = text.as_bytes();
        let mut i = 0;
        while let Some(&b) = bytes.get(i) {
            if b == b'%' {
                let hex = |at: usize| bytes.get(at).is_some_and(u8::is_ascii_hexdigit);
                if !(hex(i + 1) && hex(i + 2)) {
                    return false;
                }
                i += 3;
                continue;
            }
            let ok =
                b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&b) || extra.contains(&b);
            if !ok {
                return false;
            }
            i += 1;
        }
        true
    }
    const PCHAR: &[u8] = b":@";
    const QUERY: &[u8] = b":@/?";
    if !value.is_ascii() {
        return false;
    }
    let (rest, fragment) = match value.split_once('#') {
        Some((rest, fragment)) => (rest, Some(fragment)),
        None => (value, None),
    };
    if fragment.is_some_and(|f| !chars_ok(f, QUERY)) {
        return false;
    }
    let (rest, query) = match rest.split_once('?') {
        Some((rest, query)) => (rest, Some(query)),
        None => (rest, None),
    };
    if query.is_some_and(|q| !chars_ok(q, QUERY)) {
        return false;
    }
    // A ':' before any '/' ends a scheme; a relative reference's first segment has none.
    let first_slash = rest.find('/').unwrap_or(rest.len());
    let hier = match rest.find(':') {
        Some(colon) if colon < first_slash => {
            let scheme = rest.get(..colon).unwrap_or_default();
            let mut chars = scheme.bytes();
            let scheme_ok = chars.next().is_some_and(|b| b.is_ascii_alphabetic())
                && chars.all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b));
            if !scheme_ok {
                return false;
            }
            rest.get(colon + 1..).unwrap_or_default()
        }
        _ => rest,
    };
    let path = match hier.strip_prefix("//") {
        Some(after) => {
            let end = after.find('/').unwrap_or(after.len());
            let (authority, path) = after.split_at(end);
            let host_port = match authority.split_once('@') {
                Some((userinfo, host_port)) => {
                    if !chars_ok(userinfo, b":") {
                        return false;
                    }
                    host_port
                }
                None => authority,
            };
            let (host, port) = match host_port.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (host_port, None),
            };
            // libxml2 wants at least one digit after the ':' (RFC 3986 allows none) and a
            // port that fits its integer: at most five digits here.
            let port_ok = |port: &str| {
                (1..=5).contains(&port.len()) && port.bytes().all(|b| b.is_ascii_digit())
            };
            if !chars_ok(host, b"") || port.is_some_and(|p| !port_ok(p)) {
                return false;
            }
            path
        }
        None => hier,
    };
    path.split('/').all(|segment| chars_ok(segment, PCHAR))
}

/// The namespace name of the `xmlns` prefix (Namespaces in XML 1.0 §3): no prefix may be bound
/// to it, nor the default namespace.
const XMLNS_NAMESPACE: &str = "http://www.w3.org/2000/xmlns/";

/// The prefixes in scope: for each prefix (`""` the default namespace), its bindings, innermost
/// last; and for each open element, the prefixes it declared (to unbind them at its end tag).
#[derive(Default)]
struct Scopes<'a> {
    bindings: HashMap<&'a str, Vec<&'a str>>,
    frames: Vec<Vec<&'a str>>,
}

impl<'a> Scopes<'a> {
    fn resolve(&self, prefix: &str) -> Option<&'a str> {
        if prefix == "xml" {
            return Some(XML_NAMESPACE);
        }
        self.bindings.get(prefix).and_then(|b| b.last()).copied()
    }

    fn push(&mut self, declared: Vec<(&'a str, &'a str)>) {
        let mut frame = Vec::with_capacity(declared.len());
        for (prefix, uri) in declared {
            self.bindings.entry(prefix).or_default().push(uri);
            frame.push(prefix);
        }
        self.frames.push(frame);
    }

    fn pop(&mut self) {
        for prefix in self.frames.pop().unwrap_or_default() {
            if let Some(stack) = self.bindings.get_mut(prefix) {
                stack.pop();
            }
        }
    }
}

/// One attribute of a start tag: its qualified name and its value's range in the packet.
struct Attribute<'a> {
    name: &'a str,
    value: std::ops::Range<usize>,
}

/// Checks that `data` is a well-formed XMP packet (see the module documentation) and returns it
/// with the values of its [`XMP_BOOKKEEPING`] attributes emptied; `None` when it is not one.
/// One pass, linear in the packet.
pub(super) fn scan(data: &[u8]) -> Option<String> {
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    let text = std::str::from_utf8(data).ok()?;
    if !text.chars().all(is_char) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut open: Vec<&str> = Vec::new();
    let mut scopes = Scopes::default();
    let mut root: Option<bool> = None;
    let mut at = 0usize;
    while at < bytes.len() {
        let rest = text.get(at..)?;
        if !rest.starts_with('<') {
            // Character data up to the next markup.
            let end = rest.find('<').map_or(text.len(), |i| at + i);
            let chunk = text.get(at..end)?;
            if open.is_empty() {
                if !chunk.bytes().all(is_space) {
                    return None; // text outside the root element
                }
            } else if chunk.contains("]]>") || !references_ok(chunk) {
                return None;
            }
            out.push_str(chunk);
            at = end;
            continue;
        }
        if let Some(pi) = rest.strip_prefix("<?") {
            let target_len = name_len(pi);
            let target = pi.get(..target_len)?;
            if !is_ncname(target) || target_len > MAX_XML_NAME {
                return None;
            }
            let after_target = pi.get(target_len..)?;
            let end = after_target.find("?>")?;
            // §2.6: a target `xml` in any case is reserved; §2.8: the XML declaration, in
            // lowercase, only at the very start and only in its grammar (QA round 2, finding 19:
            // `<?xml ?>`, version 2.0, standalone="maybe", `<?XML`, which lxml refuses).
            if target.eq_ignore_ascii_case("xml")
                && (target != "xml" || at != 0 || !is_xml_declaration(after_target.get(..end)?))
            {
                return None;
            }
            if end > 0 && !after_target.bytes().next().is_some_and(is_space) {
                return None;
            }
            let total = 2 + target_len + end + 2;
            out.push_str(rest.get(..total)?);
            at += total;
        } else if let Some(comment) = rest.strip_prefix("<!--") {
            let end = comment.find("-->")?;
            let body = comment.get(..end)?;
            // §2.5: no "--" inside, and no "-" before the end.
            if body.contains("--") || body.ends_with('-') {
                return None;
            }
            let total = 4 + end + 3;
            out.push_str(rest.get(..total)?);
            at += total;
        } else if let Some(cdata) = rest.strip_prefix("<![CDATA[") {
            if open.is_empty() {
                return None;
            }
            let total = 9 + cdata.find("]]>")? + 3;
            out.push_str(rest.get(..total)?);
            at += total;
        } else if rest.starts_with("<!") {
            // <!DOCTYPE ...>, <!ENTITY ...>: refused (pyHanko resolves no entity).
            return None;
        } else if let Some(end_tag) = rest.strip_prefix("</") {
            let len = name_len(end_tag);
            let name = end_tag.get(..len)?;
            let after = end_tag.get(len..)?;
            let spaces = after.bytes().take_while(|&b| is_space(b)).count();
            if after.as_bytes().get(spaces) != Some(&b'>') || open.pop() != Some(name) {
                return None;
            }
            scopes.pop();
            let total = 2 + len + spaces + 1;
            out.push_str(rest.get(..total)?);
            at += total;
        } else {
            at = start_tag(text, at, &mut out, &mut open, &mut scopes, &mut root)?;
        }
    }
    (open.is_empty() && root == Some(true)).then_some(out)
}

/// Reads the start tag at `at` of `text` (its `<`), writes it (masked) to `out`, opens its
/// element in `open` and `scopes` unless it is empty, notes the root in `root`, and returns the
/// position after it; `None` when it is not well-formed.
fn start_tag<'a>(
    text: &'a str,
    at: usize,
    out: &mut String,
    open: &mut Vec<&'a str>,
    scopes: &mut Scopes<'a>,
    root: &mut Option<bool>,
) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = at + 1;
    let name_end = i + name_len(text.get(i..)?);
    let name = text.get(i..name_end)?;
    if name.is_empty() || name.len() > MAX_XML_NAME {
        return None;
    }
    i = name_end;
    let mut attributes: Vec<Attribute<'a>> = Vec::new();
    let mut seen: HashSet<&str> = HashSet::new();
    let empty = loop {
        let spaces = bytes.get(i..)?.iter().take_while(|&&b| is_space(b)).count();
        i += spaces;
        match bytes.get(i)? {
            b'>' => {
                i += 1;
                break false;
            }
            b'/' => {
                if bytes.get(i + 1) != Some(&b'>') {
                    return None;
                }
                i += 2;
                break true;
            }
            _ => {}
        }
        // An attribute: after white-space, Name S? = S? 'value' or "value".
        if spaces == 0 {
            return None;
        }
        let len = name_len(text.get(i..)?);
        let attribute = text.get(i..i + len)?;
        if attribute.is_empty() || len > MAX_XML_NAME || attributes.len() >= MAX_XML_ATTRIBUTES {
            return None;
        }
        if !seen.insert(attribute) {
            return None; // §3.1 "Unique Att Spec"
        }
        i += len;
        i += bytes.get(i..)?.iter().take_while(|&&b| is_space(b)).count();
        if bytes.get(i) != Some(&b'=') {
            return None;
        }
        i += 1;
        i += bytes.get(i..)?.iter().take_while(|&&b| is_space(b)).count();
        let quote = *bytes.get(i)?;
        if quote != b'"' && quote != b'\'' {
            return None;
        }
        let start = i + 1;
        let close = start + text.get(start..)?.find(char::from(quote))?;
        let value = text.get(start..close)?;
        if value.contains('<') || !references_ok(value) {
            return None;
        }
        attributes.push(Attribute {
            name: attribute,
            value: start..close,
        });
        i = close + 1;
    };

    // Namespaces: the declarations of this tag, then every prefix resolved.
    // Namespaces in XML 1.0 §3 and QA round 2, finding 20: a namespace name is a URI-reference
    // (written without references, so the raw value is the name), `xmlns` is bound to nothing,
    // `xml` only to its namespace and its namespace to `xml` only, the default namespace to
    // neither reserved name; a prefix is never undeclared (`xmlns:p=""`).
    let mut declared: Vec<(&'a str, &'a str)> = Vec::new();
    for attribute in &attributes {
        let value = text.get(attribute.value.clone())?;
        let reserved = value == XML_NAMESPACE || value == XMLNS_NAMESPACE;
        let uri_ok = !value.contains('&') && is_uri_reference(value);
        if attribute.name == "xmlns" {
            if reserved || !uri_ok {
                return None;
            }
            declared.push(("", value));
        } else if let Some(prefix) = attribute.name.strip_prefix("xmlns:") {
            if !is_ncname(prefix) || prefix == "xmlns" || value.is_empty() || !uri_ok {
                return None;
            }
            if (prefix == "xml") != (value == XML_NAMESPACE) || value == XMLNS_NAMESPACE {
                return None;
            }
            declared.push((prefix, value));
        }
    }
    let own = |prefix: &str| {
        declared
            .iter()
            .rev()
            .find(|(p, _)| *p == prefix)
            .map(|(_, u)| *u)
    };
    let resolve = |prefix: &str| own(prefix).or_else(|| scopes.resolve(prefix));
    let (prefix, local) = split_qname(name)?;
    let namespace = resolve(prefix);
    if !prefix.is_empty() && namespace.is_none() {
        return None; // an undeclared prefix
    }
    if open.is_empty() {
        if root.is_some() {
            return None; // a second root element
        }
        *root = Some(local == "xmpmeta" && namespace == Some(XMPMETA_NAMESPACE));
    }
    let mut expanded: HashSet<(&str, &str)> = HashSet::new();
    let mut masked: Vec<std::ops::Range<usize>> = Vec::new();
    for attribute in &attributes {
        if attribute.name == "xmlns" || attribute.name.starts_with("xmlns:") {
            continue;
        }
        let (prefix, local) = split_qname(attribute.name)?;
        if prefix.is_empty() {
            continue; // no namespace; unique by name already
        }
        let namespace = resolve(prefix)?;
        if !expanded.insert((namespace, local)) {
            return None; // Namespaces §6.3: unique expanded names
        }
        if own(prefix) == Some(namespace) && XMP_BOOKKEEPING.contains(&(namespace, local)) {
            masked.push(attribute.value.clone());
        }
    }
    // The tag, with the bookkeeping values left out (in order: attributes are in order).
    let mut from = at;
    for range in masked {
        out.push_str(text.get(from..range.start)?);
        from = range.end;
    }
    out.push_str(text.get(from..i)?);
    if !empty {
        if open.len() >= MAX_XML_DEPTH {
            return None;
        }
        open.push(name);
        scopes.push(declared);
    }
    Some(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A packet whose root declares `x` and holds `body`.
    fn packet(body: &str) -> String {
        format!("<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">{body}</x:xmpmeta>")
    }

    #[test]
    fn xmp_packets_are_recognised() {
        let packet_text = "\u{feff}<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
            <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"a > b\">\n\
            <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n\
            <!-- a comment with <tags> -->\n\
            <rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\
            <dc:format>application/pdf &amp; more&#x20;&#32;</dc:format><dc:x/><dc:y><![CDATA[<raw>]]></dc:y>\
            </rdf:Description>\n</rdf:RDF>\n</x:xmpmeta>\n                \n\
            <?xpacket end=\"w\"?>";
        assert!(looks_like_xmp(packet_text.as_bytes()));
        assert!(looks_like_xmp(
            b"<?xml version=\"1.0\"?><xmpmeta xmlns = 'adobe:ns:meta/'><a/></xmpmeta>"
        ));
        assert!(looks_like_xmp(
            b"<meta:xmpmeta xmlns:meta=\"adobe:ns:meta/\"/>"
        ));
        for bad in [
            "",
            "not xml",
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">",
            &packet("<a></b>"),
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"></x:xmpmeta><second/>",
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"></x:xmpmeta> text",
            "<x:other xmlns:x=\"adobe:ns:meta/\"/>",
            "<x:xmpmeta xmlns:x=\"http://example.com/\"/>",
            "<x:xmpmeta xmlns:y=\"adobe:ns:meta/\"/>",
            "<!DOCTYPE x [<!ENTITY e \"boom\">]><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><!-- unterminated </x:xmpmeta>",
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\" a=\"unterminated/>",
            // QA variants R4: the XML well-formedness rules lxml applies.
            &packet("<d a=\"1\" a=\"2\"/>"),
            &packet("<d a=\"x<y\"/>"),
            &packet("<d a=\"&bogus;\"/>"),
            &packet("<d a=\"&#0;\"/>"),
            &packet("<d>&#xFFFF;</d>"),
            &packet("<d a/>"),
            &packet("<d a=1/>"),
            &packet("<d a=\"1\"b=\"2\"/>"),
            &packet("<d>&bogus;</d>"),
            &packet("<d>a & b</d>"),
            &packet("<d>]]></d>"),
            &packet("<!-- a -- b -->"),
            &packet("<?xml version=\"1.0\"?>"),
            &packet("<y:d/>"),
            &packet("<d y:a=\"1\"/>"),
            &packet("<d xmlns:p=\"\"/>"),
            &packet("<d xmlns:p=\"u\" xmlns:q=\"u\" p:a=\"1\" q:a=\"2\"/>"),
            &packet("<a:b:c xmlns:a=\"u\"/>"),
            &packet("<d>\u{1}</d>"),
            "<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"><![CDATA[x]]></x:xmpmeta><![CDATA[y]]>",
            // QA round 2, findings 18-20 (variants R4x-*, lxml 6.1.3 / libxml2 2.14.6 refuse
            // each): a signed character reference, an XML declaration outside its grammar, a
            // namespace name that is no URI-reference, the reserved namespace bindings.
            &packet("<d>&#x+41;</d>"),
            &packet("<d a=\"&#x+41;\"/>"),
            &packet("<d>&#X41;</d>"),
            "<?xml ?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            "<?xml version=\"2.0\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            "<?xml version=\"1.0\" standalone=\"maybe\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            "<?XML version=\"1.0\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            "<?Xml version=\"1.0\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            "<?xml version=\"1.0\" foo=\"bar\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            "<?xml version=\"1.0\"encoding=\"UTF-8\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            "<?xml standalone=\"yes\" version=\"1.0\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            " <?xml version=\"1.0\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            &packet("<?xml-stylesheet href=\"a\"?><?XmL x?>"),
            &packet("<d xmlns:p=\"http://ns.adobe.com/xap/1.0/ with space\"/>"),
            &packet("<d xmlns:p=\"http://www.w3.org/2000/xmlns/\"/>"),
            &packet("<d xmlns=\"http://www.w3.org/2000/xmlns/\"/>"),
            &packet("<d xmlns=\"http://www.w3.org/XML/1998/namespace\"/>"),
            &packet("<d xmlns=\"a b\"/>"),
            &packet("<d xmlns:p=\"http://a/&#x20;b\"/>"),
            &packet("<d xmlns:p=\"http://a/&apos;\"/>"),
        ] {
            assert!(!looks_like_xmp(bad.as_bytes()), "{bad}");
        }
        for good in [
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            "<?xml version='1.0' encoding='utf-8' standalone='no' ?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            "<?xml  version = \"1.0\" ?><x:xmpmeta xmlns:x=\"adobe:ns:meta/\"/>",
            &packet("<?xml-stylesheet href=\"a\"?><?xpacket end=\"w\"?>"),
            &packet("<d xmlns:p=\"urn:a:b\" xmlns:q=\"u\" xmlns=\"\"/>"),
            &packet("<d xmlns:p=\"http://u:p@h:80/p?q#f\" xmlns:q=\"http://a%41/\"/>"),
        ] {
            assert!(looks_like_xmp(good.as_bytes()), "{good}");
        }
        assert!(!looks_like_xmp(b"\xFF\xFE<\x00x\x00"));
        // Deep nesting stops at the limit instead of growing without bound.
        let deep = packet(&format!(
            "{}{}",
            "<a>".repeat(MAX_XML_DEPTH + 1),
            "</a>".repeat(MAX_XML_DEPTH + 1)
        ));
        assert!(!looks_like_xmp(deep.as_bytes()));
        // So do the attributes of one tag.
        let many: String = (0..=MAX_XML_ATTRIBUTES)
            .map(|i| format!(" a{i}=\"\""))
            .collect();
        assert!(!looks_like_xmp(packet(&format!("<d{many}/>")).as_bytes()));
        let fine: String = (0..MAX_XML_ATTRIBUTES)
            .map(|i| format!(" a{i}=\"\""))
            .collect();
        assert!(looks_like_xmp(packet(&format!("<d{fine}/>")).as_bytes()));
    }

    #[test]
    fn namespace_names_are_uri_references() {
        // QA round 2, finding 20: what lxml 6.1.3 (libxml2 2.14.6) accepts as a namespace name,
        // probed one by one; `[::1]` is the one it accepts and Folioxide refuses (stricter).
        for (uri, ok) in [
            ("http://ns.adobe.com/xap/1.0/", true),
            ("adobe:ns:meta/", true),
            ("http://www.w3.org/1999/02/22-rdf-syntax-ns#", true),
            ("http://a:80/x", true),
            ("http://a:/x", false),
            ("http://a:999999999999/x", false),
            ("http://[::1]/x", false),
            ("http://a]/x", false),
            ("u", true),
            ("a:b", true),
            ("1a:b", false),
            ("a/b:c", true),
            ("a?b#c", true),
            ("a#b#c", false),
            ("http://a@b@c/", false),
            ("http://a%41/", true),
            ("http://a%4/", false),
            ("mailto:x@y", true),
            ("http://a/b c", false),
            ("http://a/b[c]", false),
            ("http:", true),
            ("http://", true),
            (":", false),
            ("//", true),
            ("urn:a:b", true),
            ("http://a'b/", true),
            ("http://a/#frag/?x", true),
            ("x:y:z", true),
            ("http://u:p@h/p", true),
            ("http://h:1:2/", false),
            ("http://a/b%zz", false),
            ("%41", true),
            ("a%", false),
            ("http://a/\\", false),
            ("http://a/^", false),
            ("http://a/`", false),
            ("http://a/{", false),
            ("http://a/|", false),
            ("http://a/\u{e9}", false),
            ("http://a/\u{7f}", false),
        ] {
            assert_eq!(is_uri_reference(uri), ok, "{uri:?}");
        }
    }

    /// M4 QA round 3, finding 19: lxml (without `huge_tree`) refuses a name longer than 50,000
    /// bytes ("Name too long"); so does the scan, for elements, attributes, prefixes and
    /// processing-instruction targets, and it accepts one of exactly 50,000.
    #[test]
    fn names_are_at_most_libxml2_long() {
        let n = |len: usize| "n".repeat(len);
        for len in [MAX_XML_NAME, MAX_XML_NAME + 1] {
            let ok = len <= MAX_XML_NAME;
            let element = packet(&format!("<{}/>", n(len)));
            let attribute = packet(&format!("<d {}=\"1\"/>", n(len)));
            let pi = packet(&format!("<?{} data?>", n(len)));
            for (what, text) in [("element", element), ("attribute", attribute), ("pi", pi)] {
                assert_eq!(looks_like_xmp(text.as_bytes()), ok, "{what} of {len}");
            }
        }
        // A prefix: its declaration `xmlns:p` is a name too (the whole name is bounded).
        let prefixed = |p: &str| packet(&format!("<d xmlns:{p}=\"http://e/\" {p}:a=\"1\"/>"));
        assert!(looks_like_xmp(prefixed(&n(MAX_XML_NAME - 6)).as_bytes()));
        assert!(!looks_like_xmp(prefixed(&n(MAX_XML_NAME + 1)).as_bytes()));
    }

    #[test]
    fn the_scan_is_linear_in_the_attributes() {
        // QA finding R4-dos: 100,000 repeated attributes in one start tag took 12 s with the old
        // masker (quadratic); a duplicate is refused at once now.
        let attributes = " xmp:ModifyDate=\"2026\"".repeat(100_000);
        let hostile = packet(&format!(
            "<d xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"{attributes}/>"
        ));
        let (result, _) =
            folioxide_testkit::budget::within(std::time::Duration::from_secs(10), move || {
                looks_like_xmp(hostile.as_bytes())
            })
            .expect("linear");
        assert!(!result);
        // A large well-formed packet: 400 tags of 1000 distinct attributes each (quadratic per
        // tag, the old masker needed minutes for it).
        let attrs: String = (0..MAX_XML_ATTRIBUTES - 24)
            .map(|a| format!(" xmp:a{a}=\"x\""))
            .collect();
        let tag = format!("<d xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"{attrs}/>");
        let large = packet(&tag.repeat(400));
        let (result, _) =
            folioxide_testkit::budget::within(std::time::Duration::from_secs(30), move || {
                xmp_without_bookkeeping(large.as_bytes()).map(|m| m.len())
            })
            .expect("linear");
        assert!(result.is_some());
    }

    #[test]
    fn xmp_bookkeeping_is_only_modify_date_and_producer() {
        // pyHanko's packets before and after its document timestamp (pyhanko-certified-p1-dts).
        let packet_with = |date: &str, extra: &str| {
            format!(
                "<?xpacket begin=\"\u{feff}\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
                 <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"pyHanko 0.37.0\">\n\
                 <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n\
                 <rdf:Description xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\" \
                 xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\" \
                 xmlns:dc=\"http://purl.org/dc/elements/1.1/\" \
                 xmp:ModifyDate=\"{date}\" pdf:Producer=\"pyHanko 0.37.0\"{extra} rdf:about=\"\"/>\n\
                 </rdf:RDF>\n</x:xmpmeta>\n<?xpacket end=\"r\"?>\n"
            )
        };
        let masked = |text: &str| xmp_without_bookkeeping(text.as_bytes());
        let before = packet_with("2026-10-10T18:36:28+00:00", "");
        let after = packet_with("2026-10-11T05:25:27+00:00", "");
        assert!(looks_like_xmp(before.as_bytes()) && looks_like_xmp(after.as_bytes()));
        assert_ne!(before, after);
        assert_eq!(masked(&before), masked(&after));
        assert!(masked(&before).unwrap().contains("xmp:ModifyDate=\"\""));
        // Any other property is not bookkeeping.
        let titled = packet_with("2026-10-11T05:25:27+00:00", " dc:title=\"Paid\"");
        assert!(masked(&titled).is_some());
        assert_ne!(masked(&before), masked(&titled));
        let other_producer = before.replace("pdf:Producer=\"pyHanko 0.37.0\"", "pdf:Producer='x'");
        assert_ne!(
            masked(&before),
            masked(&other_producer),
            "the quotes are kept"
        );
        // A masked value must still be well-formed (QA variants R4-value-*).
        for value in ["a<b", "&bogus;", "&#0;"] {
            assert_eq!(masked(&packet_with(value, "")), None, "{value}");
        }
        // The prefix must be bound to the namespace on the same start tag.
        let elsewhere = |date: &str| {
            packet(&format!(
                "<d xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"><e xmp:ModifyDate=\"{date}\"/></d>"
            ))
        };
        assert_ne!(masked(&elsewhere("1")), masked(&elsewhere("2")));
        assert!(masked(&elsewhere("1")).is_some());
        let rebound = |date: &str| {
            packet(&format!(
                "<d xmlns:xmp=\"http://example.com/\" xmp:ModifyDate=\"{date}\"/>"
            ))
        };
        assert_ne!(masked(&rebound("1")), masked(&rebound("2")));
        let ok = |date: &str| {
            packet(&format!(
                "<d xmlns:xmp = 'http://ns.adobe.com/xap/1.0/' xmp:ModifyDate = '{date}' />"
            ))
        };
        assert_eq!(masked(&ok("1")), masked(&ok("2")));
        // Text, comments and CDATA are never masked.
        for wrap in [
            "<!-- <d xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmp:ModifyDate=\"{}\"/> -->",
            "<d><![CDATA[<d xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmp:ModifyDate=\"{}\"/>]]></d>",
            "<d>xmp:ModifyDate=\"{}\"</d>",
        ] {
            let a = packet(&wrap.replace("{}", "1"));
            let b = packet(&wrap.replace("{}", "2"));
            assert!(masked(&a).is_some(), "{wrap}");
            assert_ne!(masked(&a), masked(&b), "{wrap}");
        }
        // Markup that is not understood is never masked.
        for bad in ["<d a=1/>", "<d a=\"1/>", "<d =\"1\"/>", "<d a\"1\"/>"] {
            assert_eq!(masked(&packet(bad)), None, "{bad}");
        }
        assert_eq!(xmp_without_bookkeeping(b"\xFF"), None);
    }
}
