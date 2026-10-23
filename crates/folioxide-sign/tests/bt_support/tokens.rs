//! Timestamp token variants of QA round 3 (findings 2–5): BER or unsorted encodings of the
//! signed attributes that the mock TSA signs as they are ([`MockTsaOptions::signed_attrs_encoding`]
//! takes these `fn`s), extra signed attributes, ESS `policies` and TSTInfo `extensions`.
//!
//! Every function here takes and returns whole DER (or BER) elements; the input is the mock's
//! DER `SET` of signed attributes, definite lengths only.
//!
//! [`MockTsaOptions::signed_attrs_encoding`]: folioxide_testkit::tsa::MockTsaOptions

/// `(header length, content length)` of the definite-length element at the start of `d`.
fn header(d: &[u8]) -> (usize, usize) {
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
}

/// The content octets of the definite-length element `d`.
fn content(d: &[u8]) -> &[u8] {
    let (h, l) = header(d);
    &d[h..h + l]
}

/// The consecutive definite-length elements of `c`.
fn children(mut c: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while !c.is_empty() {
        let (h, l) = header(c);
        out.push(&c[..h + l]);
        c = &c[h + l..];
    }
    out
}

/// A DER element.
pub fn der(tag: u8, c: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match c.len() {
        n if n < 0x80 => out.push(n as u8),
        n if n < 0x100 => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(c);
    out
}

/// The element `d` with a non-minimal length: one more length octet than DER needs (`81 05`
/// for 5, `82 00 C8` for 200), as QA's `relen(…, 'l1')`.
fn long_form(d: &[u8]) -> Vec<u8> {
    let c = content(d);
    let mut out = vec![d[0]];
    match c.len() {
        n if n < 0x80 => out.extend([0x81, n as u8]),
        n if n < 0x100 => out.extend([0x82, 0x00, n as u8]),
        n => out.extend([0x83, 0x00, (n >> 8) as u8, n as u8]),
    }
    out.extend_from_slice(c);
    out
}

/// The element `d` in the indefinite-length form (`tag 80 … 00 00`).
fn indefinite(d: &[u8]) -> Vec<u8> {
    [&[d[0], 0x80][..], content(d), &[0, 0]].concat()
}

/// An `Attribute` of the OID content octets `oid` with `values`, written in the order given.
pub fn attribute(oid: &[u8], values: &[Vec<u8>]) -> Vec<u8> {
    der(
        0x30,
        &[der(0x06, oid), der(0x31, &values.concat())].concat(),
    )
}

/// content-type (1.2.840.113549.1.9.3).
const CONTENT_TYPE: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
/// message-digest (1.2.840.113549.1.9.4).
const MESSAGE_DIGEST: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
/// signing-time (1.2.840.113549.1.9.5).
pub const SIGNING_TIME: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05];
/// signing-certificate-v2 (1.2.840.113549.1.9.16.2.47).
const SIGNING_CERTIFICATE_V2: [u8; 11] = [
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
];

/// The DER `SET` of signed attributes `set` with `f(attribute)` for every attribute whose type
/// is `oid` (the others unchanged), and its own header from `outer`.
fn map_attributes(
    set: &[u8],
    oid: Option<&[u8]>,
    f: impl Fn(&[u8]) -> Vec<u8>,
    outer: impl Fn(&[u8]) -> Vec<u8>,
) -> Vec<u8> {
    let attributes: Vec<Vec<u8>> = children(content(set))
        .into_iter()
        .map(|a| {
            let attr_type = content(children(content(a))[0]);
            if oid.is_none_or(|oid| oid == attr_type) {
                f(a)
            } else {
                a.to_vec()
            }
        })
        .collect();
    outer(&der(0x31, &attributes.concat()))
}

/// The attribute `a` with `f` applied to its type (the OID element).
fn map_type(a: &[u8], f: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let parts = children(content(a));
    der(0x30, &[f(parts[0]), parts[1].to_vec()].concat())
}

/// The attribute `a` with `f` applied to its values `SET`.
fn map_values(a: &[u8], f: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let parts = children(content(a));
    der(0x30, &[parts[0].to_vec(), f(parts[1])].concat())
}

fn same(d: &[u8]) -> Vec<u8> {
    d.to_vec()
}

/// `r3-ber-sattr-set-header-longform-4`: the `SET`'s length in four octets.
pub fn set_header_long_form_4(set: &[u8]) -> Vec<u8> {
    let c = content(set);
    let len = u32::try_from(c.len()).unwrap().to_be_bytes();
    [&[0x31, 0x84][..], &len, c].concat()
}

/// `r3-ber-sattr-first-attr-header-longform`: the first attribute's length not minimal.
pub fn first_attribute_long_form(set: &[u8]) -> Vec<u8> {
    let attributes = children(content(set));
    let mut out = long_form(attributes[0]);
    for a in &attributes[1..] {
        out.extend_from_slice(a);
    }
    der(0x31, &out)
}

/// `r3-ber-sattr-all-attrs-indefinite`: every attribute `SEQUENCE` indefinite.
pub fn attributes_indefinite(set: &[u8]) -> Vec<u8> {
    map_attributes(set, None, indefinite, same)
}

/// `r3-ber-sattr-ess-attr-indefinite`: the signing-certificate-v2 attribute indefinite.
pub fn ess_attribute_indefinite(set: &[u8]) -> Vec<u8> {
    map_attributes(set, Some(&SIGNING_CERTIFICATE_V2), indefinite, same)
}

/// `r3-ber-sattr-md-oid-longform`: the message-digest attribute's type OID length not minimal.
pub fn message_digest_type_long_form(set: &[u8]) -> Vec<u8> {
    map_attributes(set, Some(&MESSAGE_DIGEST), |a| map_type(a, long_form), same)
}

/// `r3-ber-sattr-md-set-longform`: the message-digest attribute's values `SET` length not
/// minimal.
pub fn message_digest_values_long_form(set: &[u8]) -> Vec<u8> {
    map_attributes(
        set,
        Some(&MESSAGE_DIGEST),
        |a| map_values(a, long_form),
        same,
    )
}

/// `r3-ber-sattr-ct-value-oid-longform`: the content-type value (an OID) length not minimal.
pub fn content_type_value_long_form(set: &[u8]) -> Vec<u8> {
    map_attributes(
        set,
        Some(&CONTENT_TYPE),
        |a| map_values(a, |values| der(0x31, &long_form(content(values)))),
        same,
    )
}

/// The attributes in reverse DER order (each one still DER): OpenSSL keeps the order it
/// received when it re-encodes, so it accepts this; BouncyCastle sorts, and RFC 5652 §5.4 signs
/// the DER encoding, which is sorted (X.690 §11.6).
pub fn attributes_reversed(set: &[u8]) -> Vec<u8> {
    let mut attributes = children(content(set));
    attributes.reverse();
    der(0x31, &attributes.concat())
}

/// A UTCTime value of signing-time.
pub fn utc_time(text: &str) -> Vec<u8> {
    der(0x17, text.as_bytes())
}

/// An attribute of `oid` with `values` in **reverse** DER order (QA's `extra_attr(…, True)`):
/// `r3-attr-*-unsorted-values`.
pub fn unsorted_attribute(oid: &[u8], values: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.reverse();
    attribute(oid, &sorted)
}

/// An attribute of `oid` with `values` in DER order.
pub fn sorted_attribute(oid: &[u8], values: &[Vec<u8>]) -> Vec<u8> {
    let mut sorted = values.to_vec();
    sorted.sort();
    attribute(oid, &sorted)
}

/// An OID's content octets in a test arc (1.2.3.4.`last`).
pub fn test_oid(last: u8) -> Vec<u8> {
    vec![0x2A, 0x03, 0x04, last]
}

/// `SEQUENCE { e… }`.
pub fn seq(elements: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &elements.concat())
}

/// An INTEGER with the content octet `v`.
pub fn int(v: u8) -> Vec<u8> {
    der(0x02, &[v])
}

/// An OCTET STRING.
pub fn octets(c: &[u8]) -> Vec<u8> {
    der(0x04, c)
}

/// An OBJECT IDENTIFIER element of the content octets `c`.
pub fn oid(c: &[u8]) -> Vec<u8> {
    der(0x06, c)
}

/// `policies` holding one well-formed `PolicyInformation { 1.2.3.4.1 }` (QA's `POL_OK`).
pub fn policies_valid() -> Vec<u8> {
    seq(&[seq(&[oid(&test_oid(1))])])
}

/// `id-qt-cps` (1.3.6.1.5.5.7.2.1) as content octets.
pub const ID_QT_CPS: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01];
/// `id-qt-unotice` (1.3.6.1.5.5.7.2.2) as content octets.
pub const ID_QT_UNOTICE: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02];

/// `policies` with one `PolicyInformation` whose one qualifier is `(id, value)`.
pub fn policies_with_qualifier(id: &[u8], value: Vec<u8>) -> Vec<u8> {
    seq(&[seq(&[oid(&test_oid(1)), seq(&[seq(&[oid(id), value])])])])
}

/// `extensions [1]` holding `extensions` (whole `Extension`s, or whatever a test puts there).
pub fn tst_extensions(extensions: &[Vec<u8>]) -> Vec<u8> {
    der(0xA1, &extensions.concat())
}

/// A well-formed non-critical `Extension { 1.2.3.4.`last`, OCTET STRING { NULL } }`.
pub fn extension(last: u8) -> Vec<u8> {
    seq(&[oid(&test_oid(last)), octets(&[0x05, 0x00])])
}
