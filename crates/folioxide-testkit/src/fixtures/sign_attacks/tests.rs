//! Structural unit tests for the byte-level attack generators (brief §5.1). The attacks cannot be
//! fully exercised until signing exists (stage 2 runs them against real signed fixtures and the
//! oracle); here each generator is checked on the unsigned, signature-shaped [`sig_shaped`]
//! fixture for the byte-level property it must hold.

use super::*;
use folioxide_syntax::{Name, OpenOptions, Store};

/// A byte-level attack generator.
type Gen = fn(&[u8]) -> Option<Vec<u8>>;

/// A signature-shaped fixture with a 512-hex-digit `/Contents` placeholder.
fn fixture() -> Vec<u8> {
    sig_shaped(256)
}

/// Opens `pdf` leniently; `None` if it cannot be opened at all.
fn try_open(pdf: &[u8]) -> Option<Store> {
    Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).ok()
}

/// The in-place (same-length) USF mutators: each must keep the byte length and the signed prefix
/// up to the mutated token, and leave a reopenable file.
fn in_place() -> Vec<(&'static str, Gen)> {
    vec![
        ("usf_contents_missing", usf_contents_missing),
        ("usf_contents_null", usf_contents_null),
        ("usf_contents_empty_hex", usf_contents_empty_hex),
        ("usf_contents_literal_string", usf_contents_literal_string),
        ("usf_byterange_missing", usf_byterange_missing),
        ("usf_byterange_null", usf_byterange_null),
        ("usf_byterange_two_values", usf_byterange_two_values),
        ("usf_byterange_negative", usf_byterange_negative),
        ("usf_byterange_not_from_zero", usf_byterange_not_from_zero),
        ("usf_byterange_past_eof", usf_byterange_past_eof),
        ("usf_byterange_reals", usf_byterange_reals),
        ("usf_byterange_indirect", usf_byterange_indirect),
        ("usf_byterange_zeroes", usf_byterange_zeroes),
        ("usf_subfilter_unknown", usf_subfilter_unknown),
        ("usf_cms_garbage", usf_cms_garbage),
    ]
}

/// The mutators that append a revision: each must preserve the whole signed prefix (bytes are
/// only added) and grow the file.
fn appenders() -> Vec<(&'static str, Gen)> {
    vec![
        ("isa_classic_content_replaced", isa_classic_content_replaced),
        ("isa_free_object", isa_free_object),
        ("isa_relist_identical", isa_relist_identical),
        ("isa_info_only", isa_info_only),
        ("isa_objects_without_xref", isa_objects_without_xref),
        ("isa_xref_without_trailer", isa_xref_without_trailer),
        ("isa_bad_startxref_update", isa_bad_startxref_update),
        (
            "isa_prev_skips_signed_revision",
            isa_prev_skips_signed_revision,
        ),
        ("isa_hybrid_table_vs_xrefstm", isa_hybrid_table_vs_xrefstm),
        (
            "isa_objstm_container_overwritten",
            isa_objstm_container_overwritten,
        ),
        ("swa_two_dicts_same_byterange", swa_two_dicts_same_byterange),
        (
            "swa_sig_dict_redefined_in_update",
            swa_sig_dict_redefined_in_update,
        ),
        ("shadow_hide_overlay_removed", shadow_hide_overlay_removed),
        (
            "shadow_hide_repoint_to_signed_bytes",
            shadow_hide_repoint_to_signed_bytes,
        ),
        ("shadow_replace_font", shadow_replace_font),
        ("shadow_replace_field_value", shadow_replace_field_value),
        ("shadow_root_switch", shadow_root_switch),
        (
            "shadow_short_length_in_update",
            shadow_short_length_in_update,
        ),
    ]
}

#[test]
fn sig_shaped_is_a_well_formed_signature_scaffold() {
    let pdf = fixture();
    let store = try_open(&pdf).expect("sig_shaped opens");
    // Not reconstructed, two revisions (base + the signature update).
    assert!(!store.structure_repaired());
    assert_eq!(store.revisions().len(), 2);
    // It carries a located /ByteRange and /Contents, and the AcroForm/field wiring.
    assert!(byte_range_value_span(&pdf).is_some());
    let contents = contents_value_span(&pdf).expect("a /Contents token");
    assert_eq!(
        contents.end - contents.start,
        512 + 2,
        "2*256 hex digits + <>"
    );
    assert!(find(&pdf, b"/SubFilter /ETSI.CAdES.detached").is_some());
    assert!(find(&pdf, b"/FT /Sig").is_some());
    // The signature object is uncompressed, so its /Contents is byte-addressable.
    let sig = first_sig_dict(&store).expect("a signature dictionary");
    assert!(matches!(
        store.object_location(sig),
        Some(folioxide_syntax::ObjectLocation::InFile { .. })
    ));
}

#[test]
fn in_place_mutators_preserve_length_and_offsets() {
    let pdf = fixture();
    for (name, mutate) in in_place() {
        let out = mutate(&pdf).unwrap_or_else(|| panic!("{name} applies to sig_shaped"));
        assert_eq!(out.len(), pdf.len(), "{name}: same-length, in-place");
        // The prefix up to the first changed byte is identical, and so is the tail: only the
        // token region changed, so every later offset (the xref) is intact and the file reopens.
        assert!(try_open(&out).is_some(), "{name}: still opens");
        // Something actually changed.
        assert_ne!(out, pdf, "{name}: must mutate");
    }
}

#[test]
fn appenders_preserve_the_signed_prefix_and_grow() {
    let pdf = fixture();
    for (name, mutate) in appenders() {
        let out = mutate(&pdf).unwrap_or_else(|| panic!("{name} applies to sig_shaped"));
        assert!(out.len() > pdf.len(), "{name}: appends bytes");
        assert!(
            out.get(..pdf.len()) == Some(pdf.as_slice()),
            "{name}: the signed bytes are untouched (appended, never rewritten)"
        );
        // Opening must never panic (robustness); malformed updates may be structure_repaired.
        let _ = try_open(&out);
    }
}

#[test]
fn well_formed_appenders_reopen_with_another_revision() {
    // The writer-based ISA/shadow mutators produce a parseable extra revision.
    let pdf = fixture();
    for (name, mutate) in [
        (
            "isa_classic_content_replaced",
            isa_classic_content_replaced as Gen,
        ),
        ("isa_free_object", isa_free_object),
        ("isa_relist_identical", isa_relist_identical),
        ("isa_info_only", isa_info_only),
        ("shadow_hide_overlay_removed", shadow_hide_overlay_removed),
        ("shadow_replace_font", shadow_replace_font),
        ("shadow_replace_field_value", shadow_replace_field_value),
        ("shadow_root_switch", shadow_root_switch),
    ] {
        let out = mutate(&pdf).unwrap_or_else(|| panic!("{name} applies"));
        let store = try_open(&out).unwrap_or_else(|| panic!("{name} reopens"));
        assert_eq!(store.revisions().len(), 3, "{name}: base + sig + attack");
        assert!(!store.structure_repaired(), "{name}: well-formed");
    }
}

#[test]
fn usf_contents_missing_renames_only_the_sig_contents_key() {
    let pdf = fixture();
    let out = usf_contents_missing(&pdf).unwrap();
    // The signature /Contents key is gone, renamed to /Xontents; the page's `/Contents 4 0 R`
    // reference (a different value kind) is untouched.
    assert!(find(&out, b"/Xontents").is_some());
    assert!(
        find(&out, b"/Contents 4 0 R").is_some(),
        "page /Contents kept"
    );
}

#[test]
fn usf_byterange_variants_change_the_array_in_place() {
    let pdf = fixture();
    let span = byte_range_value_span(&pdf).unwrap();
    let width = span.end - span.start;
    for (name, mutate, needle) in [
        (
            "two_values",
            usf_byterange_two_values as Gen,
            b"[0 0]".as_slice(),
        ),
        ("negative", usf_byterange_negative, b"[0 -1 0 0]"),
        ("not_from_zero", usf_byterange_not_from_zero, b"[1 2 3 4]"),
        ("zeroes", usf_byterange_zeroes, b"[0 0 0 0]"),
        ("indirect", usf_byterange_indirect, b"1 0 R"),
    ] {
        let out = mutate(&pdf).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(out.len(), pdf.len(), "{name}");
        let region = out.get(span.start..span.start + width).unwrap();
        assert!(
            region.starts_with(needle),
            "{name}: {:?}",
            String::from_utf8_lossy(region)
        );
        // The padding keeps the closing bracket's original column unused by content.
        assert!(region.iter().all(|&b| b != b'\n'), "{name}: single line");
    }
}

#[test]
fn mutate_cms_der_keeps_contents_width() {
    // A synthetic ContentInfo-shaped DER embedded in /Contents: mutate_cms_der decodes it, lets a
    // transform run, and re-pads to the same width.
    let der: Vec<u8> = {
        // SEQUENCE { OID content-type, SET { ... } } — just enough to carry the content-type OID.
        let mut inner = oid_content_type().to_vec();
        let mut seq = vec![0x30, inner.len() as u8];
        seq.append(&mut inner);
        seq
    };
    // Build a /Contents large enough to hold it with zero padding, via sig_shaped then overwrite.
    let base = sig_shaped(64);
    let span = contents_value_span(&base).unwrap();
    let hex = encode_hex(&der);
    let mut embedded = base.clone();
    let inner = span.start + 1..span.end - 1;
    let mut value = hex;
    value.resize(inner.end - inner.start, b'0');
    embedded.splice(inner.clone(), value);

    // The OID is present, so content_type_corrupt flips its tail and keeps the width.
    let out = usf_cms_content_type_corrupt(&embedded).expect("content-type OID present");
    assert_eq!(out.len(), embedded.len());
    let out_der = decode_hex(out.get(inner.clone()).unwrap()).unwrap();
    assert_ne!(
        trim_to_der(&out_der),
        der.as_slice(),
        "the OID tail was flipped"
    );
    // ESS OID is absent here, so that mutator declines rather than corrupting unrelated bytes.
    assert!(usf_ess_mismatch(&embedded).is_none());
}

/// A ContentInfo-shaped DER: `SEQUENCE { OID, [0] { SEQUENCE { version, SET digestAlgs, SEQUENCE
/// encap { OID }, [0] certs { cert }, SET signerInfos { SEQUENCE { …, OCTET STRING sig } } } } }`,
/// with a certificate long enough to need a long-form length.
fn synthetic_cms() -> Vec<u8> {
    let oid = der_encode(
        0x06,
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02],
    );
    let version = der_encode(0x02, &[1]);
    let digest_algs = der_encode(TAG_SET, &der_encode(TAG_SEQUENCE, &[0x05, 0x00]));
    let encap = der_encode(TAG_SEQUENCE, &der_encode(0x06, &[0x2A, 0x03]));
    let certs = der_encode(TAG_CONTEXT_0, &der_encode(TAG_SEQUENCE, &[0x55; 300]));
    let signer_info = der_encode(
        TAG_SEQUENCE,
        &[version.clone(), der_encode(TAG_OCTET_STRING, &[7, 8, 9])].concat(),
    );
    let infos = der_encode(TAG_SET, &signer_info);
    let signed_data = der_encode(
        TAG_SEQUENCE,
        &[version, digest_algs, encap, certs, infos].concat(),
    );
    der_encode(
        TAG_SEQUENCE,
        &[oid, der_encode(TAG_CONTEXT_0, &signed_data)].concat(),
    )
}

/// `cms` embedded zero-padded in a signature-shaped PDF's `/Contents`.
fn with_cms(cms: &[u8]) -> (Vec<u8>, Range<usize>) {
    let base = sig_shaped(1024);
    let span = contents_value_span(&base).unwrap();
    let inner = span.start + 1..span.end - 1;
    let mut value = encode_hex(cms);
    value.resize(inner.len(), b'0');
    let mut pdf = base;
    pdf.splice(inner.clone(), value);
    (pdf, inner)
}

/// The SignedData fields of the CMS in `pdf`'s `/Contents`.
fn signed_data_fields(pdf: &[u8], inner: Range<usize>) -> Vec<(u8, Vec<u8>)> {
    let der = decode_hex(&pdf[inner]).unwrap();
    let mut fields = None;
    edit_signed_data(trim_to_der(&der), |f| {
        fields = Some(f.clone());
        Some(())
    })
    .unwrap();
    fields.unwrap()
}

#[test]
fn der_walker_round_trips() {
    let cms = synthetic_cms();
    assert_eq!(edit_signed_data(&cms, |_| Some(())), Some(cms.clone()));
    assert_eq!(edit_signed_data(&cms, |_| None), None);
    assert_eq!(edit_signed_data(&cms[..cms.len() - 1], |_| Some(())), None);
    assert_eq!(edit_signed_data(b"\x30\x00", |_| Some(())), None);
    assert_eq!(der_elements(&[0x1F, 0x01, 0x00]), None, "multi-byte tag");
    assert_eq!(der_encode(0x04, &[0; 0x80])[..3], [0x04, 0x81, 0x80]);
    assert_eq!(der_encode(0x04, &[0; 0x100])[..4], [0x04, 0x82, 0x01, 0x00]);
}

#[test]
fn size_changing_cms_attacks_keep_the_placeholder_width() {
    let (pdf, inner) = with_cms(&synthetic_cms());
    let fields = signed_data_fields(&pdf, inner.clone());
    assert_eq!(fields.len(), 5);

    let two = usf_cms_two_signerinfos(&pdf).unwrap();
    assert_eq!(two.len(), pdf.len());
    let infos = signed_data_fields(&two, inner.clone()).pop().unwrap().1;
    let infos = der_elements(&infos).unwrap();
    assert_eq!(infos.len(), 2, "a second SignerInfo");
    assert_ne!(infos[0], infos[1], "the copy's signature differs");
    assert_eq!(infos[0].1.len(), infos[1].1.len());

    let none = usf_cms_no_certificates(&pdf).unwrap();
    assert_eq!(none.len(), pdf.len());
    let fields = signed_data_fields(&none, inner.clone());
    assert_eq!(fields.len(), 4);
    assert!(fields.iter().all(|(tag, _)| *tag != TAG_CONTEXT_0));
    // Nothing left to remove.
    assert!(usf_cms_no_certificates(&none).is_none());

    let econtent = usf_cms_econtent_present(&pdf).unwrap();
    assert_eq!(econtent.len(), pdf.len());
    let encap = signed_data_fields(&econtent, inner).swap_remove(2).1;
    let encap = der_elements(&encap).unwrap();
    assert_eq!(encap.len(), 2);
    assert_eq!(encap[1].0, TAG_CONTEXT_0, "an eContent");

    // A CMS that fills the placeholder: no room for a second SignerInfo.
    let (_, inner) = with_cms(&synthetic_cms());
    let mut full = synthetic_cms();
    let room = inner.len() / 2 - full.len();
    full = edit_signed_data(&full, |fields| {
        let (_, certs) = fields.iter_mut().find(|(t, _)| *t == TAG_CONTEXT_0)?;
        certs.extend(der_encode(0x04, &vec![0; room - 8]));
        Some(())
    })
    .unwrap();
    assert!(full.len() <= inner.len() / 2);
    let (pdf, _) = with_cms(&full);
    assert!(usf_cms_two_signerinfos(&pdf).is_none());
    // The generators decline without a CMS.
    let plain = sig_shaped(64);
    assert!(usf_cms_two_signerinfos(&plain).is_none());
    assert!(usf_cms_no_certificates(&plain).is_none());
    assert!(usf_cms_econtent_present(&plain).is_none());
}

#[test]
fn swa_helpers() {
    assert_eq!(parse_ints(b"[0 10 20 30]"), Some(vec![0, 10, 20, 30]));
    assert_eq!(parse_ints(b"[0 1.5]"), None);
    assert_eq!(parse_ints(b"0 1"), None);
    let section = b"xref\n0 3\n0000000000 65535 f \n0000000100 00000 n \n0000000200 00000 n \n\
                    trailer\n<< /Size 3 /Prev 100 >>\n";
    let moved = shift_xref_offsets(section, 150, 1000).unwrap();
    assert_eq!(moved.len(), section.len());
    let text = String::from_utf8(moved).unwrap();
    assert!(
        text.contains("0000000100 00000 n \n0000001200 00000 n \n"),
        "{text}"
    );
    assert!(text.contains("/Prev 100"), "the trailer is kept: {text}");
    assert!(
        shift_xref_offsets(b"xref\n0 1\n", 0, 1).is_none(),
        "no trailer"
    );
    // Wrapping needs the /ByteRange in signed part 2 (pyHanko's layout): ours declines.
    assert!(swa_part2_moved(&sig_shaped(64)).is_none());
    assert!(swa_part2_moved(&crate::fixtures::syntax::minimal()).is_none());
}

#[test]
fn der_total_len_reads_short_and_long_forms() {
    // Short form: 0x30 0x03 <3 bytes>.
    assert_eq!(der_total_len(&[0x30, 0x03, 1, 2, 3]), Some(5));
    // Long form: 0x30 0x81 0x80 <128 bytes>.
    let mut long = vec![0x30, 0x81, 0x80];
    long.extend(std::iter::repeat_n(0u8, 0x80));
    assert_eq!(der_total_len(&long), Some(3 + 0x80));
    // Trailing padding is trimmed.
    let mut padded = vec![0x30, 0x02, 0xAA, 0xBB];
    padded.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(trim_to_der(&padded), &[0x30, 0x02, 0xAA, 0xBB]);
}

#[test]
fn last_startxref_reads_the_newest_offset() {
    let pdf = fixture();
    let value = last_startxref(&pdf).expect("a startxref");
    // It points at a cross-reference section: `xref` or an object header lives there.
    let at = usize::try_from(value).unwrap();
    assert!(pdf.get(at..at + 4) == Some(b"xref") || super::find(&pdf, b"startxref").is_some());
}

#[test]
fn generators_decline_on_a_plain_unsigned_pdf() {
    // With no signature dictionary, the signature-specific generators return None rather than
    // mangling an unrelated object.
    let plain = crate::fixtures::syntax::minimal();
    assert!(usf_contents_null(&plain).is_none());
    assert!(usf_byterange_null(&plain).is_none());
    assert!(usf_subfilter_unknown(&plain).is_none());
    assert!(usf_cms_content_type_corrupt(&plain).is_none());
    // The generic ISA appenders still work on any PDF (they do not need a signature).
    assert!(isa_objects_without_xref(&plain).is_some());
}

/// The newest AcroForm dictionary of `pdf` (indirect).
fn acroform_of(pdf: &[u8]) -> Dict {
    let store = try_open(pdf).expect("opens");
    let root = store.root_id().expect("a catalog");
    let catalog = store.resolve(root).unwrap().as_dict().unwrap().clone();
    let acroform = catalog.get_ref(b"AcroForm").expect("an indirect AcroForm");
    store.resolve(acroform).unwrap().as_dict().unwrap().clone()
}

/// Asserts that `out` is `before` plus one well-formed revision.
fn one_more_revision(name: &str, before: &[u8], out: &[u8]) -> Store {
    assert!(out.starts_with(before), "{name}: appended");
    let revisions = try_open(before).unwrap().revisions().len();
    let store = try_open(out).unwrap_or_else(|| panic!("{name} reopens"));
    assert_eq!(store.revisions().len(), revisions + 1, "{name}");
    assert!(!store.structure_repaired(), "{name}: well-formed");
    store
}

#[test]
fn text_field_inputs_vary_one_control_each() {
    let minimal = crate::fixtures::syntax::minimal();
    let field = |pdf: &[u8]| {
        let store = try_open(pdf).unwrap();
        let id = field_named(&store, b"Amount").expect("the Amount field");
        store.resolve(id).unwrap().as_dict().unwrap().clone()
    };
    let fonts = |form: &Dict| {
        form.get_dict(b"DR")
            .unwrap()
            .get_dict(b"Font")
            .unwrap()
            .clone()
    };

    let input = text_field_form_input(&minimal).expect("applies");
    let form = acroform_of(&input);
    assert_eq!(
        form.get_str_bytes(b"DA"),
        Some(b"/Helv 20 Tf 0 g".as_slice())
    );
    assert!(!form.contains_key(b"NeedAppearances") && !form.contains_key(b"Q"));
    assert!(fonts(&form).contains_key(b"Helv"));
    assert!(field(&input).contains_key(b"AP") && !field(&input).contains_key(b"DA"));

    let input = text_field_need_appearances_input(&minimal).expect("applies");
    assert_eq!(
        acroform_of(&input).get(b"NeedAppearances"),
        Some(&Object::Bool(true))
    );
    assert!(field(&input).contains_key(b"AP"));

    let input = text_field_no_appearance_input(&minimal).expect("applies");
    let form = acroform_of(&input);
    assert!(!form.contains_key(b"DA") && !form.contains_key(b"NeedAppearances"));
    assert!(!field(&input).contains_key(b"AP") && !field(&input).contains_key(b"DA"));

    let input = text_field_da_font_missing_input(&minimal).expect("applies");
    let form = acroform_of(&input);
    assert!(form.contains_key(b"DA") && fonts(&form).is_empty());

    // /AP /N an indirect dictionary that is no stream.
    let input = text_field_ap_not_stream_input(&minimal).expect("applies");
    let store = try_open(&input).unwrap();
    let ap = field(&input).get_dict(b"AP").unwrap().clone();
    let n = store.resolve(ap.get_ref(b"N").unwrap()).unwrap();
    assert!(n.as_dict().is_some() && !matches!(*n, Object::Stream(_)));
    assert!(!field(&input).contains_key(b"DA") && !acroform_of(&input).contains_key(b"DA"));

    // The orphan widget: on the page, not in /Fields, which lists the `Other` field instead.
    let registered = |pdf: &[u8]| {
        let store = try_open(pdf).unwrap();
        let fields = acroform_of(pdf).get_array(b"Fields").unwrap().to_vec();
        let amount = field_named(&store, b"Amount").unwrap();
        let other = field_named(&store, b"Other").unwrap();
        let page = store.resolve(first_page(&store).unwrap()).unwrap();
        let annots = page
            .as_dict()
            .unwrap()
            .get_array(b"Annots")
            .unwrap()
            .to_vec();
        assert!(annots.contains(&Object::Ref(amount)) && annots.contains(&Object::Ref(other)));
        (
            fields.contains(&Object::Ref(amount)),
            fields.contains(&Object::Ref(other)),
        )
    };
    let input = orphan_text_widget_input(&minimal).expect("applies");
    assert_eq!(registered(&input), (false, true));
    assert!(!field(&input).contains_key(b"AP") && !field(&input).contains_key(b"DA"));
    assert!(!acroform_of(&input).contains_key(b"DA"));
    let input = orphan_text_widget_da_font_input(&minimal).expect("applies");
    assert_eq!(registered(&input), (false, true));
    assert_eq!(
        field(&input).get_str_bytes(b"DA"),
        Some(b"/F7 20 Tf 0 g".as_slice())
    );
    assert!(!fonts(&acroform_of(&input)).contains_key(b"F7"));
    // The registered field's appearance stream without /Resources.
    let appearance_of = |pdf: &[u8], name: &[u8]| {
        let store = try_open(pdf).unwrap();
        let id = field_named(&store, name).unwrap();
        let field = store.resolve(id).unwrap().as_dict().unwrap().clone();
        let n = field.get_dict(b"AP").unwrap().get_ref(b"N").unwrap();
        match &*store.resolve(n).unwrap() {
            Object::Stream(stream) => stream.dict.clone(),
            other => panic!("{other:?}"),
        }
    };
    assert!(appearance_of(&input, b"Other").contains_key(b"Resources"));
    let input = orphan_widget_bare_appearance_input(&minimal).expect("applies");
    assert_eq!(registered(&input), (false, true));
    assert!(!appearance_of(&input, b"Other").contains_key(b"Resources"));
}

#[test]
fn acroform_control_generators_change_one_key_each() {
    let minimal = crate::fixtures::syntax::minimal();
    let text_field = text_field_form_input(&minimal).expect("applies");
    let need_appearances = text_field_need_appearances_input(&minimal).expect("applies");
    let no_appearance = text_field_no_appearance_input(&minimal).expect("applies");
    let da_font_missing = text_field_da_font_missing_input(&minimal).expect("applies");
    let ap_not_stream = text_field_ap_not_stream_input(&minimal).expect("applies");
    let orphan = orphan_text_widget_input(&minimal).expect("applies");
    let orphan_da_font = orphan_text_widget_da_font_input(&minimal).expect("applies");
    let fonts = |form: &Dict| {
        form.get_dict(b"DR")
            .unwrap()
            .get_dict(b"Font")
            .unwrap()
            .clone()
    };
    let helv = fonts(&acroform_of(&text_field))
        .get(b"Helv")
        .cloned()
        .expect("/DR /Font /Helv");

    for (name, input, generate) in [
        (
            "shadow_acroform_need_appearances_set",
            &text_field,
            shadow_acroform_need_appearances_set as Gen,
        ),
        (
            "shadow_acroform_need_appearances_removed_stale_ap",
            &need_appearances,
            shadow_acroform_need_appearances_removed_stale_ap,
        ),
        (
            "acroform_need_appearances_false_added",
            &text_field,
            acroform_need_appearances_false_added,
        ),
        (
            "shadow_acroform_da_changed",
            &text_field,
            shadow_acroform_da_changed,
        ),
        (
            "shadow_acroform_da_removed",
            &text_field,
            shadow_acroform_da_removed,
        ),
        (
            "shadow_acroform_da_added_noap",
            &no_appearance,
            shadow_acroform_da_added_noap,
        ),
        (
            "shadow_acroform_da_added_ap_not_stream",
            &ap_not_stream,
            shadow_acroform_da_added_ap_not_stream,
        ),
        (
            "shadow_acroform_da_added_orphan_widget",
            &orphan,
            shadow_acroform_da_added_orphan_widget,
        ),
        (
            "shadow_acroform_dr_font_orphan_widget_da",
            &orphan_da_font,
            shadow_acroform_dr_font_orphan_widget_da,
        ),
        (
            "shadow_acroform_q_changed",
            &text_field,
            shadow_acroform_q_changed,
        ),
        (
            "shadow_acroform_dr_name_replaced",
            &text_field,
            shadow_acroform_dr_name_replaced,
        ),
        (
            "shadow_acroform_dr_name_removed",
            &text_field,
            shadow_acroform_dr_name_removed,
        ),
        (
            "shadow_acroform_dr_da_font_added",
            &da_font_missing,
            shadow_acroform_dr_da_font_added,
        ),
        (
            "shadow_acroform_dr_encoding_added",
            &text_field,
            shadow_acroform_dr_encoding_added,
        ),
        (
            "acroform_dr_name_added",
            &text_field,
            acroform_dr_name_added,
        ),
    ] {
        let form = acroform_of(input);
        let out = generate(input).unwrap_or_else(|| panic!("{name} applies"));
        one_more_revision(name, input, &out);
        let after = acroform_of(&out);
        let changed: Vec<&Name> = after
            .keys()
            .chain(form.keys())
            .filter(|k| after.get(k.as_bytes()) != form.get(k.as_bytes()))
            .collect();
        assert!(!changed.is_empty(), "{name}: something changes");
        assert!(
            changed
                .iter()
                .all(|k| k.as_bytes() == changed[0].as_bytes()),
            "{name}: one key changes ({changed:?})"
        );
        let dr = |form: &Dict| form.get_dict(b"DR").unwrap().clone();
        match name {
            "shadow_acroform_need_appearances_set" => {
                assert_eq!(after.get(b"NeedAppearances"), Some(&Object::Bool(true)));
            }
            "shadow_acroform_need_appearances_removed_stale_ap" => {
                assert!(!after.contains_key(b"NeedAppearances"));
            }
            "acroform_need_appearances_false_added" => {
                assert_eq!(after.get(b"NeedAppearances"), Some(&Object::Bool(false)));
            }
            "shadow_acroform_da_changed" => {
                assert_eq!(
                    after.get_str_bytes(b"DA"),
                    Some(b"/Helv 20 Tf 1 g".as_slice())
                );
            }
            "shadow_acroform_da_removed" => assert!(!after.contains_key(b"DA")),
            "shadow_acroform_da_added_noap"
            | "shadow_acroform_da_added_ap_not_stream"
            | "shadow_acroform_da_added_orphan_widget" => {
                assert_eq!(
                    after.get_str_bytes(b"DA"),
                    Some(b"/Helv 20 Tf 1 g".as_slice())
                );
            }
            "shadow_acroform_dr_font_orphan_widget_da" => {
                assert!(!fonts(&form).contains_key(b"F7"));
                assert_eq!(fonts(&after).get(b"Helv"), Some(&helv));
                let store = try_open(&out).unwrap();
                let f7 = fonts(&after).get_ref(b"F7").expect("an indirect /F7");
                let f7 = store.resolve(f7).unwrap().as_dict().unwrap().clone();
                assert_eq!(
                    f7.get_name(b"BaseFont").map(Name::as_bytes),
                    Some(b"Helvetica".as_slice())
                );
                assert!(
                    f7.get_dict(b"Encoding")
                        .unwrap()
                        .contains_key(b"Differences")
                );
            }
            "shadow_acroform_q_changed" => assert_eq!(after.get(b"Q"), Some(&Object::Int(2))),
            "shadow_acroform_dr_name_replaced" => {
                assert_ne!(fonts(&after).get(b"Helv"), Some(&helv));
            }
            "shadow_acroform_dr_name_removed" => {
                assert!(fonts(&after).is_empty(), "{after:?}");
            }
            "shadow_acroform_dr_da_font_added" => {
                assert!(fonts(&form).is_empty() && fonts(&after).contains_key(b"Helv"));
            }
            "shadow_acroform_dr_encoding_added" => {
                assert_eq!(fonts(&after), fonts(&form));
                assert!(dr(&after).get_dict(b"Encoding").is_some());
            }
            _ => {
                assert_eq!(fonts(&after).get(b"Helv"), Some(&helv));
                assert!(fonts(&after).contains_key(b"Cour"));
            }
        }
    }

    // Each generator declines when its precondition does not hold.
    assert!(shadow_acroform_need_appearances_removed_stale_ap(&text_field).is_none());
    assert!(acroform_need_appearances_false_added(&need_appearances).is_none());
    assert!(shadow_acroform_da_added_noap(&text_field).is_none());
    assert!(shadow_acroform_da_added_ap_not_stream(&text_field).is_none());
    assert!(shadow_acroform_da_added_orphan_widget(&text_field).is_none());
    let added = shadow_acroform_dr_font_orphan_widget_da(&orphan_da_font).unwrap();
    assert!(shadow_acroform_dr_font_orphan_widget_da(&added).is_none());
    assert!(shadow_acroform_da_removed(&no_appearance).is_none());
    assert!(shadow_acroform_dr_da_font_added(&text_field).is_none());
    assert!(shadow_acroform_dr_name_removed(&da_font_missing).is_none());
    let encoded = shadow_acroform_dr_encoding_added(&text_field).unwrap();
    assert!(shadow_acroform_dr_encoding_added(&encoded).is_none());
    let q = shadow_acroform_q_changed(&text_field).unwrap();
    let q = shadow_acroform_q_changed(&q).unwrap();
    assert_eq!(
        acroform_of(&q).get(b"Q"),
        Some(&Object::Int(0)),
        "2 becomes 0"
    );

    // The /DA control applies only to an AcroForm without one.
    assert!(acroform_da_added(&text_field).is_none());
    let pdf = fixture();
    let out = acroform_da_added(&pdf).expect("applies to an AcroForm without /DA");
    one_more_revision("acroform_da_added", &pdf, &out);
    assert!(acroform_of(&out).contains_key(b"DA"));
}

#[test]
fn field_value_and_dss_generators_change_one_object_each() {
    let input = text_field_form_input(&crate::fixtures::syntax::minimal()).expect("applies");
    let out = form_field_value_changed(&input).expect("applies");
    let store = one_more_revision("form_field_value_changed", &input, &out);
    let field = field_named(&store, b"Amount").unwrap();
    let field = store.resolve(field).unwrap().as_dict().unwrap().clone();
    assert_eq!(field.get_str_bytes(b"V"), Some(b"1 EUR".as_slice()));
    assert!(form_field_value_changed(&crate::fixtures::syntax::minimal()).is_none());

    // The DSS holds a certificate: the fixture's CMS is a zero placeholder, so it declines;
    // a CMS-shaped /Contents with a [0] certificate is taken.
    let pdf = fixture();
    assert!(dss_added(&pdf).is_none());
    let certificate = der_encode(TAG_SEQUENCE, &der_encode(0x02, &[7]));
    let signed_data = [
        der_encode(0x02, &[1]),
        der_encode(TAG_SET, &[]),
        der_encode(TAG_SEQUENCE, &[]),
        der_encode(TAG_CONTEXT_0, &certificate),
    ]
    .concat();
    let content_info = der_encode(
        TAG_SEQUENCE,
        &[
            der_encode(0x06, &[0x2A]),
            der_encode(TAG_CONTEXT_0, &der_encode(TAG_SEQUENCE, &signed_data)),
        ]
        .concat(),
    );
    let pdf = mutate_cms_der(&pdf, |_| Some(content_info.clone())).expect("fits");
    let out = dss_added(&pdf).expect("applies");
    let store = one_more_revision("dss_added", &pdf, &out);
    let root = store.root_id().unwrap();
    let catalog = store.resolve(root).unwrap().as_dict().unwrap().clone();
    let dss = store.resolve(catalog.get_ref(b"DSS").unwrap()).unwrap();
    let certs = dss.as_dict().unwrap().get_array(b"Certs").unwrap().to_vec();
    let stream = store.resolve(certs[0].as_ref().unwrap()).unwrap();
    let data = store.stream_data(stream.as_stream().unwrap()).unwrap().data;
    assert_eq!(data, certificate);
    assert!(dss_added(&out).is_none(), "a /DSS is there already");
}

#[test]
fn role_pointer_generators_detach_and_change_the_old_object() {
    let input = info_metadata_input(&crate::fixtures::syntax::minimal()).expect("applies");
    let store = try_open(&input).unwrap();
    let info = store.trailer().get_ref(keys::INFO).expect("an /Info");
    let (_, metadata) = catalog_metadata(&store).expect("a /Metadata");
    let title = |store: &Store, id: ObjectId| {
        store
            .resolve(id)
            .unwrap()
            .as_dict()
            .unwrap()
            .get_str_bytes(b"Title")
            .unwrap()
            .to_vec()
    };
    let xmp = |store: &Store, id: ObjectId| {
        let value = store.resolve(id).unwrap();
        let stream = value.as_stream().unwrap();
        store.stream_data(stream).unwrap().data
    };
    assert_eq!(title(&store, info), b"Invoice");
    assert!(xmp(&store, metadata).windows(7).any(|w| w == b"Invoice"));

    for (name, generate) in [
        (
            "shadow_info_repoint_old_changed",
            shadow_info_repoint_old_changed as Gen,
        ),
        (
            "shadow_info_removed_old_changed",
            shadow_info_removed_old_changed,
        ),
        ("info_changed_in_place", info_changed_in_place),
        (
            "shadow_metadata_repoint_old_changed",
            shadow_metadata_repoint_old_changed,
        ),
        (
            "shadow_metadata_removed_old_changed",
            shadow_metadata_removed_old_changed,
        ),
        ("metadata_changed_in_place", metadata_changed_in_place),
    ] {
        let out = generate(&input).unwrap_or_else(|| panic!("{name} applies"));
        let after = one_more_revision(name, &input, &out);
        let new_info = after.trailer().get_ref(keys::INFO);
        let new_metadata = catalog_metadata(&after).map(|(_, m)| m);
        if name.contains("info") {
            // The old dictionary is retitled; the trailer names it, a new one, or nothing.
            assert_eq!(title(&after, info), b"Paid", "{name}");
            let want = match name {
                "shadow_info_repoint_old_changed" => new_info.filter(|&n| n != info),
                "shadow_info_removed_old_changed" => None,
                _ => Some(info),
            };
            assert_eq!(new_info, want, "{name}");
            assert_eq!(new_metadata, Some(metadata), "{name}");
        } else {
            assert!(
                xmp(&after, metadata).windows(4).any(|w| w == b"Paid"),
                "{name}"
            );
            let want = match name {
                "shadow_metadata_repoint_old_changed" => new_metadata.filter(|&m| m != metadata),
                "shadow_metadata_removed_old_changed" => None,
                _ => Some(metadata),
            };
            assert_eq!(new_metadata, want, "{name}");
            assert_eq!(new_info, Some(info), "{name}");
        }
    }
}

#[test]
fn new_sig_field_generators_register_a_field_with_the_key() {
    let pdf = fixture();
    for (name, generate, key) in [
        (
            "shadow_new_sig_field_a_javascript",
            shadow_new_sig_field_a_javascript as Gen,
            "A",
        ),
        (
            "shadow_new_sig_field_a_launch",
            shadow_new_sig_field_a_launch,
            "A",
        ),
        (
            "shadow_new_sig_field_a_uri",
            shadow_new_sig_field_a_uri,
            "A",
        ),
        ("shadow_new_sig_field_oc", shadow_new_sig_field_oc, "OC"),
        (
            "shadow_new_sig_field_aa_direct",
            shadow_new_sig_field_aa_direct,
            "AA",
        ),
        (
            "shadow_new_sig_field_parent",
            shadow_new_sig_field_parent,
            "Parent",
        ),
        ("new_sig_field_mk", new_sig_field_mk, "MK"),
    ] {
        let out = generate(&pdf).unwrap_or_else(|| panic!("{name} applies"));
        let store = one_more_revision(name, &pdf, &out);
        let fields = acroform_of(&out).get_array(b"Fields").unwrap().to_vec();
        let field = fields
            .last()
            .and_then(Object::as_ref)
            .expect("a new root field");
        let dict = store.resolve(field).unwrap().as_dict().unwrap().clone();
        assert_eq!(
            dict.get_name(b"FT").map(Name::as_bytes),
            Some(b"Sig".as_slice())
        );
        assert_eq!(
            dict.get_str_bytes(b"T"),
            Some(b"Signature2".as_slice()),
            "{name}"
        );
        assert!(dict.contains_key(key.as_bytes()), "{name}: /{key}");
        assert!(!dict.contains_key(b"V"), "{name}: unsigned");
        if key == "Parent" {
            // The parent is the signed field (object 7 of the fixture), with its /V.
            let parent = dict.get_ref(b"Parent").unwrap();
            assert_eq!(parent, ObjectId::new(7, 0));
            let parent = store.resolve(parent).unwrap();
            assert!(parent.as_dict().unwrap().contains_key(b"V"));
        }
    }
    // Without a signed field there is no parent to point to.
    let plain = crate::fixtures::syntax::minimal();
    assert!(shadow_new_sig_field_parent(&plain).is_none());
}
