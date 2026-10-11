#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Verification and signing stay bounded on hostile documents (R-18; QA findings 4 and 5): many
//! signature dictionaries over one large byte range, many over distinct large ranges, and a
//! field tree whose long names would be repeated in every kid.

mod sign_support;

use std::time::Duration;

use folioxide_sign::field::{MAX_FIELD_NAME_BYTES, MAX_FIELD_NAME_BYTES_TOTAL};
use folioxide_sign::report::ModificationLevel;
use folioxide_sign::verify_pdf::{
    MAX_CHANGED_OBJECTS, MAX_REPORTS, MAX_REPORTS_PER_SIGNATURE_DICTIONARY, MAX_VERIFIED_SIGNATURES,
};
use folioxide_syntax::{Dict, ErrorCode, IncrementalOptions, Object, ObjectId, OpenOptions, Store};
use folioxide_testkit::budget::within;
use folioxide_testkit::fixtures::syntax;
use folioxide_testkit::{PdfBuilder, XrefOpts};
use sign_support::*;

/// The hexadecimal DER of a real signature's CMS (without the zero padding).
fn real_cms_hex() -> String {
    let signed = sign_default(&syntax::minimal(), &rsa2048());
    let range = verify_plain(&signed)[0].byte_range.clone().unwrap();
    let (a, b) = (range[1] as usize, range[2] as usize);
    let hex = std::str::from_utf8(&signed[a + 1..b - 1]).unwrap();
    let len = hex.trim_end_matches('0').len().div_ceil(2) * 2;
    hex[..len].to_owned()
}

/// A one-page document whose AcroForm holds `fields` (field objects `first..`, written by
/// `write_fields`), with a page content stream of `filler` bytes.
fn document(filler: usize, write_fields: impl FnOnce(&mut PdfBuilder) -> Vec<u32>) -> Vec<u8> {
    let mut b = PdfBuilder::new();
    b.header("1.7");
    b.obj(2, 0, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
    b.obj(
        3,
        0,
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
    );
    b.stream_obj(4, 0, "", &b"0 0 m\n".repeat(filler / 6), None);
    let roots = write_fields(&mut b);
    let refs: Vec<String> = roots.iter().map(|n| format!("{n} 0 R")).collect();
    b.obj(
        1,
        0,
        format!(
            "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [{}] >> >>",
            refs.join(" ")
        ),
    );
    b.xref_table(XrefOpts::default());
    let trailer = format!("/Size {} /Root 1 0 R", b.size());
    b.trailer(trailer).startxref(None).raw(b"%%EOF\n");
    b.build()
}

#[test]
fn verify_many_signatures_over_one_large_range() {
    // QA finding 5 (D1b): hundreds of signature fields whose dictionaries sign the same range,
    // most of a 2 MB file. The range is hashed once; past MAX_VERIFIED_SIGNATURES the
    // signatures are listed without the CMS work.
    let cms = real_cms_hex();
    let count = MAX_VERIFIED_SIGNATURES + 44;
    let filler = 2 * 1024 * 1024;
    let pdf = document(filler, |b| {
        let mut roots = Vec::new();
        for i in 0..count as u32 {
            let (field, sig) = (10 + 2 * i, 11 + 2 * i);
            b.obj(field, 0, format!("<< /FT /Sig /T (S{i}) /V {sig} 0 R >>"));
            b.obj(
                sig,
                0,
                format!(
                    "<< /Type /Sig /SubFilter /ETSI.CAdES.detached /ByteRange [0 100 200 {}] \
                     /Contents <{cms}> >>",
                    filler - 1000
                ),
            );
            roots.push(field);
        }
        roots
    });
    let reports = verify_plain(&pdf);
    assert_eq!(reports.len(), count);
    let unverified = |r: &folioxide_sign::report::SignatureReport| {
        r.warnings.iter().any(|w| w.starts_with("not verified"))
    };
    assert_eq!(
        reports.iter().filter(|r| unverified(r)).count(),
        count - MAX_VERIFIED_SIGNATURES
    );
    for r in &reports {
        assert!(!r.is_valid(), "{}", summary(r));
        if unverified(r) {
            assert!(!r.intact && !r.signature_valid && r.signer.is_none());
        } else {
            // The one hash of the shared range is the other document's digest: not intact.
            assert!(r.signer.is_some(), "{}", summary(r));
        }
    }
}

#[test]
fn verify_bounds_the_bytes_hashed_for_distinct_ranges() {
    // Signatures over distinct ranges that each cover most of the file: past the hashing budget
    // (64 MiB plus four times the file) the remaining ones are not hashed, with a warning.
    let cms = real_cms_hex();
    let count = 60u32;
    let filler = 4 * 1024 * 1024;
    let pdf = document(filler, |b| {
        let mut roots = Vec::new();
        for i in 0..count {
            let (field, sig) = (10 + 2 * i, 11 + 2 * i);
            b.obj(field, 0, format!("<< /FT /Sig /T (S{i}) /V {sig} 0 R >>"));
            b.obj(
                sig,
                0,
                format!(
                    "<< /Type /Sig /SubFilter /ETSI.CAdES.detached /ByteRange [0 100 {} {}] \
                     /Contents <{cms}> >>",
                    200 + i,
                    filler - 1000
                ),
            );
            roots.push(field);
        }
        roots
    });
    let reports = verify_plain(&pdf);
    assert_eq!(reports.len(), count as usize);
    let not_hashed = reports
        .iter()
        .filter(|r| r.warnings.iter().any(|w| w.contains("were not hashed")))
        .count();
    // 64 MiB + 4 x ~4 MiB = ~80 MiB covers about 20 of the 4 MiB ranges.
    assert!((30..count as usize).contains(&not_hashed), "{not_hashed}");
    for r in reports
        .iter()
        .filter(|r| r.warnings.iter().any(|w| w.contains("were not hashed")))
    {
        assert!(!r.intact && !r.is_valid());
    }
}

#[test]
fn verify_field_tree_with_a_huge_name_is_bounded() {
    // QA finding 4 (D2s): a parent field with a 1 MB /T and thousands of signed kids. The names
    // are built on demand and capped, instead of a 1 MB name per kid (gigabytes).
    let cms = real_cms_hex();
    let kids = 3000u32;
    let pdf = document(0, |b| {
        let kid_refs: Vec<String> = (0..kids).map(|k| format!("{} 0 R", 20 + k)).collect();
        b.obj(
            10,
            0,
            format!(
                "<< /T ({}) /FT /Sig /Kids [{}] >>",
                "A".repeat(1_000_000),
                kid_refs.join(" ")
            ),
        );
        b.obj(
            11,
            0,
            format!(
                "<< /Type /Sig /SubFilter /ETSI.CAdES.detached /ByteRange [0 100 200 300] \
                 /Contents <{cms}> >>"
            ),
        );
        for k in 0..kids {
            b.obj(
                20 + k,
                0,
                format!("<< /T (k{k}) /Parent 10 0 R /V 11 0 R >>"),
            );
        }
        vec![10]
    });
    let reports = verify_plain(&pdf);
    // One signature dictionary shared by every kid: reported for the first few fields only.
    assert_eq!(reports.len(), MAX_REPORTS_PER_SIGNATURE_DICTIONARY);
    assert!(
        reports[0]
            .warnings
            .iter()
            .any(|w| w.contains(&format!("is the value of {kids} fields"))),
        "{:?}",
        reports[0].warnings
    );
    let mut total = 0;
    for r in &reports {
        let name = r.field_name.as_deref().unwrap();
        assert!(
            name.len() <= MAX_FIELD_NAME_BYTES + '…'.len_utf8(),
            "{}",
            name.len()
        );
        assert!(name.ends_with('…'));
        total += name.len();
    }
    assert!(total <= MAX_FIELD_NAME_BYTES_TOTAL + reports.len() * '…'.len_utf8());
    assert!(
        reports[0].warnings.iter().any(|w| w.contains("shortened")),
        "{:?}",
        reports[0].warnings
    );

    // Signing the same document creates a new field: the walk keeps the partial names, not a
    // qualified name per kid.
    let signed = sign_default(&pdf, &rsa2048());
    let reports = verify_plain(&signed);
    let new = reports
        .iter()
        .find(|r| r.field_name.as_deref() == Some("Signature1"))
        .expect("the new signature");
    assert!(new.is_valid(), "{}", summary(new));
}

#[test]
fn shared_long_partial_names_hit_the_name_budget() {
    // One 1 MB /T string shared by twenty root fields: 20 MB of partial names. Signing (which
    // needs the whole tree) refuses with LimitExceeded; verification examines what fits and says
    // so.
    let pdf = document(0, |b| {
        b.obj(9, 0, format!("({})", "N".repeat(1_000_000)));
        let mut roots = Vec::new();
        for i in 0..20 {
            b.obj(10 + i, 0, "<< /FT /Sig /T 9 0 R >>");
            roots.push(10 + i);
        }
        roots
    });
    let doc = open(&pdf);
    let err = folioxide_sign::field::signature_fields(&doc).unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded, "{err}");
    let err = folioxide_sign::sign::sign(
        &doc,
        &folioxide_sign::sign::SignRequest::new(&rsa2048(), time()),
    )
    .unwrap_err();
    assert_eq!(err.code(), ErrorCode::LimitExceeded, "{err}");
    // Nothing is signed, so verification lists nothing, without running out of memory.
    assert!(verify_plain(&pdf).is_empty());
}

/// `signed` (one signature, `Signature1`) with a revision that adds a root field `P` whose
/// `kids` kid fields all have the signature's dictionary as `/V` (QA K100k: one dictionary,
/// a hundred thousand reports).
fn kids_sharing_the_signature(signed: &[u8], kids: usize) -> Vec<u8> {
    let mut store = Store::open_bytes(signed.to_vec(), &OpenOptions::default()).unwrap();
    let root = store.root_id().unwrap();
    let catalog = store.resolve(root).unwrap().as_dict().unwrap().clone();
    let acroform = catalog.get_ref(b"AcroForm").unwrap();
    let mut form = store.resolve(acroform).unwrap().as_dict().unwrap().clone();
    let first_field = form.get_array(b"Fields").unwrap()[0].as_ref().unwrap();
    let sig = store
        .resolve(first_field)
        .unwrap()
        .as_dict()
        .unwrap()
        .get_ref(b"V")
        .unwrap();
    let mut parent = Dict::new();
    parent.insert("FT", Object::name("Sig"));
    parent.insert("T", Object::literal_string("P"));
    let parent = store.add(Object::Dict(parent)).unwrap();
    let mut refs = Vec::with_capacity(kids);
    for k in 0..kids {
        let mut kid = Dict::new();
        kid.insert("T", Object::literal_string(format!("k{k}")));
        kid.insert("Parent", Object::Ref(parent));
        kid.insert("V", Object::Ref(sig));
        refs.push(Object::Ref(store.add(Object::Dict(kid)).unwrap()));
    }
    let mut parent_dict = store.resolve(parent).unwrap().as_dict().unwrap().clone();
    parent_dict.insert("Kids", Object::Array(refs));
    store.set(parent, Object::Dict(parent_dict)).unwrap();
    let mut fields = form.get_array(b"Fields").unwrap().to_vec();
    fields.push(Object::Ref(parent));
    form.insert("Fields", Object::Array(fields));
    store.set(acroform, Object::Dict(form)).unwrap();
    store
        .save_incremental(&IncrementalOptions::default())
        .unwrap()
}

#[test]
fn verify_a_signature_dictionary_shared_by_many_fields_is_reported_a_few_times() {
    // QA finding (K100k): 50,000 kid fields whose /V is the one real signature dictionary. It
    // is verified and reported for the first fields only (a warning counts the rest), the
    // analysis is shared, and changed_objects names at most MAX_CHANGED_OBJECTS objects.
    let kids = 50_000;
    let signed = sign_default(&syntax::minimal(), &rsa2048());
    let pdf = kids_sharing_the_signature(&signed, kids);
    let (reports, elapsed) = within(Duration::from_secs(120), move || verify_plain(&pdf)).unwrap();
    assert_eq!(reports.len(), MAX_REPORTS_PER_SIGNATURE_DICTIONARY);
    let first = &reports[0];
    assert_eq!(first.field_name.as_deref(), Some("Signature1"));
    assert!(first.intact && first.signature_valid, "{}", summary(first));
    // The new fields are not signature fields the diff policy allows: the document changed.
    assert_eq!(first.modification, ModificationLevel::Other);
    let fields = kids + 1;
    for r in &reports {
        assert_eq!(r.sig_object, first.sig_object);
        assert!(
            r.warnings.iter().any(|w| w.contains(&format!(
                "is the value of {fields} fields; it is reported for the first \
                 {MAX_REPORTS_PER_SIGNATURE_DICTIONARY}"
            ))),
            "{:?}",
            r.warnings
        );
        assert_eq!(r.changed_objects.len(), MAX_CHANGED_OBJECTS);
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("changed objects names the first")),
            "{:?}",
            r.warnings
        );
        assert!(r.changed_objects.windows(2).all(|w| w[0] < w[1]));
    }
    eprintln!("{kids} shared kids verified in {elapsed:?}");
}

#[test]
fn verify_returns_at_most_max_reports() {
    // More signature dictionaries than MAX_REPORTS (orphans here): the list is cut, every report
    // says how many were left out, and the cut list is fail-closed (the reports past
    // MAX_VERIFIED_SIGNATURES are not verified, so not valid).
    let count = MAX_REPORTS + 300;
    let pdf = document(0, |b| {
        for i in 0..count as u32 {
            b.obj(
                10 + i,
                0,
                "<< /Type /Sig /ByteRange [0 1 2 3] /Contents <00> >>",
            );
        }
        Vec::new()
    });
    let reports = verify_plain(&pdf);
    assert_eq!(reports.len(), MAX_REPORTS);
    for r in &reports {
        assert!(!r.is_valid());
        assert!(
            r.warnings
                .iter()
                .any(|w| w.contains("300 of them are not reported")),
            "{:?}",
            r.warnings
        );
    }
    let unverified = reports
        .iter()
        .filter(|r| r.warnings.iter().any(|w| w.starts_with("not verified")))
        .count();
    assert_eq!(unverified, MAX_REPORTS - MAX_VERIFIED_SIGNATURES);
}

#[test]
fn verify_names_a_bounded_number_of_changed_objects() {
    // A revision after the signature that adds many objects: changed_objects names the first
    // MAX_CHANGED_OBJECTS, sorted, and a warning gives the full count.
    let signed = sign_default(&syntax::minimal(), &rsa2048());
    let mut store = Store::open_bytes(signed, &OpenOptions::default()).unwrap();
    let added = MAX_CHANGED_OBJECTS + 50;
    for i in 0..added {
        store.add(Object::Int(i as i64)).unwrap();
    }
    let pdf = store
        .save_incremental(&IncrementalOptions::default())
        .unwrap();
    let r = &verify_plain(&pdf)[0];
    assert_eq!(r.modification, ModificationLevel::LtaUpdates, "orphans");
    assert_eq!(r.changed_objects.len(), MAX_CHANGED_OBJECTS);
    assert!(r.changed_objects.windows(2).all(|w| w[0] < w[1]));
    assert!(
        r.changed_objects
            .iter()
            .all(|id| *id != ObjectId::new(0, 0))
    );
    assert!(
        r.warnings
            .iter()
            .any(|w| w.contains(&format!("list {added} objects"))),
        "{:?}",
        r.warnings
    );
}
