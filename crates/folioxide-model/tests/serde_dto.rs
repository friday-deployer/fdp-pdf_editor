#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The DTOs' `serde` support (M2 brief "DTOs", ARCHITECTURE §A.7 and §A.8 point 4): `camelCase`
//! names, the representations chosen for rotations, dates and rectangles, the three states of
//! an [`InfoUpdate`] field, and round trips through JSON. The crate's own dev-dependency turns
//! the `serde` feature on, so these tests always run.

mod common;

use std::collections::BTreeMap;

use common::open;
use folioxide_model::{DocInfo, InfoUpdate, PageInfo, PdfDate, Rect, Rotation, Trapped};
use folioxide_testkit::fixtures::model;
use serde_json::{Value, json};

fn to_json<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

fn from_json<T: serde::de::DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

/// `PageInfo` is `{ index, width, height, mediaBox, cropBox, rotation }` with the rotation in
/// degrees and boxes as `{ llx, lly, urx, ury }`.
#[test]
fn page_info_json_shape() {
    let doc = open(model::inherited_attributes());
    let info = doc.page(0).unwrap().info();
    let value = to_json(&info);
    assert_eq!(
        value,
        json!({
            "index": 0,
            "width": 790.0,
            "height": 575.0,
            "mediaBox": { "llx": 0.0, "lly": 0.0, "urx": 595.0, "ury": 842.0 },
            "cropBox": { "llx": 10.0, "lly": 10.0, "urx": 585.0, "ury": 800.0 },
            "rotation": 90
        })
    );
    let back: PageInfo = from_json(value);
    assert_eq!(back, info);
    // Every page of the fixture round-trips.
    for i in 0..doc.page_count().unwrap() {
        let info = doc.page(i).unwrap().info();
        assert_eq!(from_json::<PageInfo>(to_json(&info)), info);
    }
}

/// Rotations are degrees; deserializing normalizes any multiple of 90 and refuses the rest.
#[test]
fn rotation_is_degrees() {
    for (rotation, degrees) in [
        (Rotation::R0, 0),
        (Rotation::R90, 90),
        (Rotation::R180, 180),
        (Rotation::R270, 270),
    ] {
        assert_eq!(to_json(&rotation), json!(degrees));
        assert_eq!(from_json::<Rotation>(json!(degrees)), rotation);
    }
    assert_eq!(from_json::<Rotation>(json!(-90)), Rotation::R270);
    assert_eq!(from_json::<Rotation>(json!(450)), Rotation::R90);
    let err = serde_json::from_value::<Rotation>(json!(45)).unwrap_err();
    assert!(err.to_string().contains("multiple of 90"), "{err}");
    assert!(serde_json::from_value::<Rotation>(json!("90")).is_err());
}

/// A rectangle deserializes normalized, like `Rect::new`.
#[test]
fn rect_is_normalized() {
    let r: Rect = from_json(json!({ "llx": 612, "lly": 792, "urx": 0, "ury": 0 }));
    assert_eq!(r, Rect::new(0.0, 0.0, 612.0, 792.0));
    assert!(serde_json::from_value::<Rect>(json!({ "llx": 0, "lly": 0, "urx": 1 })).is_err());
}

/// Dates are PDF date strings; deserializing is as lenient as `PdfDate::parse`.
#[test]
fn dates_are_pdf_date_strings() {
    let date = PdfDate::new(2024, 2, 29, 13, 30, 5)
        .unwrap()
        .with_offset(Some(330))
        .unwrap();
    assert_eq!(to_json(&date), json!("D:20240229133005+05'30'"));
    assert_eq!(from_json::<PdfDate>(json!("D:20240229133005+05'30'")), date);
    assert_eq!(from_json::<PdfDate>(json!("2024")).year, 2024);
    let utc = PdfDate::new(2026, 1, 2, 3, 4, 5)
        .unwrap()
        .with_offset(Some(0))
        .unwrap();
    assert_eq!(to_json(&utc), json!("D:20260102030405Z"));
    let err = serde_json::from_value::<PdfDate>(json!("yesterday")).unwrap_err();
    assert!(err.to_string().contains("not a PDF date"), "{err}");
    // The same conversions without serde.
    assert_eq!(date.to_string(), "D:20240229133005+05'30'");
    assert_eq!("D:20240229133005+05'30'".parse::<PdfDate>().unwrap(), date);
    assert_eq!(String::from(date), date.to_pdf_string());
}

/// `DocInfo` leaves absent entries out and uses `camelCase`; `Trapped` is a lower-case word.
#[test]
fn doc_info_json_shape() {
    let doc = open(model::info_strings());
    let info = doc.info().unwrap();
    let value = to_json(&info);
    assert_eq!(
        value,
        json!({
            "title": "\u{201C}Folio\u{201D} \u{2014} \u{FB01}nal \u{20AC}5",
            "author": "Zo\u{EB} \u{1F600}",
            "subject": "\u{DC}n\u{EF}c\u{F6}d\u{E9}",
            "keywords": "\u{65E5}\u{672C}",
            "producer": "folioxide-testkit",
            "creationDate": "D:20240229133005+05'30'",
            "modDate": "D:20240301000000",
            "trapped": "false",
            "custom": { "Company": "ACME" }
        })
    );
    assert_eq!(from_json::<DocInfo>(value), info);
    // Missing fields are absent entries.
    assert_eq!(from_json::<DocInfo>(json!({})), DocInfo::default());
    for (trapped, word) in [
        (Trapped::True, "true"),
        (Trapped::False, "false"),
        (Trapped::Unknown, "unknown"),
    ] {
        assert_eq!(to_json(&trapped), json!(word));
        assert_eq!(from_json::<Trapped>(json!(word)), trapped);
    }
}

/// An `InfoUpdate` field has three states: absent (keep), `null` (remove), a value (set).
#[test]
fn info_update_three_states() {
    let update: InfoUpdate = from_json(json!({
        "title": "New title",
        "author": null,
        "modDate": "D:20261010120000Z",
        "trapped": null,
        "custom": { "Company": "ACME", "Obsolete": null }
    }));
    assert_eq!(update.title, Some(Some("New title".to_owned())));
    assert_eq!(update.author, Some(None));
    assert_eq!(update.subject, None);
    assert_eq!(update.keywords, None);
    assert_eq!(update.creation_date, None);
    assert_eq!(
        update.mod_date,
        Some(Some(
            PdfDate::new(2026, 10, 10, 12, 0, 0)
                .unwrap()
                .with_offset(Some(0))
                .unwrap()
        ))
    );
    assert_eq!(update.trapped, Some(None));
    let mut custom = BTreeMap::new();
    custom.insert("Company".to_owned(), Some("ACME".to_owned()));
    custom.insert("Obsolete".to_owned(), None);
    assert_eq!(update.custom, custom);

    // Serializing gives the same three states back.
    let value = to_json(&update);
    assert_eq!(
        value,
        json!({
            "title": "New title",
            "author": null,
            "modDate": "D:20261010120000Z",
            "trapped": null,
            "custom": { "Company": "ACME", "Obsolete": null }
        })
    );
    assert_eq!(from_json::<InfoUpdate>(value), update);
    // An empty object changes nothing.
    assert!(from_json::<InfoUpdate>(json!({})).is_empty());
    assert_eq!(to_json(&InfoUpdate::default()), json!({}));
}

/// Applying a deserialized update gives what the JSON says.
#[test]
fn info_update_from_json_applies() {
    let mut doc = open(model::info_strings());
    let update: InfoUpdate = from_json(json!({
        "title": "\u{65B0}\u{3057}\u{3044}",
        "author": null,
        "trapped": "true",
        "custom": { "Company": null, "Reviewed": "yes" }
    }));
    doc.set_info(&update).unwrap();
    let info = doc.info().unwrap();
    assert_eq!(info.title.as_deref(), Some("\u{65B0}\u{3057}\u{3044}"));
    assert_eq!(info.author, None);
    assert_eq!(info.subject.as_deref(), Some("\u{DC}n\u{EF}c\u{F6}d\u{E9}"));
    assert_eq!(info.trapped, Some(Trapped::True));
    assert_eq!(info.custom.get("Company"), None);
    assert_eq!(info.custom.get("Reviewed").map(String::as_str), Some("yes"));
}
