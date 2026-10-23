//! # folioxide-node: Node.js binding for Folioxide
//!
//! A napi-rs (Node-API) addon that exposes the `folioxide` facade crate to JavaScript. It is the
//! only crate in the workspace that depends on napi. The npm package `folioxide` wraps the
//! generated loader (`binding.js`) in a hand-written facade (`index.js`, `index.mjs`,
//! `index.d.ts`); see `docs/ARCHITECTURE.md` §A.7.
//!
//! - [`PdfDocument`] (`document`): open, create, inspect, edit and save a document, with
//!   asynchronous variants of the heavy operations and `E_BUSY` instead of blocking.
//! - The plain objects that cross the boundary (`dto`): [`PageInfo`], [`DocInfo`],
//!   [`InfoUpdate`], [`Diagnostic`] and the options, with the JSON shape of the core's `serde`
//!   DTOs.
//! - Signing and verification (`sign`): [`LocalSigner`] (PKCS#12 and PEM keys),
//!   `PdfDocument.prepareSignature` and [`PreparedSignature`] for the two-phase flow (the
//!   JavaScript facade's `signPdf` awaits an external signer between the phases), and
//!   `PdfDocument.verifySignatures`, whose [`SignatureReport`]s have the JSON shape of the core's
//!   serde DTOs. M4 adds certification (`certify`), visible signatures
//!   ([`SignatureAppearanceOptions`]) and PAdES B-T: `PreparedSignature.timestampRequest` and
//!   `finish(signature, timestampResponse)`, around a TSA the facade's `signPdf` awaits, and the
//!   reports' [`TimestampInfo`].
//! - Errors (`error`): every error carries `err.code = "E_" + ErrorCode`, or `E_BUSY` or
//!   `E_CLOSED`.

mod document;
mod dto;
mod error;
mod sign;

pub use document::{OpenTask, PdfDocument, SaveError, SaveTask};
pub use dto::{
    Diagnostic, DocInfo, IncrementalSaveOptions, InfoUpdate, OpenOptions, PageBox, PageInfo, Rect,
    SaveOptions, StreamCompression, Trapped, XrefStyle,
};
pub use error::{BindingError, E_BUSY, E_CLOSED, JsResult, MAX_MESSAGE_LEN};
pub use sign::{
    AppearanceFont, CertificateInfo, Coverage, DigestAlg, DocumentTaskError, FieldMode, FinishTask,
    ImagePosition, KeyDescription, LocalSigner, ModificationLevel, ObjectRef, PadesLevel,
    PrepareSignatureOptions, PrepareTask, PreparedSignature, ProblemCode, SigAlg, SignTask,
    SignatureAppearanceOptions, SignatureFieldSpec, SignatureKind, SignatureProblem,
    SignatureReport, SubFilter, TimestampInfo, TimestampRequestOptions, VerifyOptions, VerifyTask,
};

use napi_derive::napi;

/// Returns the version of the native Folioxide library, for example `"0.1.0"`.
///
/// It equals the version of the `folioxide` npm package.
#[napi]
pub fn version() -> String {
    folioxide::VERSION.to_owned()
}

/// Parses a PDF date string (ISO 32000-2 §7.9.4, leniently: partial dates such as `"D:2026"`,
/// a missing `D:`, the offset forms real files use) and returns it in RFC 3339 form, such as
/// `"2026-10-10T09:30:00+02:00"`, or `null` when the text is not a date.
///
/// A date whose offset from UT is unknown has no offset in the result (a local date-time).
#[napi]
pub fn pdf_date_to_iso(text: String) -> Option<String> {
    folioxide::PdfDate::parse(text.as_bytes()).map(|date| date.to_rfc3339())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hand-written TypeScript declarations of the npm package.
    const INDEX_D_TS: &str = include_str!("../index.d.ts");

    #[test]
    fn pdf_dates_convert_to_rfc3339() {
        assert_eq!(
            pdf_date_to_iso("D:20240229133005+05'30'".to_owned()).as_deref(),
            Some("2024-02-29T13:30:05+05:30")
        );
        assert_eq!(
            pdf_date_to_iso("D:2026".to_owned()).as_deref(),
            Some("2026-01-01T00:00:00")
        );
        assert_eq!(pdf_date_to_iso("yesterday".to_owned()), None);
    }

    /// `index.d.ts` lists every error code the binding can throw in its `ErrorCode` union, so
    /// the union cannot fall behind the core's `ErrorCode`.
    #[test]
    fn index_d_ts_lists_every_error_code() {
        let union = declaration(INDEX_D_TS, "export type ErrorCode =");
        for &code in folioxide::ErrorCode::ALL {
            let js = format!("'{}'", error::js_code(code));
            assert!(union.contains(&js), "index.d.ts ErrorCode lacks {js}");
        }
        assert!(union.contains(&format!("'{E_BUSY}'")));
        assert!(union.contains(&format!("'{E_CLOSED}'")));
    }

    /// `index.d.ts` lists every diagnostic kind in its `DiagnosticKind` union.
    #[test]
    fn index_d_ts_lists_every_diagnostic_kind() {
        let union = declaration(INDEX_D_TS, "export type DiagnosticKind =");
        for &kind in folioxide::DiagnosticKind::ALL {
            let js = format!("'{}'", kind.as_str());
            assert!(union.contains(&js), "index.d.ts DiagnosticKind lacks {js}");
        }
    }

    /// `index.d.ts` lists every problem code of the signature reports in its `ProblemCode`
    /// union, and the values of every report enum in theirs (the binding passes the core's
    /// strings through, so the unions must not fall behind the core).
    #[test]
    fn index_d_ts_lists_every_report_value() {
        let union = declaration(INDEX_D_TS, "export type ProblemCode =");
        for &code in folioxide::ProblemCode::ALL {
            let js = format!("'{}'", code.as_str());
            assert!(union.contains(&js), "index.d.ts ProblemCode lacks {js}");
        }
        let unions: [(&str, Vec<&str>); 4] = [
            (
                "export type Coverage =",
                [
                    folioxide::Coverage::EntireFile,
                    folioxide::Coverage::EntireRevision,
                    folioxide::Coverage::ContiguousBlockFromStart,
                    folioxide::Coverage::Unclear,
                ]
                .map(folioxide::Coverage::as_str)
                .to_vec(),
            ),
            (
                "export type ModificationLevel =",
                [
                    folioxide::ModificationLevel::None,
                    folioxide::ModificationLevel::LtaUpdates,
                    folioxide::ModificationLevel::FormFilling,
                    folioxide::ModificationLevel::Annotations,
                    folioxide::ModificationLevel::Other,
                ]
                .map(folioxide::ModificationLevel::as_str)
                .to_vec(),
            ),
            (
                "export type SignatureKind =",
                [
                    folioxide::SignatureKind::Signature,
                    folioxide::SignatureKind::DocTimeStamp,
                ]
                .map(folioxide::SignatureKind::as_str)
                .to_vec(),
            ),
            (
                "export type PadesLevel =",
                vec![
                    folioxide::PadesLevel::BB.as_str(),
                    folioxide::PadesLevel::BT.as_str(),
                ],
            ),
        ];
        for (start, values) in unions {
            let union = declaration(INDEX_D_TS, start);
            for value in values {
                assert!(
                    union.contains(&format!("'{value}'")),
                    "{start} lacks '{value}'"
                );
            }
        }
    }

    /// The hand-written JavaScript facade of the npm package.
    const INDEX_JS: &str = include_str!("../index.js");

    /// `signPdf`'s timestamp token budget and retry margin are the core's (M4 brief §3.5, D-8).
    #[test]
    fn index_js_timestamp_constants_are_the_cores() {
        for (name, value) in [
            ("DEFAULT_TSA_RESERVE", folioxide::DEFAULT_TSA_RESERVE),
            ("TSA_RETRY_MARGIN", folioxide::TSA_RETRY_MARGIN),
        ] {
            let line = format!("const {name} = {value}\n");
            assert!(INDEX_JS.contains(&line), "index.js lacks `{}`", line.trim());
        }
    }

    /// The TypeScript declarations `napi build` generates (`pnpm build`).
    const BINDING_D_TS: &str = include_str!("../binding.d.ts");

    /// The generated `binding.d.ts` types `SignatureProblem.code` as its `ProblemCode` union,
    /// which lists every core problem code (the binding's type-only `ProblemCode` enum keeps up
    /// with the core), so the type tests can check `Equal<binding.TimestampInfo, TimestampInfo>`.
    #[test]
    fn binding_d_ts_lists_every_problem_code() {
        let union = declaration(BINDING_D_TS, "export type ProblemCode =");
        for &code in folioxide::ProblemCode::ALL {
            let js = format!("'{}'", code.as_str());
            assert!(union.contains(&js), "binding.d.ts ProblemCode lacks {js}");
        }
        assert_eq!(
            union.matches('|').count() + 1,
            folioxide::ProblemCode::ALL.len(),
            "binding.d.ts ProblemCode has values the core does not: {union}"
        );
    }

    /// The text of the declaration that starts with `start`, up to the next blank line.
    fn declaration<'a>(source: &'a str, start: &str) -> &'a str {
        let from = source
            .find(start)
            .unwrap_or_else(|| panic!("index.d.ts has no `{start}`"));
        let rest = &source[from..];
        rest.find("\n\n").map_or(rest, |end| &rest[..end])
    }
}
