//! The attack corpus (M3 brief §5.1): the stage-1 byte-level generators of
//! `folioxide_testkit::fixtures::sign_attacks`, applied to a really signed file, and what the
//! reference validator (pyHanko 0.37) does with each case.
//!
//! The expected values of our own verifier are asserted by the `attacks_*` tests; the
//! `sign-attacks` oracle suite writes them into each case's expect.json, except where
//! [`DELIBERATE_DIFFERENCES`] says that Folioxide is deliberately stricter: there the expect
//! file carries pyHanko's value and the Rust test asserts ours.

use folioxide_model::Document;
use folioxide_sign::field::FieldSpec;
use folioxide_sign::prepare::SignatureOptions;
use folioxide_sign::sign::{SignRequest, sign};
use folioxide_syntax::{Object, OpenOptions};
use folioxide_testkit::fixtures::{sign_attacks as mutators, syntax};

/// A generator: the signed file in, the attacked file out (`None`: not applicable).
pub type Generator = fn(&[u8]) -> Option<Vec<u8>>;

/// What pyHanko does with a case (probed with `tools/oracles/validate_sig.py`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reference {
    /// pyHanko produces a status for every field; the oracle compares it.
    Status,
    /// pyHanko raises, or reports the signature not intact or not valid, and so do pdfsig and
    /// OpenSSL: the expect entry is `rejected: true` (DECISIONS D10 D-3).
    Rejected,
    /// pyHanko cannot read the file at all (it raises while following the cross-reference
    /// data, brief §5.1 "or raises"), while the signed bytes are untouched, so pdfsig and
    /// OpenSSL validate the signature: the attack is detected by coverage and modification
    /// (and `StructureRepaired`), not by rejection. The expect entry carries our values
    /// (intact and valid), and the pyHanko row is a `knownFailures` entry with the reason in
    /// [`PYHANKO_RAISES`].
    PyhankoRaises,
}

/// One case of the corpus.
pub struct AttackCase {
    /// The case name: the `attacks_<name>` test and the oracle case.
    pub name: &'static str,
    /// The generator.
    pub generate: Generator,
    /// What pyHanko does with it.
    pub reference: Reference,
    /// The signed file the generator attacks.
    pub base: Base,
}

/// The signed file an attack starts from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base {
    /// [`signed_base`]: our RSA-2048 signature on `minimal.pdf` (`/ByteRange` before
    /// `/Contents`, so the `/ByteRange` is in signed part 1).
    Ours,
    /// [`pyhanko_base`]: pyHanko's RSA-2048 signature on `minimal.pdf` (`/Contents` before
    /// `/ByteRange`, so the `/ByteRange` is in signed part 2), which signature wrapping needs.
    PyHanko,
    /// Our RSA-2048 signature on `minimal.pdf` prepared so that the trailer's `/Info` is the page
    /// content stream (expert finding 10).
    InfoAliasContent,
    /// Our RSA-2048 signature on `minimal.pdf` prepared so that the catalog's `/MarkInfo` is the
    /// page font.
    MarkInfoAliasFont,
    /// Our RSA-2048 signature on `minimal.pdf` prepared with a page annotation that is also the
    /// trailer's `/Info`.
    InfoAliasAnnotation,
    /// Our RSA-2048 signature on `minimal.pdf` prepared so that the page's `/Parent` is a
    /// page-tree node outside the `/Kids` tree that is also the trailer's `/Info` (expert
    /// finding: page-attribute inheritance).
    InfoAliasPageParent,
    /// The same with the catalog's `/MarkInfo` as the page's `/Parent`.
    MarkInfoAliasPageParent,
    /// Our RSA-2048 signature on `minimal.pdf` prepared with three visible, unsigned signature
    /// fields and an AcroForm `/DR` (QA finding: an existing field that stays unsigned).
    UnsignedFields,
    /// Our RSA-2048 signature on `minimal.pdf` prepared with a text field whose signed
    /// appearance shows "100 EUR" while its value is "900 EUR", and an AcroForm with `/DA` and
    /// `/DR` (expert finding: the AcroForm's appearance controls).
    TextField,
    /// The same with `/NeedAppearances true` in the AcroForm: viewers show the field as they
    /// construct it from its value, "900 EUR" (expert finding: removing it later shows the stale
    /// "100 EUR").
    TextFieldNeedAppearances,
    /// The same text field without an appearance stream, in an AcroForm without `/DA` (expert
    /// finding: a `/DA` added later decides how the field is drawn).
    TextFieldNoAppearance,
    /// The same text field with an AcroForm `/DA` that selects `/Helv` while `/DR /Font` is empty
    /// (a font name that does not resolve when the document is signed).
    TextFieldDaFontMissing,
    /// The text field of [`Base::TextFieldNoAppearance`] with an `/AP` whose `/N` is an indirect
    /// dictionary that is no stream (expert finding, round 5).
    TextFieldApNotStream,
    /// The text field of [`Base::TextFieldNoAppearance`] as an orphan widget: on the page but not
    /// in `/Fields`, which lists a second text field with an appearance stream (expert finding,
    /// round 5).
    OrphanTextWidget,
    /// [`Base::OrphanTextWidget`] with the orphan widget's own `/DA (/F7 20 Tf 0 g)`, a font
    /// name `/DR` lacks (expert finding, round 5, `u_orphan_f7`).
    OrphanTextWidgetDaFont,
    /// Our RSA-2048 signature on `minimal.pdf` prepared with a trailer `/Info` dictionary and a
    /// catalog `/Metadata` XMP stream (QA finding: role objects the new revision no longer
    /// points to).
    InfoMetadata,
}

impl Base {
    /// The signed file.
    pub fn bytes(self) -> Vec<u8> {
        let aliased = |prepare: fn(&[u8]) -> Option<Vec<u8>>| {
            let input = prepare(&syntax::minimal()).expect("the alias input applies");
            super::sign_default(&input, &super::rsa2048())
        };
        match self {
            Base::Ours => signed_base(),
            Base::PyHanko => pyhanko_base(),
            Base::InfoAliasContent => aliased(mutators::info_alias_content_input),
            Base::MarkInfoAliasFont => aliased(mutators::markinfo_alias_font_input),
            Base::InfoAliasAnnotation => aliased(mutators::info_alias_annotation_input),
            Base::InfoAliasPageParent => aliased(mutators::info_alias_page_parent_input),
            Base::MarkInfoAliasPageParent => aliased(mutators::markinfo_alias_page_parent_input),
            Base::UnsignedFields => aliased(mutators::unsigned_sig_fields_input),
            Base::TextField => aliased(mutators::text_field_form_input),
            Base::TextFieldNeedAppearances => aliased(mutators::text_field_need_appearances_input),
            Base::TextFieldNoAppearance => aliased(mutators::text_field_no_appearance_input),
            Base::TextFieldDaFontMissing => aliased(mutators::text_field_da_font_missing_input),
            Base::TextFieldApNotStream => aliased(mutators::text_field_ap_not_stream_input),
            Base::OrphanTextWidget => aliased(mutators::orphan_text_widget_input),
            Base::OrphanTextWidgetDaFont => aliased(mutators::orphan_text_widget_da_font_input),
            Base::InfoMetadata => aliased(mutators::info_metadata_input),
        }
    }

    /// The index of the signed revision: the base revision, the preparing revision when there
    /// is one, then the signature.
    pub fn signed_revision(self) -> usize {
        match self {
            Base::Ours | Base::PyHanko => 1,
            Base::InfoAliasContent
            | Base::MarkInfoAliasFont
            | Base::InfoAliasAnnotation
            | Base::InfoAliasPageParent
            | Base::MarkInfoAliasPageParent
            | Base::UnsignedFields
            | Base::TextField
            | Base::TextFieldNeedAppearances
            | Base::TextFieldNoAppearance
            | Base::TextFieldDaFontMissing
            | Base::TextFieldApNotStream
            | Base::OrphanTextWidget
            | Base::OrphanTextWidgetDaFont
            | Base::InfoMetadata => 2,
        }
    }
}

/// `fixtures/sign/pdf/pyhanko-rsa2048.pdf`: pyHanko's layout of the signature dictionary.
pub fn pyhanko_base() -> Vec<u8> {
    std::fs::read(super::repo().join("fixtures/sign/pdf/pyhanko-rsa2048.pdf"))
        .unwrap_or_else(|e| panic!("pyhanko-rsa2048.pdf: {e}"))
}

/// The field of the attacked signature in every corpus case (each base signs `Signature1`).
pub const ATTACKED_FIELD: &str = "Signature1";

/// The field of a co-signer's later, legitimate signature in a corpus case
/// (`cosigner_removes_need_appearances`).
pub const COSIGNER_FIELD: &str = "CoSigner";

/// Where Folioxide deliberately differs from pyHanko (brief §0): `(case, field, ours, pyhanko,
/// reason)`, for the attacked signature ([`ATTACKED_FIELD`]; a co-signer's later signature in
/// the same case is compared as it is). The expect file carries pyHanko's value; the Rust test
/// asserts ours. Every difference is in the stricter direction.
pub const DELIBERATE_DIFFERENCES: &[(&str, &str, &str, &str, &str)] = &[
    (
        "isa_objects_without_xref",
        "modification",
        "other",
        "none",
        "D-9: objects after the last %%EOF that no startxref reaches are an UnreferencedUpdate \
         repair, which cannot be attributed to a revision (probe A_noxref)",
    ),
    (
        "isa_xref_without_trailer",
        "modification",
        "other",
        "none",
        "D-9: an xref section without trailer or startxref after the last %%EOF is an \
         UnreferencedUpdate repair",
    ),
    (
        "isa_hybrid_table_vs_xrefstm",
        "modification",
        "other",
        "ltaUpdates",
        "V10 union: the hybrid update's table lists the content stream at a byte-identical copy \
         and its cross-reference stream at another stream; readers differ on which half they \
         use, so the disagreement itself is OTHER. pyHanko reads the table, finds an identical \
         object and reports LTA_UPDATES (expert finding 13, atk_hybrid)",
    ),
    (
        "isa_objstm_container_overwritten",
        "modification",
        "other",
        "none",
        "D-9: the stage-1 generator appends an update that no startxref reaches \
         (UnreferencedUpdate repair); pyHanko ignores it",
    ),
    (
        "shadow_short_length_in_update",
        "modification",
        "other",
        "none",
        "D-9: the update with the short /Length is reached by no startxref \
         (UnreferencedUpdate repair); pyHanko ignores it",
    ),
    (
        "shadow_info_alias_page_parent",
        "modification",
        "other",
        "ltaUpdates",
        "V10 roles: the trailer /Info dictionary is also the page's /Parent (outside the /Kids \
         tree), so the page inherits its /Resources (ISO 32000-2 7.7.3.4) in pdf.js, MuPDF and \
         pdfium; changing it replaces the rendered font. pyHanko skips /Parent in its usage \
         paths and reports LTA_UPDATES (expert finding, atk_parent)",
    ),
    (
        "shadow_markinfo_alias_page_parent",
        "modification",
        "other",
        "ltaUpdates",
        "V10 roles: the catalog /MarkInfo dictionary is also the page's /Parent, so the page \
         inherits its /Resources in pdf.js, MuPDF and pdfium; pyHanko skips /Parent in its usage \
         paths and reports LTA_UPDATES (expert finding, atk_mi_parent)",
    ),
    (
        "shadow_acroform_need_appearances_set",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (3) whitelist: setting the AcroForm's /NeedAppearances makes viewers regenerate the \
         signed fields' appearances from their values (poppler and MuPDF draw the text field's \
         /V '900 EUR' instead of the signed '100 EUR'); no signer sets it. pyHanko exempts the \
         key from its AcroForm comparison and reports LTA_UPDATES (expert finding, mk_na)",
    ),
    (
        "shadow_acroform_da_changed",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (3) whitelist: changing the AcroForm's existing /DA changes how viewers regenerate \
         every field without its own (here white text); a later signer may only add a /DA where \
         there is none. pyHanko exempts the key and reports LTA_UPDATES (expert finding, \
         atk_da_white)",
    ),
    (
        "shadow_acroform_dr_name_replaced",
        "modification",
        "other",
        "formFilling",
        "V10 (3) whitelist: /DR may only gain names; re-pointing the existing /Helv (the font \
         the /DA selects) to another font changes regenerated appearances. pyHanko clears what a \
         new /DR holds at FORM_FILLING (expert finding, atk_dr_font)",
    ),
    (
        "shadow_acroform_need_appearances_removed_stale_ap",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (3) whitelist: the signed revision has /NeedAppearances true, so viewers showed the \
         text field as they constructed it from its /V ('900 EUR'); removing the key makes them \
         show the stale stored appearance ('100 EUR', poppler), a shadow Hide-and-Reveal. Any \
         change to /NeedAppearances is OTHER, so the earlier signatures of a document whose \
         later signer removed it (pyHanko's signer deletes it when it signs; pyHanko then reports \
         FORM_FILLING for them) are OTHER too. pyHanko exempts the key and reports LTA_UPDATES \
         (expert finding, mk2 b_na_stale / u_na_removed)",
    ),
    (
        "cosigner_removes_need_appearances",
        "modification",
        "other",
        "formFilling",
        "V10 (3) whitelist, the consequence of shadow_acroform_need_appearances_removed_stale_ap: \
         a later signer whose signing revision removes /NeedAppearances true (pyHanko's signer \
         always does) makes the earlier signatures OTHER, because the earlier signer saw the \
         constructed appearances and the stored ones may be stale. pyHanko exempts the key and \
         reports FORM_FILLING for the new signature (checked on pyHanko co-signed files, round 4)",
    ),
    (
        "acroform_need_appearances_false_added",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (3) whitelist: any change to /NeedAppearances is OTHER, even /NeedAppearances false \
         added where the key was absent (which means false); the rule does not judge values. \
         pyHanko exempts the key and reports LTA_UPDATES",
    ),
    (
        "shadow_acroform_da_removed",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (3) whitelist: removing the AcroForm's /DA changes how viewers construct the \
         appearance of every field without its own; only adding a /DA where there is none can be \
         form filling. pyHanko exempts the key and reports LTA_UPDATES",
    ),
    (
        "shadow_acroform_da_added_noap",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (3) whitelist: the signed text field has neither an appearance stream nor a /DA of \
         its own, so the AcroForm /DA added later (white text) decides how viewers draw it \
         (MuPDF: 138 dark pixels before, 0 after); any change to the AcroForm's /DA is OTHER. \
         pyHanko exempts the key and reports LTA_UPDATES (expert finding, s_b_noap_noda / \
         u_da_added_white)",
    ),
    (
        "shadow_acroform_da_added_ap_not_stream",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (3) whitelist: the signed text field's /AP /N is a dictionary that is no stream, so \
         viewers have no appearance to draw and use the AcroForm /DA added later (white text); \
         any change to the AcroForm's /DA is OTHER. pyHanko exempts the key and reports \
         LTA_UPDATES for this indirect plain dictionary, and raises IndirectObjectExpected when \
         /N is a direct empty or state dictionary or an integer (expert finding, round 5, \
         u_n_plaindict, u_n_emptydict, u_n_statedict, u_n_int)",
    ),
    (
        "shadow_acroform_da_added_orphan_widget",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (3) whitelist: the signed text widget is on the page but not in /Fields; viewers \
         draw it with the AcroForm /DA added later (white text); any change to the AcroForm's \
         /DA is OTHER. pyHanko exempts the key and reports LTA_UPDATES (expert finding, round \
         5, u_orphan)",
    ),
    (
        "acroform_da_added",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (3) whitelist: an added /DA can restyle any field that viewers regenerate, and \
         deciding which fields are safe proved unreliable (expert findings, rounds 4 and 5: \
         fields without an appearance stream, an /AP /N that is no stream, widgets outside \
         /Fields), so any change to the AcroForm's /DA is OTHER, even here where the only field \
         is the signature field. pyHanko exempts the key from its AcroForm comparison and \
         reports LTA_UPDATES",
    ),
    (
        "shadow_acroform_q_changed",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (3) whitelist: the AcroForm's /Q is the quadding of every field without its own; \
         changing it moves the text of constructed appearances, and no signer changes it. \
         pyHanko exempts the key and reports LTA_UPDATES",
    ),
    (
        "shadow_acroform_dr_name_removed",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (3) whitelist: /DR may only gain names; removing /Helv (the font the /DA selects) \
         changes the font of constructed appearances. pyHanko exempts the direct /DR from its \
         AcroForm comparison and, with no new object to clear, reports LTA_UPDATES (FORM_FILLING \
         when the update also adds an object to /DR)",
    ),
    (
        "shadow_acroform_dr_da_font_added",
        "modification",
        "other",
        "formFilling",
        "V10 (3) whitelist: the signed /DA selects /Helv, which /DR did not have; adding it later \
         makes the name resolve to a font of the update's choosing, as a dangling reference that \
         now resolves would. pyHanko clears what a new /DR holds at FORM_FILLING",
    ),
    (
        "shadow_acroform_dr_font_orphan_widget_da",
        "modification",
        "other",
        "formFilling",
        "V10 (3) whitelist: the signed orphan text widget (on the page, not in /Fields) has its \
         own /DA selecting /F7, which /DR did not have; adding it later makes the name resolve \
         to a font of the update's choosing (poppler then shows other text). The /DR guard reads \
         the /DA of every annotation on every page of the signed revision, not only the field \
         tree's. pyHanko clears what a new /DR holds at FORM_FILLING (expert finding, round 5, \
         u_orphan_f7)",
    ),
    (
        "shadow_acroform_dr_encoding_added",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (3) whitelist: /DR may only gain names in its resource categories (/Font /XObject \
         /ColorSpace /ExtGState /Pattern /Shading /ProcSet); a new /Encoding changes how \
         constructed text maps to glyphs. pyHanko exempts /DR and reports LTA_UPDATES. Acrobat \
         writes /DR /Encoding: check a real Acrobat co-signed sample before M4",
    ),
    (
        "form_field_value_changed",
        "modification",
        "other",
        "formFilling",
        "D-9: M3 does not classify changes to form fields other than signature fields, so a new \
         /V for the text field is OTHER until M4 WP4.2; pyHanko's field rules allow it at \
         FORM_FILLING",
    ),
    (
        "dss_added",
        "modification",
        "other",
        "ltaUpdates",
        "D-9: M3 does not classify the document security store, so a /DSS added to the catalog \
         is OTHER until M11; pyHanko's DSSCompareRule allows it at LTA_UPDATES",
    ),
    (
        "shadow_info_removed_old_changed",
        "modification",
        "other",
        "ltaUpdates",
        "V10 roles: the update drops the trailer's /Info and changes the dictionary it named; a \
         role is granted only while the newest trailer names the object. pyHanko's trailer view \
         inherits /Info from the older trailer, takes the changed dictionary for the current \
         /Info and reports LTA_UPDATES (QA finding, role_info_removed_old_changed)",
    ),
    (
        "shadow_new_sig_field_aa_direct",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (1) whitelist: no signer gives its new signature field additional actions; a \
         JavaScript /AA on a new invisible field runs on page open. pyHanko clears the field at \
         LTA_UPDATES (QA finding, role_inv_AA_js)",
    ),
    (
        "shadow_new_sig_field_a_javascript",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (1) whitelist: no signer gives its new signature field an action (/A JavaScript); \
         pyHanko clears the field at LTA_UPDATES (QA finding, role_inv_A_js)",
    ),
    (
        "shadow_new_sig_field_a_launch",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (1) whitelist: no signer gives its new signature field an action (/A Launch); \
         pyHanko clears the field at LTA_UPDATES (QA finding, role_inv_A_launch)",
    ),
    (
        "shadow_new_sig_field_a_uri",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (1) whitelist: no signer gives its new signature field an action (/A URI); pyHanko \
         clears the field at LTA_UPDATES (QA finding, role_inv_A_uri)",
    ),
    (
        "shadow_new_sig_field_parent",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (1) whitelist: a new root-level signature field has no /Parent; one whose /Parent is \
         the signed field inherits its /FT and /V (ISO 32000-2 12.7.4.1), so a viewer may show the \
         new widget as signed by the earlier signature. pyHanko clears the field at LTA_UPDATES",
    ),
    (
        "shadow_new_sig_field_oc",
        "modification",
        "other",
        "ltaUpdates",
        "V10 (1) whitelist: no signer gives its new signature field optional content (/OC); \
         pyHanko clears the field at LTA_UPDATES (QA finding, role_inv_with_OC)",
    ),
    (
        "swa_sig_dict_redefined_in_update",
        "coverage",
        "unclear",
        "contiguousBlockFromStart",
        "V4/V5: the newest definition's /Contents token is in the update, not in the \
         /ByteRange gap; pyHanko compares only the gap's length with the /Contents length",
    ),
];

/// The cases pyHanko 0.37 cannot read ([`Reference::PyhankoRaises`]), with what it raises
/// (probed with `tools/oracles/validate_sig.py`). Folioxide reads them leniently, finds the
/// signature intact and valid, and reports the attack as a repaired structure whose changes
/// cannot be attributed (D-9; brief §5.1: pyHanko "NONE or raises").
pub const PYHANKO_RAISES: &[(&str, &str)] = &[
    (
        "isa_bad_startxref_update",
        "pyHanko 0.37 cannot read the file (PdfStreamError: its last startxref points past the \
         end of the file, and pyHanko does not reconstruct cross-reference data); Folioxide \
         repairs it and reports other + structureRepaired (D-9; brief 5.1: NONE or raises)",
    ),
    (
        "isa_prev_skips_signed_revision",
        "pyHanko 0.37 cannot read the file (ValueError: the appended trailer's /Prev 0 is not a \
         cross-reference section); Folioxide repairs it and reports contiguousBlockFromStart + \
         signedRevisionNotInChain + other (brief 5.1: CONTIGUOUS or raises)",
    ),
];

/// Why pyHanko cannot read the file of `case`, if it is a [`Reference::PyhankoRaises`] case.
pub fn pyhanko_raises(case: &str) -> Option<&'static str> {
    PYHANKO_RAISES
        .iter()
        .find(|(c, _)| *c == case)
        .map(|(_, reason)| *reason)
}

/// The value of `field` for `case` that the expect file carries instead of ours, if the case
/// has a deliberate difference there.
pub fn pyhanko_value(case: &str, field: &str) -> Option<&'static str> {
    DELIBERATE_DIFFERENCES
        .iter()
        .find(|(c, f, ..)| *c == case && *f == field)
        .map(|(_, _, _, pyhanko, _)| *pyhanko)
}

/// Our value of `field` for `case` when the case has a deliberate difference there.
pub fn our_value(case: &str, field: &str) -> Option<&'static str> {
    DELIBERATE_DIFFERENCES
        .iter()
        .find(|(c, f, ..)| *c == case && *f == field)
        .map(|(_, _, ours, _, _)| *ours)
}

/// The signed file the corpus attacks: `minimal.pdf` signed with RSA-2048 (our layout: the
/// `/ByteRange` precedes `/Contents`).
pub fn signed_base() -> Vec<u8> {
    super::sign_default(&syntax::minimal(), &super::rsa2048())
}

/// Every case, in the order of brief §5.1.
pub fn corpus() -> Vec<AttackCase> {
    use Reference::{PyhankoRaises, Rejected, Status};
    let case = |name, generate, reference| AttackCase {
        name,
        generate,
        reference,
        base: Base::Ours,
    };
    let on_pyhanko = |name, generate, reference| AttackCase {
        name,
        generate,
        reference,
        base: Base::PyHanko,
    };
    let on = |base, name, generate| AttackCase {
        name,
        generate,
        reference: Status,
        base,
    };
    vec![
        case(
            "usf_contents_missing",
            mutators::usf_contents_missing as Generator,
            Rejected,
        ),
        case("usf_contents_null", mutators::usf_contents_null, Rejected),
        case(
            "usf_contents_empty_hex",
            mutators::usf_contents_empty_hex,
            Rejected,
        ),
        case(
            "usf_contents_literal_string",
            mutators::usf_contents_literal_string,
            Rejected,
        ),
        case(
            "usf_byterange_missing",
            mutators::usf_byterange_missing,
            Rejected,
        ),
        case("usf_byterange_null", mutators::usf_byterange_null, Rejected),
        case(
            "usf_byterange_two_values",
            mutators::usf_byterange_two_values,
            Rejected,
        ),
        case(
            "usf_byterange_negative",
            mutators::usf_byterange_negative,
            Rejected,
        ),
        case(
            "usf_byterange_not_from_zero",
            mutators::usf_byterange_not_from_zero,
            Rejected,
        ),
        case(
            "usf_byterange_past_eof",
            mutators::usf_byterange_past_eof,
            Rejected,
        ),
        case(
            "usf_byterange_reals",
            mutators::usf_byterange_reals,
            Rejected,
        ),
        case(
            "usf_byterange_indirect",
            mutators::usf_byterange_indirect,
            Rejected,
        ),
        case(
            "usf_byterange_zeroes",
            mutators::usf_byterange_zeroes,
            Rejected,
        ),
        // pyHanko lists no signature with an unknown /SubFilter, pdfsig cannot validate it and
        // the OpenSSL route fails: every oracle rejects it (D-3 accepts "pyHanko does not list
        // the field"); Folioxide lists it with unsupportedSubFilter.
        case(
            "usf_subfilter_unknown",
            mutators::usf_subfilter_unknown,
            Rejected,
        ),
        case("usf_cms_garbage", mutators::usf_cms_garbage, Rejected),
        case(
            "usf_cms_two_signerinfos",
            mutators::usf_cms_two_signerinfos,
            Rejected,
        ),
        case(
            "usf_cms_no_certificates",
            mutators::usf_cms_no_certificates,
            Rejected,
        ),
        case(
            "usf_cms_econtent_present",
            mutators::usf_cms_econtent_present,
            Rejected,
        ),
        case("usf_ess_mismatch", mutators::usf_ess_mismatch, Status),
        case(
            "usf_content_type_missing",
            mutators::usf_cms_content_type_corrupt,
            Rejected,
        ),
        case(
            "isa_classic_content_replaced",
            mutators::isa_classic_content_replaced,
            Status,
        ),
        case(
            "isa_objects_without_xref",
            mutators::isa_objects_without_xref,
            Status,
        ),
        case(
            "isa_xref_without_trailer",
            mutators::isa_xref_without_trailer,
            Status,
        ),
        case(
            "isa_bad_startxref_update",
            mutators::isa_bad_startxref_update,
            PyhankoRaises,
        ),
        case(
            "isa_prev_skips_signed_revision",
            mutators::isa_prev_skips_signed_revision,
            PyhankoRaises,
        ),
        case("isa_free_object", mutators::isa_free_object, Status),
        case(
            "isa_relist_identical",
            mutators::isa_relist_identical,
            Status,
        ),
        case("isa_info_only", mutators::isa_info_only, Status),
        case(
            "isa_hybrid_table_vs_xrefstm",
            mutators::isa_hybrid_table_vs_xrefstm,
            Status,
        ),
        case(
            "isa_objstm_container_overwritten",
            mutators::isa_objstm_container_overwritten,
            Status,
        ),
        // The CCS 2019 wrapping attack on pyHanko's layout: intact and valid, wrapped.
        on_pyhanko("swa_part2_moved", mutators::swa_part2_moved, Status),
        // The naive attempt (bytes inserted inside part 2): not intact for anyone.
        case("swa_part2_shifted", mutators::swa_part2_shifted, Rejected),
        // pyHanko: intact False; extract_cms cannot extract the CMS from the new gap.
        case(
            "swa_gap_points_at_other_contents",
            mutators::swa_gap_points_at_other_contents,
            Rejected,
        ),
        case(
            "swa_two_dicts_same_byterange",
            mutators::swa_two_dicts_same_byterange,
            Status,
        ),
        case(
            "swa_sig_dict_redefined_in_update",
            mutators::swa_sig_dict_redefined_in_update,
            Status,
        ),
        case(
            "shadow_hide_overlay_removed",
            mutators::shadow_hide_overlay_removed,
            Status,
        ),
        case(
            "shadow_hide_repoint_to_signed_bytes",
            mutators::shadow_hide_repoint_to_signed_bytes,
            Status,
        ),
        case("shadow_replace_font", mutators::shadow_replace_font, Status),
        case(
            "shadow_replace_field_value",
            mutators::shadow_replace_field_value,
            Rejected,
        ),
        case("shadow_root_switch", mutators::shadow_root_switch, Status),
        case(
            "shadow_short_length_in_update",
            mutators::shadow_short_length_in_update,
            Status,
        ),
        // Overlays and new signature fields appended after signing (QA findings 3, 9, 11; the
        // differential against pyHanko for the "append an annotation" class).
        case(
            "shadow_overlay_sig_widget_registered",
            mutators::shadow_overlay_sig_widget_registered,
            Status,
        ),
        case(
            "shadow_overlay_sig_widget_rect_indirect",
            mutators::shadow_overlay_sig_widget_rect_indirect,
            Status,
        ),
        case(
            "shadow_overlay_widget_page_only",
            mutators::shadow_overlay_widget_page_only,
            Status,
        ),
        case(
            "shadow_overlay_stamp_ft_sig",
            mutators::shadow_overlay_stamp_ft_sig,
            Status,
        ),
        case(
            "shadow_overlay_sig_widget_no_rect",
            mutators::shadow_overlay_sig_widget_no_rect,
            Status,
        ),
        case(
            "shadow_overlay_sig_widget_zero_width",
            mutators::shadow_overlay_sig_widget_zero_width,
            Status,
        ),
        case(
            "shadow_new_sig_field_aa_indirect",
            mutators::shadow_new_sig_field_aa_indirect,
            Status,
        ),
        case(
            "shadow_new_sig_field_aa_direct",
            mutators::shadow_new_sig_field_aa_direct,
            Status,
        ),
        case(
            "shadow_new_sig_field_ap",
            mutators::shadow_new_sig_field_ap,
            Status,
        ),
        // New signature fields with actions or optional content (QA finding, round 3: the
        // whitelist refuses them; deliberately stricter than pyHanko), and the /MK control.
        case(
            "shadow_new_sig_field_a_javascript",
            mutators::shadow_new_sig_field_a_javascript,
            Status,
        ),
        case(
            "shadow_new_sig_field_a_launch",
            mutators::shadow_new_sig_field_a_launch,
            Status,
        ),
        case(
            "shadow_new_sig_field_a_uri",
            mutators::shadow_new_sig_field_a_uri,
            Status,
        ),
        case(
            "shadow_new_sig_field_oc",
            mutators::shadow_new_sig_field_oc,
            Status,
        ),
        case(
            "shadow_new_sig_field_parent",
            mutators::shadow_new_sig_field_parent,
            Status,
        ),
        case("new_sig_field_mk", mutators::new_sig_field_mk, Status),
        // The AcroForm's appearance controls (expert finding, round 3).
        on(
            Base::TextField,
            "shadow_acroform_need_appearances_set",
            mutators::shadow_acroform_need_appearances_set as Generator,
        ),
        on(
            Base::TextField,
            "shadow_acroform_da_changed",
            mutators::shadow_acroform_da_changed,
        ),
        on(
            Base::TextField,
            "shadow_acroform_dr_name_replaced",
            mutators::shadow_acroform_dr_name_replaced,
        ),
        on(
            Base::TextField,
            "acroform_dr_name_added",
            mutators::acroform_dr_name_added,
        ),
        on(Base::Ours, "acroform_da_added", mutators::acroform_da_added),
        // Every other stricter AcroForm result (expert and QA findings, round 4).
        on(
            Base::TextFieldNeedAppearances,
            "shadow_acroform_need_appearances_removed_stale_ap",
            mutators::shadow_acroform_need_appearances_removed_stale_ap,
        ),
        on(
            Base::TextFieldNeedAppearances,
            "cosigner_removes_need_appearances",
            cosigner_removes_need_appearances,
        ),
        on(
            Base::TextField,
            "acroform_need_appearances_false_added",
            mutators::acroform_need_appearances_false_added,
        ),
        on(
            Base::TextField,
            "shadow_acroform_da_removed",
            mutators::shadow_acroform_da_removed,
        ),
        on(
            Base::TextFieldNoAppearance,
            "shadow_acroform_da_added_noap",
            mutators::shadow_acroform_da_added_noap,
        ),
        // The /DA-added exception's bypasses and the /DR guard's (expert findings, round 5).
        on(
            Base::TextFieldApNotStream,
            "shadow_acroform_da_added_ap_not_stream",
            mutators::shadow_acroform_da_added_ap_not_stream,
        ),
        on(
            Base::OrphanTextWidget,
            "shadow_acroform_da_added_orphan_widget",
            mutators::shadow_acroform_da_added_orphan_widget,
        ),
        on(
            Base::OrphanTextWidgetDaFont,
            "shadow_acroform_dr_font_orphan_widget_da",
            mutators::shadow_acroform_dr_font_orphan_widget_da,
        ),
        on(
            Base::TextField,
            "shadow_acroform_q_changed",
            mutators::shadow_acroform_q_changed,
        ),
        on(
            Base::TextField,
            "shadow_acroform_dr_name_removed",
            mutators::shadow_acroform_dr_name_removed,
        ),
        on(
            Base::TextFieldDaFontMissing,
            "shadow_acroform_dr_da_font_added",
            mutators::shadow_acroform_dr_da_font_added,
        ),
        on(
            Base::TextField,
            "shadow_acroform_dr_encoding_added",
            mutators::shadow_acroform_dr_encoding_added,
        ),
        // Classes M3 does not classify yet (DECISIONS D10 D-9): generic form filling and the
        // document security store.
        on(
            Base::TextField,
            "form_field_value_changed",
            mutators::form_field_value_changed,
        ),
        on(Base::Ours, "dss_added", mutators::dss_added),
        // Role objects the new revision no longer points to (QA finding, round 3).
        on(
            Base::InfoMetadata,
            "shadow_info_repoint_old_changed",
            mutators::shadow_info_repoint_old_changed,
        ),
        on(
            Base::InfoMetadata,
            "shadow_info_removed_old_changed",
            mutators::shadow_info_removed_old_changed,
        ),
        on(
            Base::InfoMetadata,
            "info_changed_in_place",
            mutators::info_changed_in_place,
        ),
        on(
            Base::InfoMetadata,
            "shadow_metadata_repoint_old_changed",
            mutators::shadow_metadata_repoint_old_changed,
        ),
        on(
            Base::InfoMetadata,
            "shadow_metadata_removed_old_changed",
            mutators::shadow_metadata_removed_old_changed,
        ),
        on(
            Base::InfoMetadata,
            "metadata_changed_in_place",
            mutators::metadata_changed_in_place,
        ),
        // One object with two roles in the signed revision (expert finding 10).
        on(
            Base::InfoAliasContent,
            "shadow_info_alias_content",
            mutators::shadow_info_alias_content as Generator,
        ),
        on(
            Base::MarkInfoAliasFont,
            "shadow_markinfo_alias_font",
            mutators::shadow_markinfo_alias_font,
        ),
        on(
            Base::InfoAliasAnnotation,
            "shadow_info_alias_annotation",
            mutators::shadow_info_alias_annotation,
        ),
        // A role object that is also a page's /Parent (expert finding: page-attribute
        // inheritance; deliberately stricter than pyHanko).
        on(
            Base::InfoAliasPageParent,
            "shadow_info_alias_page_parent",
            mutators::shadow_info_alias_page_parent,
        ),
        on(
            Base::MarkInfoAliasPageParent,
            "shadow_markinfo_alias_page_parent",
            mutators::shadow_markinfo_alias_page_parent,
        ),
        // Existing signature fields that stay unsigned (QA finding: pyHanko allows /AP, /AS
        // and /F changes only when the revision signs the field).
        on(
            Base::UnsignedFields,
            "shadow_unsigned_field_ap_added",
            mutators::shadow_unsigned_field_ap_added,
        ),
        on(
            Base::UnsignedFields,
            "shadow_unsigned_field_ap_repointed",
            mutators::shadow_unsigned_field_ap_repointed,
        ),
        on(
            Base::UnsignedFields,
            "shadow_unsigned_field_hidden",
            mutators::shadow_unsigned_field_hidden,
        ),
        on(
            Base::UnsignedFields,
            "shadow_unsigned_field_as_added",
            mutators::shadow_unsigned_field_as_added,
        ),
        on(
            Base::UnsignedFields,
            "shadow_unsigned_field_parent_ap",
            mutators::shadow_unsigned_field_parent_ap,
        ),
        on(
            Base::UnsignedFields,
            "unsigned_field_flags_only",
            mutators::unsigned_field_flags_only,
        ),
        on(
            Base::UnsignedFields,
            "acroform_dr_removed",
            mutators::acroform_dr_removed,
        ),
    ]
}

/// `cosigner_removes_need_appearances`: on [`Base::TextFieldNeedAppearances`], a second
/// signature (ours, P-256, field `CoSigner`) whose signing revision also removes the AcroForm's
/// `/NeedAppearances true`, as pyHanko's signer does whenever it signs (`ensure_sig_flags`): the
/// pyHanko co-signing flow, which makes the first signature `Other` (stricter than pyHanko,
/// which reports `FORM_FILLING`). `None` without an indirect AcroForm with the key.
fn cosigner_removes_need_appearances(pdf: &[u8]) -> Option<Vec<u8>> {
    let mut doc = Document::open(pdf.to_vec(), &OpenOptions::default()).ok()?;
    let store = doc.store_mut();
    let root = store.root_id()?;
    let acroform = store.resolve(root).ok()?.as_dict()?.get_ref(b"AcroForm")?;
    let mut dict = store.resolve(acroform).ok()?.as_dict()?.clone();
    dict.remove(b"NeedAppearances".as_slice())?;
    store.set(acroform, Object::Dict(dict)).ok()?;
    let options = SignatureOptions::new(super::time())
        .with_field(FieldSpec::new().with_name(Some(COSIGNER_FIELD.into())));
    let signer = super::p256();
    sign(
        &doc,
        &SignRequest::new(&signer, super::time()).with_options(options),
    )
    .ok()
}

/// The attacked file of `name`.
pub fn attacked(name: &str) -> Vec<u8> {
    let case = corpus()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no case {name}"));
    (case.generate)(&case.base.bytes()).unwrap_or_else(|| panic!("{name} does not apply"))
}
