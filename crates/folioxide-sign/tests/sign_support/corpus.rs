//! The attack corpus (M3 brief §5.1): the stage-1 byte-level generators of
//! `folioxide_testkit::fixtures::sign_attacks`, applied to a really signed file, and what the
//! reference validator (pyHanko 0.37) does with each case.
//!
//! The expected values of our own verifier are asserted by the `attacks_*` tests; the
//! `sign-attacks` oracle suite writes them into each case's expect.json, except where
//! [`DELIBERATE_DIFFERENCES`] says that Folioxide is deliberately stricter: there the expect
//! file carries pyHanko's value and the Rust test asserts ours.

use folioxide_model::Document;
use folioxide_sign::docmdp::DocMdpPermissions;
use folioxide_sign::field::{FieldMode, FieldSpec};
use folioxide_sign::prepare::SignatureOptions;
use folioxide_sign::sign::{SignRequest, sign};
use folioxide_syntax::{Dict, Object, OpenOptions};
use folioxide_testkit::fixtures::{forms, sign_attacks as mutators, syntax};

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
    /// data, brief §5.1 "or raises", or reading a number written with two signs, M4 QA round
    /// 3), while the signed bytes are untouched, so pdfsig and OpenSSL validate the signature:
    /// the attack is detected by coverage and modification (and `StructureRepaired` for the
    /// cross-reference attacks), not by rejection. The expect entry carries our values
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
    /// M4: our RSA-2048 approval signature on the form document `forms::acroform` (M4 brief
    /// §3.4).
    Form,
    /// The same on `forms::acroform_tagged` (the widgets in the structure tree, D-24).
    FormTagged,
    /// The form prepared with the text field `Amount` hidden (`/F 6`).
    FormHidden,
    /// The form prepared with `Amount` ReadOnly.
    FormReadOnly,
    /// The form prepared with an XFA form in the AcroForm.
    FormXfa,
    /// The form prepared with an orphan check box widget (on the page, in no field tree).
    FormOrphanWidget,
    /// The form prepared so that the page also draws `Amount`'s appearance stream.
    FormApSharedWithPage,
    /// The form prepared with a text field `Split` whose widget is a separate kid.
    FormSplit,
    /// The form signed (raw) with FieldMDP: `/Lock` on the field and a `/Reference` FieldMDP
    /// locking `Country`.
    FormFieldMdp,
    /// `minimal.pdf` prepared with a reviewer's square annotation, then certified by our
    /// RSA-2048 signature with `P = 3` (M4 brief §5.2).
    CertifiedP3Annotated,
    /// Our RSA-2048 approval signature on `forms::rotated_pages` (pages rotated by 0, 90, 180
    /// and 270; M4 QA round 1, ruling R-3).
    RotatedPages,
    /// The form prepared so that `Amount`'s appearance stream uses a font name its own
    /// `/Resources` lack (M4 QA round 1, the F7 residual).
    FormApMissingFont,
    /// `forms::rotated_pages` certified by our RSA-2048 signature with `P = 3` (M4 QA round 2,
    /// finding 7: Text annotations on rotated pages).
    CertifiedP3Rotated,
    /// `minimal.pdf` prepared with `/Rotate 90` on its page-tree root (inherited by its page),
    /// then certified with `P = 3`.
    CertifiedP3RotatedTree,
    /// The form prepared so that `Amount`'s appearance paints with a tiling pattern whose cell
    /// uses a font name no resources define (M4 QA round 2, finding 22).
    FormApPattern,
    /// The form prepared so that `Amount`'s appearance uses a Type 3 font whose glyph procedure
    /// uses a font name no resources define.
    FormApType3,
    /// The form prepared with its page rotated by 90, `Amount` and `Agree` NoRotate, and four
    /// empty signature fields whose widgets set NoRotate, NoZoom, Hidden or NoView
    /// (`mutators::form_flagged_widgets_input`; M4 QA round 2, expert finding and finding 5).
    FormFlagged,
    /// The form prepared (raw bytes, before signing) with `Amount`'s `/Rect` written twice, a
    /// moved one first and the original last (M4 QA round 3, finding 5: a duplicate key in the
    /// signed copy of an object a later revision changes).
    FormSignedDupRect,
    /// The form prepared with the check box `Agree`'s `/AS` written twice, `/Yes` first and the
    /// signed `/Off` last.
    FormSignedDupCheckbox,
    /// `minimal.pdf` prepared with `/Rotate 90` on its page-tree root and a page without
    /// `/Parent`, then certified with `P = 3` (M4 QA round 3, finding 11, ruling R-13).
    CertifiedP3TreeWithoutParent,
    /// The same with the page's `/Parent` a `/Pages` node without `/Rotate` that the tree does
    /// not reach.
    CertifiedP3TreeParentElsewhere,
    /// The form prepared so that `Amount`'s appearance sets a graphics state whose soft mask's
    /// group uses a font name no resources define (M4 QA round 3, findings 6 and 21).
    FormApExtGStateSMask,
    /// The form prepared so that `Amount`'s appearance sets a graphics state whose `/Font` is a
    /// Type 3 font whose glyph uses a font name no resources define.
    FormApExtGStateFont,
    /// The form prepared so that its page draws `/Fx` from an `/XObject` dictionary that
    /// writes `/Fx` twice, `Amount`'s appearance stream first (ruling R-12 (2): a use that
    /// first-wins readers see and Folioxide's parser does not).
    FormApSharedFirstWins,
    /// The form prepared so that the page-tree root writes `/Extra` with a key twice, `Amount`'s
    /// appearance stream first (one hop: a use only first-wins readers see; M4 QA round 4,
    /// finding 1).
    FormApHiddenOneHop,
    /// The same with the first value a carrier `<< /Fx 8 0 R >>` that only first-wins readers
    /// reach (two hops).
    FormApHiddenTwoHops,
    /// The same with the first value a carrier array whose dictionary uses the stream (three
    /// hops).
    FormApHiddenThreeHops,
    /// `minimal.pdf` prepared with a first page that has `/Rotate 90` and `/Kids` listing a
    /// second page the root lists too, then certified with `P = 3` (M4 QA round 4, finding 10).
    CertifiedP3PageWithKids,
    /// The form prepared so that `Amount`'s appearance draws a nested form XObject whose
    /// `/Subtype /Form` is indirect and whose content uses a font name no resources define (M4
    /// QA round 4, finding 12).
    FormApIndirectSubtype,
    /// The same with a Type 3 font whose `/Subtype /Type3` is indirect.
    FormApType3IndirectSubtype,
    /// The form prepared so that `Amount`'s appearance, without resources, draws a form XObject
    /// only the page's `/Resources` define, which uses a font name no resources define.
    FormApPageLevelForm,
    /// The form prepared with `Amount`'s `/AP` an indirect dictionary, used once (manager ruling
    /// R-19, the control).
    FormApDictIndirect,
    /// The form prepared with `Amount`'s indirect `/AP` dictionary shared with a second field
    /// `Twin` (M4 QA round 5, finding 7).
    FormApDictShared,
    /// The form prepared with `Amount`'s indirect `/AP` dictionary held a second time by a
    /// first-wins carrier on the page-tree root (finding 7, the hidden-carrier twin).
    FormApDictHiddenCarrier,
    /// [`Base::FormApPageLevelForm`] with an empty `/Resources` on `Amount`'s appearance (M4 QA
    /// round 5, finding 29).
    FormApPageLevelFormOwnResEmpty,
    /// [`Base::FormApPageLevelForm`] with `/Resources << /Font … >>` on `Amount`'s appearance.
    FormApPageLevelFormFontOnly,
    /// The form whose page-tree root holds the page's resources and a page-level form, the page
    /// without resources and with a `/Parent` outside the tree (finding 29).
    FormApPageLevelFormParentMismatch,
    /// The form prepared with its empty visible signature field and a second one, `SigB`, sharing
    /// one indirect `/AP` dictionary (M4 final fix round 2, finding 1).
    FormSigApDictShared,
    /// The control: the two empty signature fields each with an indirect `/AP` dictionary of
    /// its own.
    FormSigApDictPrivate,
    /// [`Base::FormSigApDictShared`] certified by our RSA-2048 signature with `P = 2`.
    CertifiedP2SigApDictShared,
    /// The form prepared with two non-terminal text fields `P` and `Q` sharing one indirect
    /// `/AP` dictionary, each with a named terminal kid (M4 closing round, finding 10).
    FormApDictSharedParents,
    /// The control: each parent with an indirect `/AP` dictionary of its own.
    FormApDictPrivateParents,
    /// [`Base::FormApDictSharedParents`] certified by our RSA-2048 signature with `P = 2`.
    CertifiedP2ApDictSharedParents,
    /// [`Base::FormApDictPrivateParents`] certified by our RSA-2048 signature with `P = 2`.
    CertifiedP2ApDictPrivateParents,
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
            Base::Form => super::sign_default(&forms::acroform(), &super::rsa2048()),
            Base::FormTagged => super::sign_default(&forms::acroform_tagged(), &super::rsa2048()),
            Base::FormHidden => form(mutators::form_hidden_widget_input),
            Base::FormReadOnly => form(mutators::form_readonly_input),
            Base::FormXfa => form(mutators::form_xfa_input),
            Base::FormOrphanWidget => form(mutators::form_orphan_widget_input),
            Base::FormApSharedWithPage => form(mutators::form_ap_shared_with_page_input),
            Base::FormSplit => form(mutators::form_split_field_input),
            Base::FormFieldMdp => super::sign_raw(
                &forms::acroform(),
                &super::rsa2048(),
                &field_mdp_signature(),
            ),
            Base::CertifiedP3Annotated => {
                let input = mutators::annotated_input(&syntax::minimal())
                    .expect("the annotated input applies");
                certify(&input, DocMdpPermissions::FormFillingAndAnnotations)
            }
            Base::RotatedPages => super::sign_default(&forms::rotated_pages(), &super::rsa2048()),
            Base::FormApMissingFont => form(mutators::form_ap_missing_font_input),
            Base::CertifiedP3Rotated => certify(
                &forms::rotated_pages(),
                DocMdpPermissions::FormFillingAndAnnotations,
            ),
            Base::CertifiedP3RotatedTree => {
                let input = mutators::rotated_page_tree_input(&syntax::minimal())
                    .expect("the rotated page tree applies");
                certify(&input, DocMdpPermissions::FormFillingAndAnnotations)
            }
            Base::FormFlagged => form(mutators::form_flagged_widgets_input),
            Base::FormApPattern => form(mutators::form_ap_pattern_input),
            Base::FormApType3 => form(mutators::form_ap_type3_input),
            Base::FormSignedDupRect => form(mutators::parser_dup_key_rect_moved_first),
            Base::FormSignedDupCheckbox => form(mutators::parser_dup_key_checkbox_state_first),
            Base::CertifiedP3TreeWithoutParent => {
                let input = mutators::rotated_tree_page_without_parent_input(&syntax::minimal())
                    .expect("the page tree applies");
                certify(&input, DocMdpPermissions::FormFillingAndAnnotations)
            }
            Base::CertifiedP3TreeParentElsewhere => {
                let input = mutators::rotated_tree_parent_elsewhere_input(&syntax::minimal())
                    .expect("the page tree applies");
                certify(&input, DocMdpPermissions::FormFillingAndAnnotations)
            }
            Base::FormApExtGStateSMask => form(mutators::form_ap_extgstate_smask_input),
            Base::FormApExtGStateFont => form(mutators::form_ap_extgstate_font_input),
            Base::FormApSharedFirstWins => form(mutators::form_ap_shared_first_wins_input),
            Base::FormApHiddenOneHop => form(|pdf| mutators::form_ap_hidden_hop_input(pdf, 1)),
            Base::FormApHiddenTwoHops => form(|pdf| mutators::form_ap_hidden_hop_input(pdf, 2)),
            Base::FormApHiddenThreeHops => form(|pdf| mutators::form_ap_hidden_hop_input(pdf, 3)),
            Base::FormApIndirectSubtype => form(mutators::form_ap_indirect_subtype_input),
            Base::FormApType3IndirectSubtype => {
                form(mutators::form_ap_type3_indirect_subtype_input)
            }
            Base::FormApPageLevelForm => form(mutators::form_ap_page_level_form_input),
            Base::FormApDictIndirect => form(mutators::form_ap_dict_indirect_input),
            Base::FormApDictShared => form(mutators::form_ap_dict_shared_input),
            Base::FormApDictHiddenCarrier => form(mutators::form_ap_dict_hidden_carrier_input),
            Base::FormApPageLevelFormOwnResEmpty => {
                form(mutators::form_ap_page_level_form_ownres_empty_input)
            }
            Base::FormApPageLevelFormFontOnly => {
                form(mutators::form_ap_page_level_form_font_only_input)
            }
            Base::FormApPageLevelFormParentMismatch => {
                form(mutators::form_ap_page_level_form_parent_mismatch_input)
            }
            Base::CertifiedP3PageWithKids => {
                let input = mutators::page_with_kids_input(&syntax::minimal())
                    .expect("the page tree applies");
                certify(&input, DocMdpPermissions::FormFillingAndAnnotations)
            }
            Base::FormSigApDictShared => form(mutators::form_sig_ap_dict_shared_input),
            Base::FormSigApDictPrivate => form(mutators::form_sig_ap_dict_private_input),
            Base::CertifiedP2SigApDictShared => {
                let input = mutators::form_sig_ap_dict_shared_input(&forms::acroform())
                    .expect("the form input applies");
                certify(&input, DocMdpPermissions::FormFilling)
            }
            Base::FormApDictSharedParents => form(mutators::form_ap_dict_shared_parents_input),
            Base::FormApDictPrivateParents => form(mutators::form_ap_dict_private_parents_input),
            Base::CertifiedP2ApDictSharedParents => {
                let input = mutators::form_ap_dict_shared_parents_input(&forms::acroform())
                    .expect("the form input applies");
                certify(&input, DocMdpPermissions::FormFilling)
            }
            Base::CertifiedP2ApDictPrivateParents => {
                let input = mutators::form_ap_dict_private_parents_input(&forms::acroform())
                    .expect("the form input applies");
                certify(&input, DocMdpPermissions::FormFilling)
            }
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
            Base::Form
            | Base::FormTagged
            | Base::FormFieldMdp
            | Base::RotatedPages
            | Base::CertifiedP3Rotated => 1,
            Base::FormHidden
            | Base::FormReadOnly
            | Base::FormXfa
            | Base::FormOrphanWidget
            | Base::FormApSharedWithPage
            | Base::FormSplit
            | Base::FormApMissingFont
            | Base::CertifiedP3Annotated
            | Base::CertifiedP3RotatedTree
            | Base::FormFlagged
            | Base::FormApPattern
            | Base::FormApType3
            | Base::FormSignedDupRect
            | Base::FormSignedDupCheckbox
            | Base::CertifiedP3TreeWithoutParent
            | Base::CertifiedP3TreeParentElsewhere
            | Base::CertifiedP3PageWithKids
            | Base::FormApIndirectSubtype
            | Base::FormApType3IndirectSubtype
            | Base::FormApPageLevelForm
            | Base::FormApExtGStateSMask
            | Base::FormApExtGStateFont
            | Base::FormApDictIndirect
            | Base::FormApDictShared
            | Base::FormApPageLevelFormParentMismatch
            | Base::FormSigApDictShared
            | Base::FormSigApDictPrivate
            | Base::CertifiedP2SigApDictShared
            | Base::FormApDictSharedParents
            | Base::FormApDictPrivateParents
            | Base::CertifiedP2ApDictSharedParents
            | Base::CertifiedP2ApDictPrivateParents => 2,
            Base::FormApSharedFirstWins
            | Base::FormApHiddenOneHop
            | Base::FormApHiddenTwoHops
            | Base::FormApHiddenThreeHops
            | Base::FormApPageLevelFormOwnResEmpty
            | Base::FormApPageLevelFormFontOnly => 3,
            Base::FormApDictHiddenCarrier => 4,
        }
    }
}

/// `forms::acroform` prepared by `prepare`, signed by our RSA-2048 key (an approval).
fn form(prepare: fn(&[u8]) -> Option<Vec<u8>>) -> Vec<u8> {
    let input = prepare(&forms::acroform()).expect("the form input applies");
    super::sign_default(&input, &super::rsa2048())
}

/// `source` certified by our RSA-2048 key with `p`.
pub fn certify(source: &[u8], p: DocMdpPermissions) -> Vec<u8> {
    super::sign_with(
        source,
        &super::rsa2048(),
        SignatureOptions::new(super::time()).with_certification(Some(p)),
    )
}

/// The FieldMDP signature of [`Base::FormFieldMdp`]: `/Lock << /Type /SigFieldLock /Action
/// /Include /Fields [(Country)] >>` on the field and the matching `/Reference` FieldMDP
/// transform in the signature dictionary (§12.8.2.4), as Acrobat writes both.
fn field_mdp_signature() -> super::RawSignature {
    let fields = Object::Array(vec![Object::literal_string("Country")]);
    let mut lock = Dict::new();
    lock.insert("Type", Object::name("SigFieldLock"));
    lock.insert("Action", Object::name("Include"));
    lock.insert("Fields", fields.clone());
    let mut params = Dict::new();
    params.insert("Type", Object::name("TransformParams"));
    params.insert("Action", Object::name("Include"));
    params.insert("Fields", fields);
    params.insert("V", Object::name("1.2"));
    let mut reference = Dict::new();
    reference.insert("Type", Object::name("SigRef"));
    reference.insert("TransformMethod", Object::name("FieldMDP"));
    reference.insert("TransformParams", Object::Dict(params));
    super::RawSignature {
        name: "Signature1".to_owned(),
        field: vec![("Lock", Object::Dict(lock))],
        sig: vec![("Reference", Object::Array(vec![Object::Dict(reference)]))],
        ..super::RawSignature::default()
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

/// The fields of later, legitimate signatures in the corpus cases: [`COSIGNER_FIELD`], the
/// form's empty field that `existing_field_signed_ap_no_bbox` signs, and the empty fields of
/// [`Base::FormFlagged`] that the `existing_field_*` cases sign.
pub const LATER_SIGNER_FIELDS: &[&str] = &[
    COSIGNER_FIELD,
    forms::VISIBLE,
    "NoRotateSig",
    "NoZoomSig",
    "HiddenSig",
    "NoViewSig",
];

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
    // ---- M4: generic form filling (M4 brief §0.1, §5.1; DECISIONS D13 D-14) ----
    (
        "form_widget_unhidden",
        "modification",
        "other",
        "formFilling",
        "M4 §5.1 F1: the widget flags /F (here Hidden cleared, /F 6 to 4) hide or reveal the \
         widget (ISO 32000-2 12.5.3: Hide-and-Reveal); pyHanko lists /F among its value-update \
         keys",
    ),
    (
        "form_widget_hidden",
        "modification",
        "other",
        "formFilling",
        "M4 §5.1 F1: /F 4 to 2 hides a signed widget (Hide); pyHanko lists /F among its \
         value-update keys",
    ),
    (
        "form_field_da_changed",
        "modification",
        "other",
        "formFilling",
        "M4 §5.1 F1: the field's /DA restyles the appearance viewers construct (here white text; \
         the M3 /DA lesson); pyHanko lists /DA among its value-update keys",
    ),
    (
        "form_field_q_changed",
        "modification",
        "other",
        "formFilling",
        "M4 §5.1 F1: /Q changes the alignment of constructed text; pyHanko lists /Q among its \
         value-update keys",
    ),
    (
        "form_field_ff_changed",
        "modification",
        "other",
        "formFilling",
        "M4 §5.1 F1: /Ff (here Password) masks or reflows the value; pyHanko treats /Ff as \
         always modifiable",
    ),
    (
        "form_ap_changed_without_value",
        "modification",
        "other",
        "formFilling",
        "M4 §5.1 F4: a new appearance while /V stays shows a value the field does not have \
         (shadow Replace); pyHanko allows /AP updates without a value change",
    ),
    (
        "form_checkbox_ap_replaced",
        "modification",
        "other",
        "formFilling",
        "M4 §5.1 F3: the check box's signed On appearance was replaced; filling only selects one \
         of the signed appearance states",
    ),
    (
        "form_readonly_field_filled",
        "modification",
        "other",
        "formFilling",
        "M4 §5.1 F1: ISO 32000-2 12.7.4.1, a ReadOnly field shall not be changed by the user; \
         pyHanko does not look at the field flags",
    ),
    (
        "form_fill_with_xfa",
        "modification",
        "other",
        "formFilling",
        "M4 §5.1 F0, D-23: XFA-aware viewers show the XFA datasets, not the AcroForm /V, so a \
         value change shows nothing they display; generic form filling is OTHER with /XFA",
    ),
    (
        "form_as_unknown_state",
        "modification",
        "other",
        "formFilling",
        "M4 §5.1 F3: /AS names no appearance state of the signed widget, so the check box draws \
         nothing (Hide)",
    ),
    (
        "form_value_indirect",
        "modification",
        "other",
        "formFilling",
        "M4 §5.1 F2: a new /V is never an indirect reference (a later revision could change the \
         value object again unnoticed)",
    ),
    (
        "form_checkbox_as_without_value",
        "modification",
        "other",
        "formFilling",
        "M4 §5.1 F3: the check box shows checked (/AS /Yes) while its value stays /Off (shadow \
         Replace of the shown state); pyHanko allows /AS updates without a value change \
         (probe ap_checkbox_as_only)",
    ),
    // ---- M4 QA round 1, rulings R-3 and finding R5: what a new widget paints ----
    (
        "sigfield_flags_nozoom",
        "modification",
        "other",
        "formFilling",
        "R-3: the new visible signature widget has /F 12 (NoZoom), so viewers draw it at a fixed size, not inside its /Rect; signers write 4 or 132. pyHanko does not look at the widget flags",
    ),
    (
        "sigfield_flags_hidden",
        "modification",
        "other",
        "formFilling",
        "R-3: the new visible signature widget has /F 6 (Hidden); signers write 4 or 132. pyHanko does not look at the widget flags",
    ),
    (
        "sigfield_flags_noview",
        "modification",
        "other",
        "formFilling",
        "R-3: the new visible signature widget has /F 36 (NoView): it prints what the screen does not show; signers write 4 or 132. pyHanko does not look at the widget flags",
    ),
    (
        "sigfield_flags_toggle_noview",
        "modification",
        "other",
        "formFilling",
        "R-3: the new visible signature widget has /F 260 (ToggleNoView); signers write 4 or 132. pyHanko does not look at the widget flags",
    ),
    (
        "sigfield_invisible_flags_hidden",
        "modification",
        "other",
        "ltaUpdates",
        "R-3: the new invisible signature field has /F 2 (Hidden); signers write 4 or 132, and the whitelist refuses every other flag. pyHanko does not look at the widget flags",
    ),
    (
        "sigfield_norotate_rotated_page",
        "modification",
        "other",
        "formFilling",
        "R-3, QA variant R3-rot90-raw-norotate-flag: /F 20 (NoRotate) on a page rotated by 90 makes poppler paint the appearance unrotated, outside the widget's /Rect (12,139 pixels). pyHanko does not look at the widget flags",
    ),
    (
        "sigfield_ap_no_bbox",
        "modification",
        "other",
        "formFilling",
        "QA finding R5: the new widget's appearance stream has no /BBox, so PDFium does not clip it to the /Rect and paints it over the signed page (ISO 32000-2 12.5.5). pyHanko does not look at the appearance's form XObject",
    ),
    (
        "sigfield_ap_no_subtype",
        "modification",
        "other",
        "formFilling",
        "QA finding R5: the new widget's appearance stream is no form XObject (no /Subtype /Form, ISO 32000-2 8.10.1). pyHanko does not look at it",
    ),
    (
        "sigfield_ap_state_dict",
        "modification",
        "other",
        "formFilling",
        "QA finding R5: the new signature widget's /AP /N is a dictionary of appearance states, holding a stream without /BBox; a signature widget has one appearance. pyHanko does not look at it",
    ),
    (
        "sigfield_ap_page_content",
        "modification",
        "other",
        "formFilling",
        "QA finding R5: the new widget's /AP /N is the page's content stream, an existing object and no form XObject (PDFium paints it unclipped). pyHanko does not look at what the /AP names",
    ),
    (
        "shadow_overlay_sig_widget_no_rect",
        "modification",
        "other",
        "formFilling",
        "M4 QA round 2, finding 4: the new signature widget has no /Rect; a widget's /Rect must \
         be four finite numbers (signers write [0 0 0 0] for an invisible one), else viewers place \
         its appearance elsewhere than its /Rect says. pyHanko treats a missing /Rect as \
         invisible and its appearance as form filling",
    ),
    (
        "existing_field_signed_ap_no_bbox",
        "modification",
        "other",
        "formFilling",
        "QA finding R5 on the existing-field branch: the revision that signs the empty field gives it an appearance without /BBox, which PDFium paints over the page. pyHanko allows the field's new /AP",
    ),
    (
        "form_fill_ap_no_bbox",
        "modification",
        "other",
        "formFilling",
        "QA finding R5 on M4 brief 5.1 F4: the filled field's new appearance has no /BBox, which PDFium paints over the page. pyHanko allows the field's new /AP",
    ),
    // ---- M4 QA round 2: where new and signed widgets paint ----
    (
        "sigfield_rect_null_entry",
        "modification",
        "other",
        "formFilling",
        "QA round 2, finding 4 (variant R3-rect-first-null): the new signature widget's /Rect is [null 300 400 340]; poppler reads null as 0 and paints the appearance at x 0 to 400, outside the /Rect the widget declares (16,040 pixels). A new signature widget's /Rect must be four finite numbers. pyHanko does not read it",
    ),
    (
        "sigfield_rect_string_entry",
        "modification",
        "other",
        "formFilling",
        "QA round 2, finding 4 (variant R3-rect-spelling-string): /Rect [300 300 (400) 340], an entry that is no number, which viewers read as 0. pyHanko does not read it",
    ),
    (
        "sigfield_rect_wrong_length",
        "modification",
        "other",
        "formFilling",
        "QA round 2, finding 4: /Rect [300 300 400], three numbers. pyHanko does not read it",
    ),
    (
        "existing_field_signed_flags_norotate",
        "modification",
        "other",
        "formFilling",
        "R-3 on the existing-field branch (QA round 2, finding 5, variant R3-existing-field-norotate-rot90): the empty field NoRotateSig (/F 20) on a page rotated by 90 is signed with an appearance, which poppler paints upright outside the widget's /Rect (3,306 pixels). pyHanko allows the field's new /AP",
    ),
    (
        "existing_field_signed_flags_nozoom",
        "modification",
        "other",
        "formFilling",
        "R-3 on the existing-field branch: the empty field NoZoomSig (/F 12) signed with an appearance, which viewers draw at a fixed size. pyHanko allows the field's new /AP",
    ),
    (
        "existing_field_signed_flags_hidden",
        "modification",
        "other",
        "formFilling",
        "R-3 on the existing-field branch: the empty field HiddenSig (/F 6) signed with an appearance no viewer shows on screen or in print. pyHanko allows the field's new /AP",
    ),
    (
        "existing_field_signed_flags_noview",
        "modification",
        "other",
        "formFilling",
        "R-3 on the existing-field branch: the empty field NoViewSig (/F 36) signed with an appearance that prints but is not shown on screen. pyHanko allows the field's new /AP",
    ),
    (
        "form_dr_adds_name_used_in_ap_pattern",
        "modification",
        "other",
        "formFilling",
        "QA round 2, finding 22 (variant R1x-pattern-stream-no-resources): the signed appearance of Amount paints with a tiling pattern whose cell, without resources of its own, uses /F9; a viewer that looks the name up in the AcroForm /DR would draw the font the update adds there, so the name is a signed one and may not be added (poppler 24.02 and PDFium draw nothing different; pdf.js and MuPDF unprobed). pyHanko clears what a new /DR holds at FORM_FILLING",
    ),
    (
        "form_dr_adds_name_used_in_ap_type3_glyph",
        "modification",
        "other",
        "formFilling",
        "QA round 2, finding 22 (variant R1x-type3-charproc-no-resources): the same for a Type 3 font's glyph procedure, without resources of its own, that uses /F9. pyHanko clears what a new /DR holds at FORM_FILLING",
    ),
    (
        "form_dr_adds_name_used_in_ap_indirect_subtype",
        "modification",
        "other",
        "formFilling",
        "M4 QA round 4, finding 12 (variants R1w-subtype-form-indirect, R2w-dr-gains-hexescaped-name-used-in-nested): the signed appearance of Amount draws a form XObject whose /Subtype /Form is an indirect object (readers dereference it) and whose content uses /F9; the /DR guard reads it. pyHanko clears what a new /DR holds at FORM_FILLING",
    ),
    (
        "form_dr_adds_name_used_in_ap_type3_indirect_subtype",
        "modification",
        "other",
        "formFilling",
        "M4 QA round 4, finding 12 (variant R1w-subtype-t3-indirect): the same for a Type 3 font whose /Subtype /Type3 is indirect. pyHanko clears what a new /DR holds at FORM_FILLING",
    ),
    (
        "form_dr_adds_name_used_in_ap_page_level_form",
        "modification",
        "other",
        "formFilling",
        "M4 QA round 4, finding 12 (variants R1w-page-level-form, R2w-dr-gains-name-used-only-by-page-level-form-ctl): the signed appearance of Amount has no /Resources and draws /Fm0, a form XObject only the page's /Resources define (ISO 32000-2 7.8.3), whose content uses /F9; the /DR guard reads what the page's resources draw when a signed stream has none. pyHanko clears what a new /DR holds at FORM_FILLING",
    ),
    (
        "form_fill_norotate_widget_rotated_page",
        "modification",
        "other",
        "formFilling",
        "QA round 2, expert finding (M4 brief 5.1 F0): Amount's widget sets NoRotate (/F 20) on a page rotated by 90, so the appearance its fill shows is drawn upright at the /Rect's corner, outside the /Rect (poppler: 12,067 pixels). pyHanko does not read widget flags",
    ),
    (
        "form_checkbox_norotate_rotated_page",
        "modification",
        "other",
        "formFilling",
        "QA round 2, expert finding: the check box Agree sets NoRotate (/F 20) on a page rotated by 90, so the state its /AS selects is drawn outside its /Rect. pyHanko does not read widget flags",
    ),
    (
        "form_dr_adds_name_missing_from_ap_resources",
        "modification",
        "other",
        "formFilling",
        "M4 brief 5.5 scope (2), the F7 residual: the signed appearance stream of Amount has \
         /Resources of its own but draws with /F9, which they lack; a viewer that looks the name \
         up in the AcroForm /DR would draw the font the update adds there, so a /DR name any \
         signed appearance stream (or form XObject it draws) uses may not be added (poppler \
         24.02 does not fall back to /DR; pdf.js and MuPDF are unprobed). pyHanko clears what a \
         new /DR holds at FORM_FILLING",
    ),
    // ---- M4 QA round 1, ruling R-1: parser differentials (OTHER whatever the reader) ----
    (
        "parser_dup_key_rect_original_first",
        "modification",
        "other",
        "ltaUpdates",
        "R-1 parser differential: the widget's /Rect written twice, the signed value first and a moved one last: pyHanko and pypdf keep the first value and see a re-listing; Folioxide, qpdf and poppler keep the last and show the widget moved. ISO 32000-2 7.3.7 forbids duplicate keys; the \
         classifier does not depend on a reader's duplicate-key policy, so the revision is OTHER",
    ),
    (
        "parser_dup_key_flags_hidden_first",
        "modification",
        "other",
        "formFilling",
        "R-1 parser differential: the widget's /F written twice, Hidden (2) first and the signed flags last: a first-wins reader (pypdf) hides the field, a last-wins reader shows it; pyHanko lists /F among its value-update keys. ISO 32000-2 7.3.7 forbids duplicate keys; the \
         classifier does not depend on a reader's duplicate-key policy, so the revision is OTHER",
    ),
    (
        "parser_dup_key_value_evil_first",
        "modification",
        "other",
        "formFilling",
        "R-1 parser differential: the field's /V written twice, '900 EUR' first and the signed value last: a first-wins reader shows another value than a last-wins one. ISO 32000-2 7.3.7 forbids duplicate keys; the \
         classifier does not depend on a reader's duplicate-key policy, so the revision is OTHER",
    ),
    (
        "parser_dup_key_ap_page_content_first",
        "modification",
        "other",
        "formFilling",
        "R-1 parser differential: the field's /AP written twice, the page content stream as /N first and the signed /AP last: a first-wins reader draws the page content inside the widget. ISO 32000-2 7.3.7 forbids duplicate keys; the \
         classifier does not depend on a reader's duplicate-key policy, so the revision is OTHER",
    ),
    (
        "parser_dup_key_ap_n_reverse",
        "modification",
        "other",
        "formFilling",
        "R-1 parser differential: a duplicate /N nested in the field's /AP, the page content stream first and the signed stream last. ISO 32000-2 7.3.7 forbids duplicate keys; the \
         classifier does not depend on a reader's duplicate-key policy, so the revision is OTHER",
    ),
    (
        "parser_dup_key_checkbox_state_first",
        "modification",
        "other",
        "formFilling",
        "R-1 parser differential: the check box's /AS written twice, /Yes first and the signed /Off last: a first-wins reader shows it checked while its value stays /Off. ISO 32000-2 7.3.7 forbids duplicate keys; the \
         classifier does not depend on a reader's duplicate-key policy, so the revision is OTHER",
    ),
    (
        "sigfield_rect_integer_overflow",
        "modification",
        "other",
        "formFilling",
        "R-12 canonical-input gate (M4 QA round 3, findings 4 and 12): the new widget's /Rect \
         ends in 4294967296, an integer outside 32 bits, which PDFium reads as 0 (it paints the \
         appearance over y 0 to 300, outside the /Rect Folioxide reads); pyHanko reads the \
         number and does not look at the /Rect",
    ),
    (
        "form_fill_ap_matrix_magnitude",
        "modification",
        "other",
        "formFilling",
        "M4 QA round 4, finding 4 (variant F4-i-newap-bbox-ok-matrix-int32max): the fill's new \
         appearance has /Matrix [1 0 0 1 2147483647 0], a canonical integer that PDFium maps \
         onto the /Rect in single precision and places elsewhere (3,270 pixels outside); a new \
         appearance's /BBox and /Matrix entries are within +/-1e5 (ruling R-21). pyHanko does not read the \
         form XObject",
    ),
    (
        "sigfield_rect_magnitude",
        "modification",
        "other",
        "formFilling",
        "M4 QA round 4, finding 13 (variants R5w-rect-mag-y1-minus-1000000000, \
         R5w-rect-int-minus-2147483647): the new widget's /Rect [60 -1000000000 260 260] is \
         canonical but beyond +/-1e5 (ruling R-21), which PDFium maps in single precision and paints \
         elsewhere (3,800 pixels); pyHanko does not read the /Rect",
    ),
    (
        "sigfield_rect_zero_padded",
        "modification",
        "other",
        "formFilling",
        "R-12 canonical-input gate (M4 QA round 4, finding 2, variants \
         R3-i-rect-zero-padded-integer-*): the new widget's /Rect y2 is written with 32 leading \
         zeros; Folioxide, poppler and pyHanko read 340, and PDFium reads a word of 256 \
         characters or more as 0 (29,700 pixels outside the /Rect at QA's 260 and 1,000 zeros, \
         which the Rust test sigfield_rect_zero_padded_at_every_length_qa_tried holds; pypdf, \
         which the oracle's extraction uses, reads at most about 45 characters per number). A canonical integer \
         has at most 11 characters (-2147483647); pyHanko does not look at the /Rect",
    ),
    (
        "sigfield_rect_zero_padded_x1",
        "modification",
        "other",
        "formFilling",
        "R-12 canonical-input gate (M4 QA round 4, finding 2, variants \
         R3-i-rect-zero-padded-x1-*): the new widget's /Rect x1 written with 32 leading zeros \
         (at QA's 260, PDFium reads 0: 11,920 pixels outside the /Rect)",
    ),
    (
        "parser_unlisted_object_body",
        "modification",
        "other",
        "formFilling",
        "M4 QA round 4, finding 3 (variant F8-i-xref-trigger-xref-entries-19-bytes and the \
         fuzz_xref hits): the fill's update also holds a body of object 4 (the page content, \
         painted black) that its cross-reference section does not list. Folioxide, poppler and \
         pyHanko follow the section (a fill); PDFium, once a damaged entry or trailer makes it \
         rebuild the cross-reference data, takes the black page (477,210 pixels outside the \
         fill). Every body in an update must be one its section lists there",
    ),
    (
        "parser_junk_before_startxref",
        "modification",
        "other",
        "formFilling",
        "M4 QA round 4, finding 3: the fill's update has bytes other than white-space and \
         comments between its trailer dictionary and startxref, which make PDFium rebuild the \
         cross-reference data; an update holds its objects, its section and startxref only",
    ),
    (
        "parser_relisted_rect_zero_padded",
        "modification",
        "other",
        "ltaUpdates",
        "R-12 canonical-input gate (M4 QA round 4, finding 2, variant \
         F1-i-relisted-rect-zero-padded-1000): Amount re-listed with the first number of its \
         /Rect padded with 32 leading zeros. Folioxide and pyHanko read the signed value (a \
         re-listing); at QA's 1,000 zeros PDFium reads 0 and moves the widget (4,131 pixels \
         outside)",
    ),
    (
        "parser_relisted_flags_zero_padded",
        "modification",
        "other",
        "ltaUpdates",
        "R-12 canonical-input gate (M4 QA round 4, finding 2): the hidden Amount widget re-listed \
         with /F padded with 32 leading zeros; pyHanko reads the signed 6 (a re-listing), PDFium \
         reads a word of 256 characters or more as 0 and shows the hidden widget",
    ),
    (
        "sigfield_rect_int32_min",
        "modification",
        "other",
        "formFilling",
        "R-12 canonical-input gate (M4 QA round 3, finding 12): the new widget's /Rect holds \
         -2147483648, which PDFium reads as 0 (12,400 pixels outside the /Rect); canonical \
         integers are within +/-(2^31 - 1). pyHanko does not look at the /Rect",
    ),
    (
        "form_signed_dup_checkbox_relisted",
        "modification",
        "other",
        "formFilling",
        "R-12 (2), M4 QA round 3, finding 5: the signed check box writes /AS twice (/Yes first, \
         /Off last) and the update re-lists it cleanly with /AS /Off; Folioxide's last-wins \
         reading saw a re-listing, pyHanko's first-wins reading a fill from /Yes to /Off. The \
         signed copy of an object the update changes must read the same in every reader, so the \
         revision is OTHER",
    ),
    (
        "form_dr_adds_name_used_in_ap_extgstate_smask",
        "modification",
        "other",
        "formFilling",
        "F7 /DR guard (M4 QA round 3, findings 6 and 21): /F9 is used only by the transparency \
         group of the soft mask of a graphics state the signed appearance sets (ExtGState \
         /SMask /G, ISO 32000-2 11.6.5.2), without resources of its own; a viewer that falls \
         back to /DR would draw the new font there. pyHanko clears what a new /DR holds at \
         FORM_FILLING",
    ),
    (
        "form_dr_adds_name_used_in_ap_extgstate_font",
        "modification",
        "other",
        "formFilling",
        "F7 /DR guard (M4 QA round 3, findings 6 and 21): /F9 is used only by the glyph of a \
         Type 3 font that a graphics state's /Font entry selects (ISO 32000-2 Table 57); pyHanko \
         clears what a new /DR holds at FORM_FILLING",
    ),
    (
        "parser_xref_lists_number_twice",
        "modification",
        "other",
        "ltaUpdates",
        "R-1 parser differential: the update's table lists Amount in two subsections (the same entry): R-1 makes a section that lists a number twice OTHER whatever the entries, since readers differ on which listing counts when they differ; pyHanko reads the unchanged object and reports LTA_UPDATES. ISO 32000-2 7.3.7 forbids duplicate keys; the \
         classifier does not depend on a reader's duplicate-key policy, so the revision is OTHER",
    ),
    // ---- M4: certification (M4 brief §0.1, D-2) ----
    (
        "certify_p1_info_changed",
        "docmdpOk",
        "false",
        "true",
        "D-2: ISO 32000-2 12.8.2.2, P = 1: no changes to the document shall be permitted; only \
         re-listings, orphans, cross-reference streams and document timestamps are exempt. \
         pyHanko's docmdp_ok accepts LTA_UPDATES under P = 1",
    ),
    (
        "certify_p1_xmp_changed",
        "docmdpOk",
        "false",
        "true",
        "D-2: the XMP metadata changed under P = 1 (no changes permitted); pyHanko's docmdp_ok \
         accepts LTA_UPDATES under P = 1",
    ),
    (
        "docmdp_two_references",
        "docmdpOk",
        "false",
        "true",
        "R-6: two DocMDP references are DocMdpInvalid (ISO 32000-2 12.8.2.2 allows one) and P = \
         1 is then in force; pyHanko reads the first one (P = 3), which allows the approval",
    ),
    (
        "docmdp_p_missing",
        "docmdp",
        "2",
        "raises",
        "R-6: ISO 32000-2 Table 257, /P absent means 2; pyHanko 0.37 raises (raw_get('/P'): \
         'Failed to read document permissions'), so its rows are knownFailures",
    ),
    (
        "parser_tail_extra_eol",
        "modification",
        "other",
        "formFilling",
        "Manager ruling R-17 (b) (M4 QA round 5, findings 10, 13, 16-26): after the fill's %%EOF come three end-of-line bytes, one more than an update writes; past two, the bytes after %%EOF are what made poppler miss startxref in the last 1,024 bytes and rebuild the cross-reference data (at 25 KB of comments or 40 KB of white-space: 469,411 pixels outside the fill). pyHanko reads the file as a fill",
    ),
    (
        "parser_trailer_size_shrunk",
        "modification",
        "other",
        "formFilling",
        "M4 closing round, finding 13 (manager ruling R-26): the fill's trailer gives /Size 3 while the file defines objects up to 25; PDFium keeps only the objects numbered below the newest /Size (ISO 32000-2 7.5.5 Table 15: one greater than the highest object number), so it may show the page without its content, fonts and widgets. pyHanko (non-strict; strict mode raises 'Xref table size mismatch') and poppler read past it",
    ),
    (
        "parser_trailer_size_shrunk_info_only",
        "modification",
        "other",
        "ltaUpdates",
        "M4 closing round, finding 13: the same /Size 3 on an /Info-only update, which pyHanko (non-strict) reads as ltaUpdates",
    ),
    (
        "parser_trailer_size_off_by_one",
        "modification",
        "other",
        "formFilling",
        "M4 closing round, finding 13: the fill's /Size equals the highest object number the file lists, so that object is at or above it and PDFium drops it; pyHanko (non-strict) reads past it",
    ),
    (
        "parser_fake_object_in_ap_stream",
        "modification",
        "other",
        "formFilling",
        "Manager ruling R-17 (d) (findings 10 and 13, variant A1-r5-layout-fake-object-in-ap-stream-data): the fill's new appearance stream holds `4 0 obj ... endobj` (the page content painted black) at the start of a line; a reader that rebuilds the cross-reference data (poppler when it misses startxref) takes it for object 4. pyHanko follows the section",
    ),
    (
        "parser_fake_object_in_value_string",
        "modification",
        "other",
        "formFilling",
        "Manager ruling R-17 (d) (variant A1-r5-layout-fake-object-in-contents-string): the fill's value string holds `4 0 obj ... endobj` after a line break, which poppler's rebuild reads as object 4. pyHanko follows the section",
    ),
    (
        "parser_startxref_corrupted",
        "modification",
        "other",
        "formFilling",
        "Manager ruling R-17 (c): the fill's last startxref names a position one byte past its cross-reference section, so readers repair or rebuild; Folioxide's store repairs it (StructureRepaired). pyHanko finds the section nearby and reads a fill",
    ),
    (
        "parser_objstm_member_unlisted",
        "modification",
        "other",
        "ltaUpdates",
        "Manager ruling R-18 (M4 QA round 5, finding 27, variants R5v-hidden-objstm-member-*): the update's classic table lists an orphan content stream that paints the page black and a new object stream whose one member is the page, re-pointed to it; no section lists the member. Folioxide, poppler and pyHanko follow the section (an orphan and an object stream), PDFium rebuilding the cross-reference data takes the member for the page (466,059 pixels, the whole page black)",
    ),
    (
        "parser_xref_subsection_padded",
        "modification",
        "other",
        "formFilling",
        "Manager ruling R-21 (findings 11 and 30, variants A7-r5-xref-subsection-start-padded-*, R5v-xref-subsection-number-padded-300-*): the fill's table writes each subsection header's first number after 32 zeros; PDFium reads a long word as 0. A table written after the signed revision has canonical subsection headers (unsigned, at most 10 digits, no leading zero) and 20-byte entries",
    ),
    (
        "parser_xref_entries_19_bytes",
        "modification",
        "other",
        "formFilling",
        "Manager ruling R-21 (finding 11, variant A1-r5-layout-entries-19-bytes-*): the fill's table entries end in a lone line feed (19 bytes), which makes PDFium rebuild the cross-reference data (ISO 32000-2 7.5.4: each entry is exactly 20 bytes)",
    ),
    (
        "form_fill_ap_matrix_small_bbox",
        "modification",
        "other",
        "formFilling",
        "Manager ruling R-21 (finding 28, variants R5v-ap-fill-bbox-1x1-matrix-translate-*): the fill's new appearance has /BBox [0 0 1 1] and /Matrix [1 0 0 1 100000 0], every entry within +/-1e5 but its corner mapped to 100,001; PDFium maps the box in single precision and placed a one-unit box translated by 1e7 elsewhere (1,590 pixels). The /BBox mapped through the /Matrix stays within +/-1e5. pyHanko does not read the form XObject",
    ),
    (
        "sigfield_ap_matrix_small_bbox",
        "modification",
        "other",
        "formFilling",
        "Manager ruling R-21 (finding 28, variants R5v-ap-bbox-1x1-matrix-translate-*): the same appearance on a new visible signature widget (3,540 and 3,800 pixels outside its /Rect in PDFium at a translation of 1e7). pyHanko does not read the form XObject",
    ),
    // ---- M4 final fix round 2, findings 2 and 4: the precision of mapping onto the /Rect ----
    (
        "form_fill_ap_tiny_bbox_translate_1e5",
        "modification",
        "other",
        "formFilling",
        "Final fix round 2, findings 2 and 4 (variants F4-k-pdfium-bbox-001-translate-99999): the fill's new appearance has /BBox [0 0 .01 .01] and /Matrix [1 0 0 1 99999 0], every number and mapped corner within +/-1e5, but the box is scaled by 20,000 onto the 200-unit field; PDFium does that in single precision and drew 2,100 pixels outside the field. The mapped box's largest coordinate times that scale must be at most 2^20. pyHanko does not read the form XObject",
    ),
    (
        "form_fill_ap_matrix_tiny_bbox",
        "modification",
        "other",
        "formFilling",
        "Final fix round 2, finding 2 (variant F4-k-newap-matrix-real-spelling-99999.9): /BBox [0 0 .1 .1] and /Matrix [1 0 0 1 99999.9 0], scaled by 2,000 onto the field (390 pixels outside it in PDFium). pyHanko does not read the form XObject",
    ),
    (
        "sigfield_ap_tiny_bbox_translate_1e5",
        "modification",
        "other",
        "formFilling",
        "Final fix round 2, findings 2 and 4 (variants R3-k-pdfium-late-bbox-001-*): a new visible signature widget whose appearance is /BBox [0 0 .01 .01] translated by 99,999 (2,806 pixels outside its /Rect in PDFium). pyHanko does not read the form XObject",
    ),
    (
        "sigfield_ap_matrix_tiny_bbox",
        "modification",
        "other",
        "formFilling",
        "Final fix round 2, finding 2 (variants R3-k-pdfium-late-bbox-01-*): the same with /BBox [0 0 .1 .1] (80 pixels outside its /Rect in PDFium). pyHanko does not read the form XObject",
    ),
    (
        "form_dr_adds_name_used_in_ap_ownres_empty",
        "modification",
        "other",
        "formFilling",
        "M4 QA round 5, finding 29 (variant R1v-own-resources-empty-page-form): Amount's signed appearance has an empty /Resources and draws /Fm0, a form only the page's resources define, whose content uses /F9; PDFium looks a category the stream's own resources lack up in the page's, so the /DR guard reads what the page's resources draw. pyHanko clears what a new /DR holds at FORM_FILLING",
    ),
    (
        "form_dr_adds_name_used_in_ap_ownres_font_only",
        "modification",
        "other",
        "formFilling",
        "M4 QA round 5, finding 29 (variant R1v-own-resources-font-only-page-form): the same with /Resources << /Font ... >> and no /XObject. pyHanko clears what a new /DR holds at FORM_FILLING",
    ),
    (
        "form_dr_adds_name_used_in_ap_parent_mismatch",
        "modification",
        "other",
        "formFilling",
        "M4 QA round 5, finding 29 (variant R1v-bare-ap-parent-chain-differs-from-kids-walk): the page-level form is in the page-tree root's /Resources, the page has none and its /Parent is a node outside the tree; poppler inherits the root's resources along /Kids, so the /DR guard reads every node of the /Kids walk as well as each page's /Parent chain. pyHanko clears what a new /DR holds at FORM_FILLING",
    ),
    (
        "certify_p1_objstm_member_unlisted",
        "modification",
        "other",
        "ltaUpdates",
        "Manager ruling R-18 (M4 QA round 5, finding 27, variant R5v-hidden-objstm-member-p1-certified-entries19): after a P = 1 certification, an update whose classic table lists an orphan black content stream and a new object stream holding the page re-pointed to it, a member no section lists; PDFium rebuilding the cross-reference data paints the whole page black (466,059 pixels), where Folioxide and pyHanko saw an orphan and an object stream",
    ),
    (
        "certify_p1_objstm_member_unlisted",
        "docmdpOk",
        "false",
        "true",
        "Manager ruling R-18: the same case; the update is Other, so the P = 1 certification is not respected (pyHanko: LTA_UPDATES, which it accepts under P = 1)",
    ),
];

/// The one deliberate difference where Folioxide is **more lenient** than pyHanko (M4 brief
/// §0.2, DECISIONS D13 D-1): markup annotations under a certification with `P = 3` (and after an
/// approval signature) are `Annotations`, where pyHanko, which declares `P = 3` unsupported,
/// reports `OTHER`. Same shape as [`DELIBERATE_DIFFERENCES`]; the expect file carries pyHanko's
/// value and the Rust test asserts ours.
pub const MORE_LENIENT: &[(&str, &str, &str, &str, &str)] = &[
    (
        "approval_markup_annotation_added",
        "modification",
        "annotations",
        "other",
        "D-1: a markup annotation from the brief 5.2 add-only whitelist; pyHanko never emits \
         ANNOTATIONS. docmdp_ok stays false (P = 2 in force), as pyHanko's",
    ),
    (
        "certify_p3_text_popup",
        "modification",
        "annotations",
        "other",
        "D-1: ISO 32000-2 Table 257, P = 3 permits annotation creation; pyHanko declares P = 3 \
         unsupported (policies.py:204) and reports OTHER",
    ),
    (
        "certify_p3_text_popup",
        "docmdpOk",
        "true",
        "false",
        "D-1: the annotation is what P = 3 grants",
    ),
    (
        "certify_p3_highlight",
        "modification",
        "annotations",
        "other",
        "D-1: P = 3 permits annotation creation; pyHanko reports OTHER",
    ),
    (
        "certify_p3_highlight",
        "docmdpOk",
        "true",
        "false",
        "D-1: the annotation is what P = 3 grants",
    ),
    (
        "certify_p3_square",
        "modification",
        "annotations",
        "other",
        "D-1: P = 3 permits annotation creation; pyHanko reports OTHER",
    ),
    (
        "certify_p3_square",
        "docmdpOk",
        "true",
        "false",
        "D-1: the annotation is what P = 3 grants",
    ),
    (
        "certify_p3_ink",
        "modification",
        "annotations",
        "other",
        "D-1: P = 3 permits annotation creation; pyHanko reports OTHER",
    ),
    (
        "certify_p3_ink",
        "docmdpOk",
        "true",
        "false",
        "D-1: the annotation is what P = 3 grants",
    ),
    (
        "certify_p3_freetext",
        "modification",
        "annotations",
        "other",
        "D-1: P = 3 permits annotation creation; pyHanko reports OTHER",
    ),
    (
        "certify_p3_freetext",
        "docmdpOk",
        "true",
        "false",
        "D-1: the annotation is what P = 3 grants",
    ),
    (
        "certify_p3_stamp",
        "modification",
        "annotations",
        "other",
        "D-1: P = 3 permits annotation creation; pyHanko reports OTHER",
    ),
    (
        "certify_p3_stamp",
        "docmdpOk",
        "true",
        "false",
        "D-1: the annotation is what P = 3 grants",
    ),
    (
        "certify_p3_reply",
        "modification",
        "annotations",
        "other",
        "D-1: a reply (/IRT) to a listed annotation (brief 5.2 A5); pyHanko reports OTHER",
    ),
    (
        "certify_p3_reply",
        "docmdpOk",
        "true",
        "false",
        "D-1: the annotation is what P = 3 grants",
    ),
    (
        "certify_p3_text_upright_page",
        "modification",
        "annotations",
        "other",
        "D-1: a sticky note on the page of the rotated document whose /Rotate is 0 (QA round 2, finding 7: Text is allowed only there); pyHanko reports OTHER",
    ),
    (
        "certify_p3_text_upright_page",
        "docmdpOk",
        "true",
        "false",
        "D-1: the annotation is what P = 3 grants",
    ),
    (
        "certify_p3_square_rotated_page",
        "modification",
        "annotations",
        "other",
        "D-1: a square rotates with its page, inside its /Rect (QA round 2, finding 7: only Text is refused on rotated pages); pyHanko reports OTHER",
    ),
    (
        "certify_p3_square_rotated_page",
        "docmdpOk",
        "true",
        "false",
        "D-1: the annotation is what P = 3 grants",
    ),
    (
        "certify_p3_approval_then_markup",
        "modification",
        "annotations",
        "other",
        "D-1: P = 3 permits annotation creation; pyHanko reports OTHER",
    ),
    (
        "certify_p3_approval_then_markup",
        "docmdpOk",
        "true",
        "false",
        "D-1: the annotation is what P = 3 grants",
    ),
    (
        "certify_p3_approval_then_markup",
        "Approval.modification",
        "annotations",
        "other",
        "D-1 (manager ruling R-7): after an approval signature in a P = 3 certified document a \
         whitelisted markup annotation is Annotations; pyHanko reports OTHER",
    ),
    (
        "certify_p3_approval_then_markup",
        "Approval.docmdpOk",
        "true",
        "false",
        "D-1 (manager ruling R-7): the approval's P_effective is the certification's 3, which \
         grants the annotation",
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
    (
        "parser_relisted_flags_multisign",
        "pyHanko 0.37 cannot read the file (ValueError: invalid literal for int() with base 10: \
         '++6'); Folioxide reads the signed object, finds the signature intact and valid, and \
         makes the update other: the flags spelled with two signs read 6 to Folioxide and 0 to \
         PDFium (manager ruling R-12; M4 QA round 3, variant F1-h-unhide-by-spelling-00)",
    ),
    (
        "parser_relisted_rect_multisign",
        "pyHanko 0.37 cannot read the file (ValueError: invalid literal for int(): a number \
         with two signs); Folioxide makes the update other (ruling R-12; QA variant \
         F8-h-rect-x-spelled-72-00)",
    ),
    (
        "parser_relisted_page_contents_zero_padded",
        "pyHanko 0.37 lists the signature but raises when it reads the update (PdfReadError: \
         Failed to read dictionary key; expected PDF name: its reader does not take a reference \
         whose object number is padded with leading zeros, nor does pypdf); Folioxide makes the \
         update other: the page's \
         /Contents reference is not canonical (ruling R-12; M4 QA round 4, finding 2, variant \
         R3-i-page-contents-ref-zero-padded-300, where PDFium follows no stream and blanks the \
         page)",
    ),
    (
        "parser_tail_pad_lf",
        "pyHanko 0.37 cannot read the file (PdfReadError: EOF marker not found: 40,000 line feeds follow the fill's %%EOF, so no %%EOF is in the last 1,024 bytes); Folioxide reads the signed revision and makes the update other (manager ruling R-17 (a), (b); M4 QA round 5, findings 10, 13, 16-26: poppler no longer finds startxref, rebuilds the cross-reference data and paints object text it finds in an update's stream data)",
    ),
    (
        "parser_tail_pad_space",
        "pyHanko 0.37 cannot read the file (PdfReadError: EOF marker not found: 40,000 spaces follow the fill's %%EOF, so no %%EOF is in the last 1,024 bytes); Folioxide reads the signed revision and makes the update other (manager ruling R-17 (a), (b); M4 QA round 5, findings 10, 13, 16-26: poppler no longer finds startxref, rebuilds the cross-reference data and paints object text it finds in an update's stream data)",
    ),
    (
        "parser_tail_pad_nul",
        "pyHanko 0.37 cannot read the file (PdfReadError: EOF marker not found: 40,000 NUL bytes follow the fill's %%EOF, so no %%EOF is in the last 1,024 bytes); Folioxide reads the signed revision and makes the update other (manager ruling R-17 (a), (b); M4 QA round 5, findings 10, 13, 16-26: poppler no longer finds startxref, rebuilds the cross-reference data and paints object text it finds in an update's stream data)",
    ),
    (
        "parser_tail_pad_crlf",
        "pyHanko 0.37 cannot read the file (PdfReadError: EOF marker not found: 20,000 CR LF pairs follow the fill's %%EOF, so no %%EOF is in the last 1,024 bytes); Folioxide reads the signed revision and makes the update other (manager ruling R-17 (a), (b); M4 QA round 5, findings 10, 13, 16-26: poppler no longer finds startxref, rebuilds the cross-reference data and paints object text it finds in an update's stream data)",
    ),
    (
        "parser_tail_pad_comment",
        "pyHanko 0.37 cannot read the file (PdfReadError: EOF marker not found: 31,500 bytes of comment lines follow the fill's %%EOF, so no %%EOF is in the last 1,024 bytes); Folioxide reads the signed revision and makes the update other (manager ruling R-17 (a), (b); M4 QA round 5, findings 10, 13, 16-26: poppler no longer finds startxref, rebuilds the cross-reference data and paints object text it finds in an update's stream data)",
    ),
    (
        "parser_tail_pad_mixed",
        "pyHanko 0.37 cannot read the file (PdfReadError: EOF marker not found: 40,000 bytes of form feeds, tabs, spaces, end-of-lines and comments follow the fill's %%EOF, so no %%EOF is in the last 1,024 bytes); Folioxide reads the signed revision and makes the update other (manager ruling R-17 (a), (b); M4 QA round 5, findings 10, 13, 16-26: poppler no longer finds startxref, rebuilds the cross-reference data and paints object text it finds in an update's stream data)",
    ),
    (
        "sigfield_rect_multisign",
        "pyHanko 0.37 cannot read the file (ValueError: invalid literal for int(): '--341'); \
         Folioxide makes the update other (ruling R-12; QA variants R5z-rect-multisign-last, \
         R5z-rect-plusminus)",
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
        .chain(MORE_LENIENT)
        .find(|(c, f, ..)| *c == case && *f == field)
        .map(|(_, _, _, pyhanko, _)| *pyhanko)
}

/// Our value of `field` for `case` when the case has a deliberate difference there.
pub fn our_value(case: &str, field: &str) -> Option<&'static str> {
    DELIBERATE_DIFFERENCES
        .iter()
        .chain(MORE_LENIENT)
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
    let pyhanko_cannot_read = |base, name, generate| AttackCase {
        name,
        generate,
        reference: PyhankoRaises,
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
        on(
            Base::InfoMetadata,
            "metadata_changed_not_well_formed",
            mutators::metadata_changed_not_well_formed,
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
        // ---- M4 §5.4: generic form filling, controls (FormFilling = pyHanko) ----
        on(
            Base::Form,
            "form_fill_text_value_and_ap",
            mutators::form_fill_text_value_and_ap as Generator,
        ),
        on(
            Base::Form,
            "form_fill_text_value_only",
            mutators::form_fill_text_value_only,
        ),
        on(
            Base::Form,
            "form_fill_inplace_ap",
            mutators::form_fill_inplace_ap,
        ),
        on(
            Base::Form,
            "form_fill_checkbox_on",
            mutators::form_fill_checkbox_on,
        ),
        on(
            Base::Form,
            "form_fill_radio_value_only",
            mutators::form_fill_radio_value_only,
        ),
        on(Base::Form, "form_fill_choice", mutators::form_fill_choice),
        on(
            Base::FormTagged,
            "form_fill_tagged_objr",
            mutators::form_fill_tagged_objr,
        ),
        on(
            Base::Form,
            "form_fill_dr_font_added",
            mutators::form_fill_dr_font_added,
        ),
        on(
            Base::Form,
            "form_fill_value_removed",
            mutators::form_fill_value_removed,
        ),
        // ---- generic form filling, stricter than pyHanko (M4 §0.1) ----
        on(
            Base::FormHidden,
            "form_widget_unhidden",
            mutators::form_widget_unhidden,
        ),
        on(
            Base::Form,
            "form_widget_hidden",
            mutators::form_widget_hidden,
        ),
        on(
            Base::Form,
            "form_field_da_changed",
            mutators::form_field_da_changed,
        ),
        on(
            Base::Form,
            "form_field_q_changed",
            mutators::form_field_q_changed,
        ),
        on(
            Base::Form,
            "form_field_ff_changed",
            mutators::form_field_ff_changed,
        ),
        on(
            Base::Form,
            "form_ap_changed_without_value",
            mutators::form_ap_changed_without_value,
        ),
        on(
            Base::Form,
            "form_checkbox_ap_replaced",
            mutators::form_checkbox_ap_replaced,
        ),
        on(
            Base::FormReadOnly,
            "form_readonly_field_filled",
            mutators::form_readonly_field_filled,
        ),
        on(
            Base::FormXfa,
            "form_fill_with_xfa",
            mutators::form_fill_with_xfa,
        ),
        on(
            Base::Form,
            "form_as_unknown_state",
            mutators::form_as_unknown_state,
        ),
        on(
            Base::Form,
            "form_value_indirect",
            mutators::form_value_indirect,
        ),
        on(
            Base::Form,
            "form_checkbox_as_without_value",
            mutators::form_checkbox_as_without_value,
        ),
        // ---- generic form filling, OTHER for both ----
        // M4 brief §0.1 expected pyHanko to allow filling a field its FieldMDP does not lock;
        // pyHanko 0.37 reports OTHER ("Update of Reference(idnum=20) is not allowed because the
        // form field Country is locked", for a fill of Amount), so the case is equal-strict.
        on(
            Base::FormFieldMdp,
            "form_fill_under_own_fieldmdp",
            mutators::form_fill_under_own_fieldmdp,
        ),
        on(Base::Form, "form_fill_radio_b", mutators::form_fill_radio_b),
        on(
            Base::FormSplit,
            "form_kid_widget_ap",
            mutators::form_kid_widget_ap,
        ),
        on(
            Base::Form,
            "form_widget_rect_moved",
            mutators::form_widget_rect_moved,
        ),
        on(Base::Form, "form_mk_added", mutators::form_mk_added),
        on(Base::Form, "form_dv_set", mutators::form_dv_set),
        on(Base::Form, "form_tu_set", mutators::form_tu_set),
        on(Base::Form, "form_kid_added", mutators::form_kid_added),
        on(
            Base::Form,
            "form_field_renamed",
            mutators::form_field_renamed,
        ),
        on(
            Base::FormOrphanWidget,
            "form_orphan_widget_as_changed",
            mutators::form_orphan_widget_as_changed,
        ),
        on(
            Base::FormApSharedWithPage,
            "form_inplace_ap_shared_with_page",
            mutators::form_inplace_ap_shared_with_page,
        ),
        // ---- M4 §5.2: annotations (D-1) after an approval signature ----
        on(
            Base::Ours,
            "approval_markup_annotation_added",
            mutators::markup_square,
        ),
        // ---- annotations refused under P = 3 (OTHER for both) ----
        on(
            Base::CertifiedP3Annotated,
            "annots_link_uri",
            mutators::annots_link_uri,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_js_action",
            mutators::annots_js_action,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_file_attachment",
            mutators::annots_file_attachment,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_widget_added",
            mutators::annots_widget_added,
        ),
        on(Base::CertifiedP3Annotated, "annots_oc", mutators::annots_oc),
        on(
            Base::CertifiedP3Annotated,
            "annots_noview_print",
            mutators::annots_noview_print,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_popup_foreign_parent",
            mutators::annots_popup_foreign_parent,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_existing_removed",
            mutators::annots_existing_removed,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_existing_modified",
            mutators::annots_existing_modified,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_reordered",
            mutators::annots_reordered,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_redact",
            mutators::annots_redact,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_structparent",
            mutators::annots_structparent,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_popup_without_parent",
            mutators::annots_popup_without_parent,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_irt_unlisted",
            mutators::annots_irt_unlisted,
        ),
        // ---- new signature widgets (M4 QA round 1, ruling R-3; finding R5): OTHER ----
        on(
            Base::Ours,
            "sigfield_flags_nozoom",
            mutators::sigfield_flags_nozoom,
        ),
        on(
            Base::Ours,
            "sigfield_flags_hidden",
            mutators::sigfield_flags_hidden,
        ),
        on(
            Base::Ours,
            "sigfield_flags_noview",
            mutators::sigfield_flags_noview,
        ),
        on(
            Base::Ours,
            "sigfield_flags_toggle_noview",
            mutators::sigfield_flags_toggle_noview,
        ),
        on(
            Base::Ours,
            "sigfield_invisible_flags_hidden",
            mutators::sigfield_invisible_flags_hidden,
        ),
        on(
            Base::RotatedPages,
            "sigfield_norotate_rotated_page",
            mutators::sigfield_norotate_rotated_page,
        ),
        on(
            Base::Ours,
            "sigfield_ap_no_bbox",
            mutators::sigfield_ap_no_bbox,
        ),
        on(
            Base::Ours,
            "sigfield_ap_no_subtype",
            mutators::sigfield_ap_no_subtype,
        ),
        on(
            Base::Ours,
            "sigfield_ap_state_dict",
            mutators::sigfield_ap_state_dict,
        ),
        on(
            Base::Ours,
            "sigfield_ap_page_content",
            mutators::sigfield_ap_page_content,
        ),
        on(
            Base::Form,
            "existing_field_signed_ap_no_bbox",
            existing_field_signed_ap_no_bbox,
        ),
        on(
            Base::Form,
            "form_fill_ap_no_bbox",
            mutators::form_fill_ap_no_bbox,
        ),
        // M4 QA round 4, findings 4 and 13: geometry beyond ±10^7.
        on(
            Base::Form,
            "form_fill_ap_matrix_magnitude",
            mutators::form_fill_ap_matrix_magnitude,
        ),
        on(
            Base::Ours,
            "sigfield_rect_magnitude",
            mutators::sigfield_rect_magnitude,
        ),
        on(
            Base::FormApMissingFont,
            "form_dr_adds_name_missing_from_ap_resources",
            mutators::form_dr_adds_name_missing_from_ap_resources,
        ),
        // ---- M4 QA round 2: where new and signed widgets paint: OTHER ----
        on(
            Base::FormApPattern,
            "form_dr_adds_name_used_in_ap_pattern",
            mutators::form_dr_adds_name_missing_from_ap_resources,
        ),
        on(
            Base::FormApType3,
            "form_dr_adds_name_used_in_ap_type3_glyph",
            mutators::form_dr_adds_name_missing_from_ap_resources,
        ),
        // M4 QA round 4, finding 12: what the /DR guard reads, indirect subtypes and page-level
        // resources included.
        on(
            Base::FormApIndirectSubtype,
            "form_dr_adds_name_used_in_ap_indirect_subtype",
            mutators::form_dr_adds_name_missing_from_ap_resources,
        ),
        on(
            Base::FormApType3IndirectSubtype,
            "form_dr_adds_name_used_in_ap_type3_indirect_subtype",
            mutators::form_dr_adds_name_missing_from_ap_resources,
        ),
        on(
            Base::FormApPageLevelForm,
            "form_dr_adds_name_used_in_ap_page_level_form",
            mutators::form_dr_adds_name_missing_from_ap_resources,
        ),
        on(
            Base::Ours,
            "sigfield_rect_null_entry",
            mutators::sigfield_rect_null_entry,
        ),
        on(
            Base::Ours,
            "sigfield_rect_string_entry",
            mutators::sigfield_rect_string_entry,
        ),
        on(
            Base::Ours,
            "sigfield_rect_wrong_length",
            mutators::sigfield_rect_wrong_length,
        ),
        on(
            Base::FormFlagged,
            "existing_field_signed_flags_norotate",
            existing_field_signed_flags_norotate,
        ),
        on(
            Base::FormFlagged,
            "existing_field_signed_flags_nozoom",
            existing_field_signed_flags_nozoom,
        ),
        on(
            Base::FormFlagged,
            "existing_field_signed_flags_hidden",
            existing_field_signed_flags_hidden,
        ),
        on(
            Base::FormFlagged,
            "existing_field_signed_flags_noview",
            existing_field_signed_flags_noview,
        ),
        on(
            Base::FormFlagged,
            "existing_field_hidden_signed_invisibly",
            existing_field_hidden_signed_invisibly,
        ),
        on(
            Base::FormFlagged,
            "form_fill_norotate_widget_rotated_page",
            mutators::form_fill_text_value_and_ap,
        ),
        on(
            Base::FormFlagged,
            "form_checkbox_norotate_rotated_page",
            mutators::form_fill_checkbox_on,
        ),
        on(
            Base::CertifiedP3Rotated,
            "annots_text_rotated_page_90",
            mutators::annots_text_rotated_page_90,
        ),
        on(
            Base::CertifiedP3Rotated,
            "annots_text_rotated_page_180",
            mutators::annots_text_rotated_page_180,
        ),
        on(
            Base::CertifiedP3Rotated,
            "annots_text_rotated_page_270",
            mutators::annots_text_rotated_page_270,
        ),
        on(
            Base::CertifiedP3RotatedTree,
            "annots_text_inherited_rotate",
            mutators::markup_text_popup,
        ),
        on(
            Base::RotatedPages,
            "approval_text_rotated_page",
            mutators::annots_text_rotated_page_90,
        ),
        // ---- markup annotations that draw outside their /Rect (ruling R-2): OTHER ----
        on(
            Base::CertifiedP3Annotated,
            "annots_highlight_quadpoints_outside",
            mutators::annots_highlight_quadpoints_outside,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_highlight_no_ap",
            mutators::annots_highlight_no_ap,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_underline_quadpoints_outside",
            mutators::annots_underline_quadpoints_outside,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_ink_inklist_outside",
            mutators::annots_ink_inklist_outside,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_line_outside",
            mutators::annots_line_outside,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_polygon_vertices_outside",
            mutators::annots_polygon_vertices_outside,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_text_no_ap",
            mutators::annots_text_no_ap,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_text_nozoom",
            mutators::annots_text_nozoom,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_square_negative_rd",
            mutators::annots_square_negative_rd,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_square_ap_no_bbox",
            mutators::annots_square_ap_no_bbox,
        ),
        on(
            Base::CertifiedP3Annotated,
            "annots_square_ap_page_content",
            mutators::annots_square_ap_page_content,
        ),
        on(
            Base::Ours,
            "approval_highlight_quadpoints_outside",
            mutators::annots_highlight_quadpoints_outside,
        ),
        // ---- parser differentials after signing (M4 QA round 1, ruling R-1): OTHER ----
        on(
            Base::Form,
            "parser_relist_control",
            mutators::parser_relist_control,
        ),
        on(
            Base::Form,
            "parser_dup_key_rect_moved_first",
            mutators::parser_dup_key_rect_moved_first,
        ),
        on(
            Base::Form,
            "parser_dup_key_rect_original_first",
            mutators::parser_dup_key_rect_original_first,
        ),
        on(
            Base::Form,
            "parser_dup_key_flags_hidden_first",
            mutators::parser_dup_key_flags_hidden_first,
        ),
        on(
            Base::Form,
            "parser_dup_key_value_evil_first",
            mutators::parser_dup_key_value_evil_first,
        ),
        on(
            Base::Form,
            "parser_dup_key_ap_page_content_first",
            mutators::parser_dup_key_ap_page_content_first,
        ),
        on(
            Base::Form,
            "parser_dup_key_ap_n_reverse",
            mutators::parser_dup_key_ap_n_reverse,
        ),
        on(
            Base::Form,
            "parser_dup_key_checkbox_state_first",
            mutators::parser_dup_key_checkbox_state_first,
        ),
        on(
            Base::Form,
            "parser_dup_key_page_annots_empty_first",
            mutators::parser_dup_key_page_annots_empty_first,
        ),
        on(
            Base::Form,
            "parser_dup_key_page_contents_new_first",
            mutators::parser_dup_key_page_contents_new_first,
        ),
        on(
            Base::Form,
            "parser_dup_key_trailer_root_new_first",
            mutators::parser_dup_key_trailer_root_new_first,
        ),
        on(
            Base::Form,
            "parser_dup_key_catalog_pages_new_first",
            mutators::parser_dup_key_catalog_pages_new_first,
        ),
        on(
            Base::CertifiedP3Annotated,
            "parser_dup_key_annotation_rect_new_first",
            mutators::parser_dup_key_annotation_rect_new_first,
        ),
        on(
            Base::Form,
            "parser_xref_lists_number_twice",
            mutators::parser_xref_lists_number_twice,
        ),
        on(
            Base::Form,
            "parser_objstm_object_twice",
            mutators::parser_objstm_object_twice,
        ),
        // ---- M4 QA round 3, ruling R-12: bytes readers read differently: OTHER ----
        AttackCase {
            name: "parser_relisted_flags_multisign",
            generate: mutators::parser_relisted_flags_multisign,
            reference: PyhankoRaises,
            base: Base::FormHidden,
        },
        AttackCase {
            name: "parser_relisted_rect_multisign",
            generate: mutators::parser_relisted_rect_multisign,
            reference: PyhankoRaises,
            base: Base::Form,
        },
        on(
            Base::Form,
            "parser_relisted_rect_plus_control",
            mutators::parser_relisted_rect_plus_control,
        ),
        on(
            Base::Ours,
            "sigfield_rect_integer_overflow",
            mutators::sigfield_rect_integer_overflow,
        ),
        on(
            Base::Ours,
            "sigfield_rect_int32_min",
            mutators::sigfield_rect_int32_min,
        ),
        AttackCase {
            name: "sigfield_rect_multisign",
            generate: mutators::sigfield_rect_multisign,
            reference: PyhankoRaises,
            base: Base::Ours,
        },
        // ---- M4 QA round 4, finding 2: integers padded with leading zeros ----
        on(
            Base::Ours,
            "sigfield_rect_zero_padded",
            mutators::sigfield_rect_zero_padded,
        ),
        on(
            Base::Ours,
            "sigfield_rect_zero_padded_x1",
            mutators::sigfield_rect_zero_padded_x1,
        ),
        on(
            Base::Form,
            "parser_relisted_rect_zero_padded",
            mutators::parser_relisted_rect_zero_padded,
        ),
        // ---- M4 QA round 4, finding 3: bytes of an update its section does not list ----
        on(
            Base::Form,
            "parser_unlisted_object_body",
            mutators::parser_unlisted_object_body,
        ),
        on(
            Base::Form,
            "parser_junk_before_startxref",
            mutators::parser_junk_before_startxref,
        ),
        on(
            Base::FormHidden,
            "parser_relisted_flags_zero_padded",
            mutators::parser_relisted_flags_zero_padded,
        ),
        AttackCase {
            name: "parser_relisted_page_contents_zero_padded",
            generate: mutators::parser_relisted_page_contents_zero_padded,
            reference: PyhankoRaises,
            base: Base::Ours,
        },
        on(
            Base::CertifiedP3Annotated,
            "annots_square_rect_integer_overflow",
            mutators::annots_square_rect_integer_overflow,
        ),
        on(
            Base::FormSignedDupRect,
            "form_signed_dup_rect_clean_fill",
            mutators::form_fill_text_value_and_ap,
        ),
        on(
            Base::FormSignedDupCheckbox,
            "form_signed_dup_checkbox_relisted",
            mutators::form_agree_relisted,
        ),
        on(
            Base::FormApSharedFirstWins,
            "form_inplace_ap_shared_first_wins",
            mutators::form_inplace_ap_shared_with_page,
        ),
        // ---- M4 QA round 4, finding 1: the hidden use one, two and three hops away ----
        on(
            Base::FormApHiddenOneHop,
            "form_inplace_ap_hidden_one_hop",
            mutators::form_inplace_ap_shared_with_page,
        ),
        on(
            Base::FormApHiddenTwoHops,
            "form_inplace_ap_hidden_two_hops",
            mutators::form_inplace_ap_shared_with_page,
        ),
        on(
            Base::FormApHiddenThreeHops,
            "form_inplace_ap_hidden_three_hops",
            mutators::form_inplace_ap_shared_with_page,
        ),
        // ---- ruling R-13: a page every reader places the same way ----
        on(
            Base::CertifiedP3TreeWithoutParent,
            "annots_text_page_without_parent",
            mutators::markup_text_popup,
        ),
        on(
            Base::CertifiedP3TreeParentElsewhere,
            "annots_text_parent_chain_upright",
            mutators::markup_text_popup,
        ),
        // M4 QA round 4, finding 10: a /Type /Page with /Kids.
        on(
            Base::CertifiedP3PageWithKids,
            "annots_text_page_with_kids",
            mutators::markup_text_popup,
        ),
        // ---- findings 6 and 21: the /DR guard reads graphics states ----
        on(
            Base::FormApExtGStateSMask,
            "form_dr_adds_name_used_in_ap_extgstate_smask",
            mutators::form_dr_adds_name_missing_from_ap_resources,
        ),
        on(
            Base::FormApExtGStateFont,
            "form_dr_adds_name_used_in_ap_extgstate_font",
            mutators::form_dr_adds_name_missing_from_ap_resources,
        ),
        // ---- findings 19 and 20: metadata pyHanko does not read as XMP ----
        on(
            Base::InfoMetadata,
            "metadata_xmp_comment_over_lxml_limit",
            mutators::metadata_xmp_comment_over_lxml_limit,
        ),
        on(
            Base::InfoMetadata,
            "metadata_xmp_name_over_lxml_limit",
            mutators::metadata_xmp_name_over_lxml_limit,
        ),
        on(
            Base::InfoMetadata,
            "metadata_flate_bad_adler",
            mutators::metadata_flate_bad_adler,
        ),
        on(
            Base::InfoMetadata,
            "metadata_runlength",
            mutators::metadata_runlength,
        ),
        on(
            Base::InfoMetadata,
            "metadata_ascii85_without_eod",
            mutators::metadata_ascii85_without_eod,
        ),
        // ---- M4 QA round 4, finding 11: a FlateDecode before an ASCII filter ----
        on(
            Base::InfoMetadata,
            "metadata_flate_then_ahx",
            mutators::metadata_flate_then_ahx,
        ),
        on(
            Base::InfoMetadata,
            "metadata_flate_then_a85",
            mutators::metadata_flate_then_a85,
        ),
        on(
            Base::InfoMetadata,
            "metadata_flate_crypt_ahx",
            mutators::metadata_flate_crypt_ahx,
        ),
        on(
            Base::InfoMetadata,
            "metadata_flate_flate_ahx",
            mutators::metadata_flate_flate_ahx,
        ),
        // ---- M4 QA round 5, ruling R-17: updates a rebuilding reader reads otherwise ----
        pyhanko_cannot_read(
            Base::Form,
            "parser_tail_pad_lf",
            mutators::parser_tail_pad_lf,
        ),
        pyhanko_cannot_read(
            Base::Form,
            "parser_tail_pad_space",
            mutators::parser_tail_pad_space,
        ),
        pyhanko_cannot_read(
            Base::Form,
            "parser_tail_pad_nul",
            mutators::parser_tail_pad_nul,
        ),
        pyhanko_cannot_read(
            Base::Form,
            "parser_tail_pad_crlf",
            mutators::parser_tail_pad_crlf,
        ),
        pyhanko_cannot_read(
            Base::Form,
            "parser_tail_pad_comment",
            mutators::parser_tail_pad_comment,
        ),
        pyhanko_cannot_read(
            Base::Form,
            "parser_tail_pad_mixed",
            mutators::parser_tail_pad_mixed,
        ),
        on(
            Base::Form,
            "parser_tail_extra_eol",
            mutators::parser_tail_extra_eol,
        ),
        on(
            Base::Form,
            "parser_fake_object_in_ap_stream",
            mutators::parser_fake_object_in_ap_stream,
        ),
        on(
            Base::Form,
            "parser_fake_object_in_value_string",
            mutators::parser_fake_object_in_value_string,
        ),
        on(
            Base::Form,
            "parser_startxref_corrupted",
            mutators::parser_startxref_corrupted,
        ),
        // ---- closing round, finding 13: a /Size below the objects the file defines ----
        on(
            Base::Form,
            "parser_trailer_size_shrunk",
            mutators::parser_trailer_size_shrunk,
        ),
        on(
            Base::Form,
            "parser_trailer_size_shrunk_info_only",
            mutators::parser_trailer_size_shrunk_info_only,
        ),
        on(
            Base::Form,
            "parser_trailer_size_off_by_one",
            mutators::parser_trailer_size_off_by_one,
        ),
        // ---- final fix round 2 (verification), expert finding 1: an over-declared /Size, then
        // our own co-signature ----
        case(
            "parser_trailer_size_over_declared_info_only",
            size_over_declared_info_only,
            Status,
        ),
        case(
            "parser_trailer_size_over_declared_then_cosigned",
            size_over_declared_then_cosigned,
            Status,
        ),
        // ---- final fix round 2, finding 3: structure words inside a line are no structure ----
        on(
            Base::Form,
            "parser_honest_fill_structure_words",
            mutators::parser_honest_fill_structure_words,
        ),
        // ---- closing round, findings 2 and 6: a 4 MiB digit line is read in linear time ----
        on(
            Base::Form,
            "parser_ap_stream_long_digit_line",
            mutators::parser_ap_stream_long_digit_line,
        ),
        // ---- ruling R-18: object streams whose members no section lists ----
        on(
            Base::Ours,
            "parser_objstm_member_unlisted",
            mutators::parser_objstm_member_unlisted,
        ),
        // ---- ruling R-21: tables and geometry written canonically ----
        on(
            Base::Form,
            "parser_xref_subsection_padded",
            mutators::parser_xref_subsection_padded,
        ),
        on(
            Base::Form,
            "parser_xref_entries_19_bytes",
            mutators::parser_xref_entries_19_bytes,
        ),
        on(
            Base::Form,
            "form_fill_ap_matrix_small_bbox",
            mutators::form_fill_ap_matrix_small_bbox,
        ),
        on(
            Base::Ours,
            "sigfield_ap_matrix_small_bbox",
            mutators::sigfield_ap_matrix_small_bbox,
        ),
        // ---- final fix round 2, findings 2 and 4: tiny boxes scaled onto the /Rect ----
        on(
            Base::Form,
            "form_fill_ap_tiny_bbox_translate_1e5",
            mutators::form_fill_ap_tiny_bbox_translate_1e5,
        ),
        on(
            Base::Form,
            "form_fill_ap_matrix_tiny_bbox",
            mutators::form_fill_ap_matrix_tiny_bbox,
        ),
        on(
            Base::Ours,
            "sigfield_ap_tiny_bbox_translate_1e5",
            mutators::sigfield_ap_tiny_bbox_translate_1e5,
        ),
        on(
            Base::Ours,
            "sigfield_ap_matrix_tiny_bbox",
            mutators::sigfield_ap_matrix_tiny_bbox,
        ),
        // ---- ruling R-19: a field's appearance dictionary used in several contexts ----
        on(
            Base::FormApDictIndirect,
            "form_ap_dict_indirect_fill_control",
            mutators::form_fill_text_value_and_ap,
        ),
        on(
            Base::FormApDictShared,
            "form_ap_dict_shared_repointed",
            mutators::form_fill_text_value_and_ap,
        ),
        on(
            Base::FormApDictShared,
            "form_ap_dict_shared_unrelated_fill",
            mutators::form_fill_choice,
        ),
        on(
            Base::FormApDictShared,
            "form_ap_dict_shared_info_only",
            mutators::isa_info_only,
        ),
        on(
            Base::FormApDictHiddenCarrier,
            "form_ap_dict_shared_hidden_carrier",
            mutators::form_fill_choice,
        ),
        // ---- final fix round 2, finding 1: two unsigned signature fields share an /AP dict ----
        on(
            Base::FormSigApDictShared,
            "sigfield_ap_dict_shared_signed_next",
            sign_visible_field_invisibly,
        ),
        on(
            Base::FormSigApDictShared,
            "sigfield_ap_dict_shared_visible_next",
            sign_visible_field_with_appearance,
        ),
        on(
            Base::CertifiedP2SigApDictShared,
            "sigfield_ap_dict_shared_cert2_then_second",
            sign_visible_field_invisibly,
        ),
        on(
            Base::FormSigApDictPrivate,
            "sigfield_ap_dict_shared_control_private",
            sign_visible_field_invisibly,
        ),
        on(
            Base::FormSigApDictShared,
            "sigfield_ap_dict_shared_unrelated_fill",
            mutators::form_fill_text_value_and_ap,
        ),
        // ---- closing round, finding 10: non-terminal field parents share an /AP dict ----
        on(
            Base::FormApDictSharedParents,
            "form_ap_dict_shared_nonterminal_parents",
            cosign,
        ),
        on(
            Base::CertifiedP2ApDictSharedParents,
            "form_ap_dict_shared_nonterminal_parents_cert2",
            cosign,
        ),
        on(
            Base::FormApDictPrivateParents,
            "form_ap_dict_private_nonterminal_parents",
            cosign,
        ),
        on(
            Base::CertifiedP2ApDictPrivateParents,
            "form_ap_dict_private_nonterminal_parents_cert2",
            cosign,
        ),
        // ---- finding 29: what the /DR guard reads when a stream's resources lack a category ----
        on(
            Base::FormApPageLevelFormOwnResEmpty,
            "form_dr_adds_name_used_in_ap_ownres_empty",
            mutators::form_dr_adds_name_missing_from_ap_resources,
        ),
        on(
            Base::FormApPageLevelFormFontOnly,
            "form_dr_adds_name_used_in_ap_ownres_font_only",
            mutators::form_dr_adds_name_missing_from_ap_resources,
        ),
        on(
            Base::FormApPageLevelFormParentMismatch,
            "form_dr_adds_name_used_in_ap_parent_mismatch",
            mutators::form_dr_adds_name_missing_from_ap_resources,
        ),
    ]
}

// =================================================================================================
// The certification corpus (M4 brief §5.4 "Certification", §6.3 suite `certify`).
// =================================================================================================

/// One case of the certification corpus: a certified document, maybe changed after signing.
pub struct CertifyCase {
    /// The case name: the `certify_<name>` test and the oracle case.
    pub name: &'static str,
    /// Builds the file.
    pub build: fn() -> Vec<u8>,
    /// Whether the `certify` oracle suite checks it (a case whose document timestamp carries a
    /// placeholder token is Rust-only: pyHanko validates the token).
    pub oracle: bool,
    /// The oracle checks that fail by design, with the reason (`knownFailures`): the pyHanko
    /// rows of a signature whose DocMDP declaration pyHanko cannot read (it raises; manager
    /// ruling R-6).
    pub known_failures: &'static [(&'static str, &'static str)],
}

/// `certify(source, p)` then `change` (`None`: nothing after the certification).
fn certified_then(source: Vec<u8>, p: DocMdpPermissions, change: Option<Generator>) -> Vec<u8> {
    let signed = certify(&source, p);
    match change {
        Some(change) => change(&signed).expect("the change applies"),
        None => signed,
    }
}

/// An approval in the field `field` (existing when `existing`) by our P-256 key.
fn approve(pdf: &[u8], field: &str, existing: bool) -> Vec<u8> {
    let spec = FieldSpec::new().with_name(Some(field.to_owned()));
    let spec = if existing {
        spec.with_mode(FieldMode::ExistingOnly)
    } else {
        spec
    };
    super::sign_with(
        pdf,
        &super::p256(),
        SignatureOptions::new(super::time()).with_field(spec),
    )
}

/// A new visible approval (raw: Folioxide refuses to sign it, D-3), over the page heading.
fn visible_approval(pdf: &[u8]) -> Vec<u8> {
    super::sign_raw(
        pdf,
        &super::p256(),
        &super::RawSignature {
            name: "Approval".to_owned(),
            rect: [72, 600, 300, 660],
            appearance: Some(b"q 0 0 1 rg 0 0 228 60 re f Q".to_vec()),
            ..super::RawSignature::default()
        },
    )
}

/// On a document with a pyHanko XMP packet certified with P = 1, a document timestamp whose
/// revision rewrites the packet with `date` and the raw attribute text `extra`
/// ([`mutators::doc_timestamp_with_xmp`]).
pub fn certified_p1_xmp_dts(date: &str, extra: &str) -> Vec<u8> {
    let input = mutators::pyhanko_xmp_input(&syntax::minimal()).expect("XMP input");
    let signed = certify(&input, DocMdpPermissions::NoChanges);
    mutators::doc_timestamp_with_xmp(&signed, date, extra).expect("the timestamp applies")
}

/// On a document with a pyHanko XMP packet certified with P = 1, a document timestamp whose
/// revision rewrites the packet with the raw text `prolog` before it
/// ([`mutators::doc_timestamp_with_xmp_prolog`]).
pub fn certified_p1_xmp_prolog(prolog: &str) -> Vec<u8> {
    let input = mutators::pyhanko_xmp_input(&syntax::minimal()).expect("XMP input");
    let signed = certify(&input, DocMdpPermissions::NoChanges);
    mutators::doc_timestamp_with_xmp_prolog(&signed, prolog).expect("the timestamp applies")
}

/// On a document with a pyHanko XMP packet certified with P = 1, a document timestamp whose
/// revision rewrites the packet encoded for a FlateDecode-then-ASCII chain
/// ([`mutators::doc_timestamp_with_xmp_flate_then_ascii`]).
pub fn certified_p1_xmp_flate_then_ascii(ascii85: bool, crypt: bool, twice: bool) -> Vec<u8> {
    let input = mutators::pyhanko_xmp_input(&syntax::minimal()).expect("XMP input");
    let signed = certify(&input, DocMdpPermissions::NoChanges);
    mutators::doc_timestamp_with_xmp_flate_then_ascii(&signed, ascii85, crypt, twice)
        .expect("the timestamp applies")
}

/// Every certification case, in the order of brief §6.3.
pub fn certify_corpus() -> Vec<CertifyCase> {
    use DocMdpPermissions::{FormFilling as P2, FormFillingAndAnnotations as P3, NoChanges as P1};
    let case = |name, build| CertifyCase {
        name,
        build,
        oracle: true,
        known_failures: &[],
    };
    let rust_only = |name, build| CertifyCase {
        name,
        build,
        oracle: false,
        known_failures: &[],
    };
    let pyhanko_raises = |name, build| CertifyCase {
        name,
        build,
        oracle: true,
        known_failures: PYHANKO_DOCMDP_RAISES,
    };
    let signed_dupkey = |name, build| CertifyCase {
        name,
        build,
        oracle: true,
        known_failures: SIGNED_DUPLICATE_KEY,
    };
    vec![
        case("certify_p1_alone", || {
            certified_then(syntax::minimal(), P1, None)
        }),
        case("certify_p2_alone", || {
            certified_then(syntax::minimal(), P2, None)
        }),
        case("certify_p3_alone", || {
            certified_then(syntax::minimal(), P3, None)
        }),
        case("certify_p2_text_fill", || {
            certified_then(
                forms::acroform(),
                P2,
                Some(mutators::form_fill_text_value_and_ap),
            )
        }),
        case("certify_p2_checkbox_fill", || {
            certified_then(forms::acroform(), P2, Some(mutators::form_fill_checkbox_on))
        }),
        case("certify_p2_approval", || {
            approve(
                &certified_then(syntax::minimal(), P2, None),
                "Approval",
                false,
            )
        }),
        case("certify_p2_existing_visible_signed", || {
            approve(
                &certified_then(forms::acroform(), P2, None),
                forms::VISIBLE,
                true,
            )
        }),
        case("certify_p1_fill", || {
            certified_then(
                forms::acroform(),
                P1,
                Some(mutators::form_fill_text_value_and_ap),
            )
        }),
        case("certify_p1_info_changed", || {
            certified_then(syntax::minimal(), P1, Some(mutators::isa_info_only))
        }),
        case("certify_p1_xmp_changed", || {
            let input = mutators::info_metadata_input(&syntax::minimal()).expect("XMP input");
            certified_then(input, P1, Some(mutators::metadata_changed_in_place))
        }),
        rust_only("certify_p1_doc_timestamp", || {
            certified_then(
                syntax::minimal(),
                P1,
                Some(mutators::doc_timestamp_like_pyhanko),
            )
        }),
        rust_only("certify_p1_doc_timestamp_title_changed", || {
            certified_then(
                syntax::minimal(),
                P1,
                Some(mutators::doc_timestamp_with_title_changed),
            )
        }),
        rust_only("certify_p1_doc_timestamp_xmp", || {
            let input = mutators::pyhanko_xmp_input(&syntax::minimal()).expect("XMP input");
            certified_then(
                input,
                P1,
                Some(mutators::doc_timestamp_with_xmp_bookkeeping),
            )
        }),
        rust_only("certify_p1_doc_timestamp_xmp_title_changed", || {
            let input = mutators::pyhanko_xmp_input(&syntax::minimal()).expect("XMP input");
            certified_then(
                input,
                P1,
                Some(mutators::doc_timestamp_with_xmp_title_changed),
            )
        }),
        // Manager ruling R-8: the bookkeeping exemptions hold only for what the timestamp's own
        // revision writes (QA findings 24 and 32).
        rust_only("certify_p1_doc_timestamp_then_info_bookkeeping", || {
            certified_then(
                syntax::minimal(),
                P1,
                Some(mutators::doc_timestamp_then_info_bookkeeping),
            )
        }),
        rust_only("certify_p1_doc_timestamp_then_xmp_bookkeeping", || {
            let input = mutators::pyhanko_xmp_input(&syntax::minimal()).expect("XMP input");
            certified_then(
                input,
                P1,
                Some(mutators::doc_timestamp_then_xmp_bookkeeping),
            )
        }),
        // M4 QA round 2, finding 21: a later revision that lists the timestamp's dictionary
        // again adds no timestamp, so its /Info rewrite is Metadata.
        rust_only(
            "certify_p1_doc_timestamp_then_relisted_with_info_bookkeeping",
            || {
                certified_then(
                    syntax::minimal(),
                    P1,
                    Some(mutators::doc_timestamp_then_relisted_with_info_bookkeeping),
                )
            },
        ),
        // QA finding 22: the timestamp's XMP rewrite must be well-formed XML.
        rust_only("certify_p1_doc_timestamp_xmp_value_lt", || {
            certified_p1_xmp_dts("2026<10", "")
        }),
        rust_only("certify_p1_doc_timestamp_xmp_undefined_entity", || {
            certified_p1_xmp_dts("&bogus;", "")
        }),
        rust_only("certify_p1_doc_timestamp_xmp_bad_charref", || {
            certified_p1_xmp_dts("&#0;", "")
        }),
        rust_only("certify_p1_doc_timestamp_xmp_dup_attribute", || {
            certified_p1_xmp_dts(
                "2026-10-11T05:25:27+00:00",
                " xmp:ModifyDate=\"2026-10-11T05:25:28+00:00\"",
            )
        }),
        rust_only(
            "certify_p1_doc_timestamp_xmp_attribute_without_value",
            || certified_p1_xmp_dts("2026-10-11T05:25:27+00:00", " broken"),
        ),
        // M4 QA round 2, findings 18-20 and 24-30 (variants R4x-*, from a differential fuzz
        // against lxml): what lxml refuses, Folioxide refuses too.
        rust_only("certify_p1_doc_timestamp_xmp_hex_charref_sign", || {
            certified_p1_xmp_dts("2026-10-11T05:25:27&#x+30;0:00", "")
        }),
        rust_only("certify_p1_doc_timestamp_xmp_ns_uri_with_space", || {
            certified_p1_xmp_dts(
                "2026-10-11T05:25:27+00:00",
                " xmlns:ex=\"http://example.com/a b\"",
            )
        }),
        rust_only("certify_p1_doc_timestamp_xmp_xmlns_reserved_uri", || {
            certified_p1_xmp_dts(
                "2026-10-11T05:25:27+00:00",
                " xmlns:ex=\"http://www.w3.org/2000/xmlns/\"",
            )
        }),
        rust_only("certify_p1_doc_timestamp_xmp_default_ns_xml", || {
            certified_p1_xmp_dts(
                "2026-10-11T05:25:27+00:00",
                " xmlns=\"http://www.w3.org/XML/1998/namespace\"",
            )
        }),
        rust_only("certify_p1_doc_timestamp_xmp_xmldecl_version_2", || {
            certified_p1_xmp_prolog("<?xml version=\"2.0\"?>")
        }),
        rust_only(
            "certify_p1_doc_timestamp_xmp_xmldecl_standalone_maybe",
            || certified_p1_xmp_prolog("<?xml version=\"1.0\" standalone=\"maybe\"?>"),
        ),
        rust_only("certify_p1_doc_timestamp_xmp_xmldecl_uppercase", || {
            certified_p1_xmp_prolog("<?XML version=\"1.0\"?>")
        }),
        rust_only("certify_p1_doc_timestamp_xmp_xmldecl_not_first", || {
            certified_p1_xmp_prolog("\n<?xml version=\"1.0\"?>")
        }),
        // The control: a valid XML declaration is well-formed XMP (Metadata, not Other).
        rust_only("certify_p1_doc_timestamp_xmp_xmldecl_valid", || {
            certified_p1_xmp_prolog("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>")
        }),
        // M4 QA round 4, finding 11 (variants R4w-dec-flate-*-dts): the timestamp's packet
        // encoded for a chain pyHanko cannot decode (FlateDecode, then an ASCII filter).
        rust_only("certify_p1_doc_timestamp_xmp_flate_then_ahx", || {
            certified_p1_xmp_flate_then_ascii(false, false, false)
        }),
        rust_only("certify_p1_doc_timestamp_xmp_flate_then_a85", || {
            certified_p1_xmp_flate_then_ascii(true, false, false)
        }),
        rust_only("certify_p1_doc_timestamp_xmp_flate_crypt_ahx", || {
            certified_p1_xmp_flate_then_ascii(false, true, false)
        }),
        rust_only("certify_p1_doc_timestamp_xmp_flate_flate_ahx", || {
            certified_p1_xmp_flate_then_ascii(false, false, true)
        }),
        case("certify_p2_new_visible_approval", || {
            visible_approval(&certified_then(syntax::minimal(), P2, None))
        }),
        case("certify_p3_new_visible_approval", || {
            visible_approval(&certified_then(syntax::minimal(), P3, None))
        }),
        case("certify_p2_new_visible_field", || {
            certified_then(
                syntax::minimal(),
                P2,
                Some(mutators::shadow_overlay_sig_widget_registered),
            )
        }),
        case("certify_p1_annotation", || {
            certified_then(syntax::minimal(), P1, Some(mutators::markup_square))
        }),
        case("certify_p2_annotation", || {
            certified_then(syntax::minimal(), P2, Some(mutators::markup_square))
        }),
        case("certify_p3_text_popup", || {
            certified_then(syntax::minimal(), P3, Some(mutators::markup_text_popup))
        }),
        case("certify_p3_highlight", || {
            certified_then(syntax::minimal(), P3, Some(mutators::markup_highlight))
        }),
        case("certify_p3_square", || {
            certified_then(syntax::minimal(), P3, Some(mutators::markup_square))
        }),
        case("certify_p3_ink", || {
            certified_then(syntax::minimal(), P3, Some(mutators::markup_ink))
        }),
        case("certify_p3_freetext", || {
            certified_then(syntax::minimal(), P3, Some(mutators::markup_freetext))
        }),
        case("certify_p3_stamp", || {
            certified_then(syntax::minimal(), P3, Some(mutators::markup_stamp))
        }),
        case("certify_p3_reply", || {
            mutators::annots_reply(&Base::CertifiedP3Annotated.bytes()).expect("the reply")
        }),
        // M4 QA round 2, finding 7: a sticky note is allowed on an upright page only; other
        // markup rotates with its page.
        case("certify_p3_text_upright_page", || {
            mutators::annots_text_upright_page_control(&Base::CertifiedP3Rotated.bytes())
                .expect("the annotation")
        }),
        case("certify_p3_square_rotated_page", || {
            mutators::annots_square_rotated_page_control(&Base::CertifiedP3Rotated.bytes())
                .expect("the annotation")
        }),
        // Manager ruling R-7: an approval in a P = 3 certified document, then a markup
        // annotation (D-1 for both signatures).
        case("certify_p3_approval_then_markup", || {
            let approved = approve(
                &certified_then(syntax::minimal(), P3, None),
                "Approval",
                false,
            );
            mutators::markup_square(&approved).expect("the annotation")
        }),
        // Manager ruling R-4: a signature field lock's /P (ISO 32000-2 §12.7.5.5) sets the
        // signature's DocMDP permissions, as pyHanko's docmdp_level reads it.
        case("lock_p1_alone", || locked_signature(&syntax::minimal(), 1)),
        case("lock_p1_then_invisible_approval", || {
            raw_approval(&locked_signature(&syntax::minimal(), 1), false)
        }),
        case("lock_p1_then_visible_approval", || {
            raw_approval(&locked_signature(&syntax::minimal(), 1), true)
        }),
        case("lock_p2_then_invisible_approval", || {
            approve(&locked_signature(&syntax::minimal(), 2), "Approval", false)
        }),
        case("lock_p2_then_new_visible_approval", || {
            raw_approval(&locked_signature(&syntax::minimal(), 2), true)
        }),
        // M4 QA round 4, expert finding: a field lock's /P that grants more than the
        // certification in force is ignored (ISO 32000-2 §12.7.5.5), so a markup annotation
        // after an approval locked with /P 3 in a P = 2 (or P = 1) document is Other.
        case("lock_p3_after_p2_certification_then_markup", || {
            let approved = locked_approval(&certified_then(syntax::minimal(), P2, None), 3);
            mutators::markup_square(&approved).expect("the annotation")
        }),
        // M4 QA round 5, manager ruling R-20 (finding 14): a document timestamp is judged with
        // the permissions in force, so a markup annotation after it is Other unless P = 3 is in
        // force. Rust-only: the timestamp carries a placeholder token.
        rust_only("certify_p2_doc_timestamp_then_markup", || {
            let stamped = certified_then(
                syntax::minimal(),
                P2,
                Some(mutators::doc_timestamp_like_pyhanko),
            );
            mutators::markup_square(&stamped).expect("the annotation")
        }),
        rust_only("certify_p1_doc_timestamp_then_markup", || {
            let stamped = certified_then(
                syntax::minimal(),
                P1,
                Some(mutators::doc_timestamp_like_pyhanko),
            );
            mutators::markup_square(&stamped).expect("the annotation")
        }),
        rust_only("certify_p3_doc_timestamp_then_markup", || {
            let stamped = certified_then(
                syntax::minimal(),
                P3,
                Some(mutators::doc_timestamp_like_pyhanko),
            );
            mutators::markup_square(&stamped).expect("the annotation")
        }),
        // Manager ruling R-18 (finding 27, variant R5v-hidden-objstm-member-p1-certified-*): an
        // object stream whose member, the page re-pointed to a black content stream, no section
        // lists; pyHanko: ltaUpdates, docmdpOk true.
        case("certify_p1_objstm_member_unlisted", || {
            certified_then(
                syntax::minimal(),
                P1,
                Some(mutators::parser_objstm_member_unlisted),
            )
        }),
        case("lock_p3_after_p1_certification_then_markup", || {
            let approved = locked_approval(&certified_then(syntax::minimal(), P1, None), 3);
            mutators::markup_square(&approved).expect("the annotation")
        }),
        // Manager ruling R-6: DocMDP declarations pyHanko cannot read are DocMdpInvalid with
        // P = 1 in force; a missing /P is the Table 257 default 2.
        pyhanko_raises("docmdp_reference_not_array", || {
            raw_approval(
                &declared_signature(vec![("Reference", docmdp_reference(Some(Object::Int(2))))]),
                false,
            )
        }),
        pyhanko_raises("docmdp_reference_without_transform_method", || {
            let mut reference = docmdp_reference(Some(Object::Int(2)));
            if let Object::Dict(dict) = &mut reference {
                dict.remove(b"TransformMethod".as_slice());
            }
            raw_approval(
                &declared_signature(vec![("Reference", Object::Array(vec![reference]))]),
                false,
            )
        }),
        pyhanko_raises("docmdp_p_out_of_range", || {
            raw_approval(
                &declared_signature(vec![(
                    "Reference",
                    Object::Array(vec![docmdp_reference(Some(Object::Int(4)))]),
                )]),
                false,
            )
        }),
        // M4 QA round 3, ruling R-12 (variant C3-r2-p-values-huge-int): /P 4294967298, an
        // integer PDFium reads as 0, in the signed declaration: DocMdpInvalid with P = 1 in
        // force, as for any declaration readers read differently.
        pyhanko_raises("docmdp_p_huge_integer", || {
            raw_approval(
                &declared_signature(vec![(
                    "Reference",
                    Object::Array(vec![docmdp_reference(Some(Object::Int(4_294_967_298)))]),
                )]),
                false,
            )
        }),
        pyhanko_raises("docmdp_p_not_an_integer", || {
            raw_approval(
                &declared_signature(vec![(
                    "Reference",
                    Object::Array(vec![docmdp_reference(Some(Object::literal_string("2")))]),
                )]),
                false,
            )
        }),
        case("docmdp_two_references", || {
            raw_approval(
                &declared_signature(vec![(
                    "Reference",
                    Object::Array(vec![
                        docmdp_reference(Some(Object::Int(3))),
                        docmdp_reference(Some(Object::Int(3))),
                    ]),
                )]),
                false,
            )
        }),
        // M4 QA round 2, finding 8: a declaration the signature itself signs with a duplicate
        // key (pyHanko keeps the first value, Folioxide's parser the last): DocMdpInvalid, so
        // P = 1 is in force, as pyHanko's first reading has it.
        signed_dupkey("docmdp_dupkey_reference_then_fill", || {
            let signed = dupkey_signature(
                &forms::acroform(),
                vec![
                    (
                        "Reference",
                        Object::Array(vec![docmdp_reference(Some(Object::Int(1)))]),
                    ),
                    (
                        "Referencf",
                        Object::Array(vec![docmdp_reference(Some(Object::Int(3)))]),
                    ),
                ],
                Vec::new(),
                true,
                vec![(b"/Referencf".as_slice(), b"/Reference".as_slice())],
            );
            mutators::form_fill_text_value_and_ap(&signed).expect("the fill applies")
        }),
        signed_dupkey("docmdp_dupkey_transform_params_p_then_fill", || {
            let mut reference = docmdp_reference(Some(Object::Int(1)));
            if let Object::Dict(dict) = &mut reference
                && let Some(Object::Dict(params)) = dict.get(b"TransformParams").cloned()
            {
                let mut params = params;
                params.insert("Z", Object::Int(3));
                dict.insert("TransformParams", Object::Dict(params));
            }
            let signed = dupkey_signature(
                &forms::acroform(),
                vec![("Reference", Object::Array(vec![reference]))],
                Vec::new(),
                true,
                vec![(b"/Z 3".as_slice(), b"/P 3".as_slice())],
            );
            mutators::form_fill_text_value_and_ap(&signed).expect("the fill applies")
        }),
        signed_dupkey("docmdp_dupkey_reference_in_approval_then_fill", || {
            let signed = dupkey_signature(
                &forms::acroform(),
                vec![
                    (
                        "Reference",
                        Object::Array(vec![docmdp_reference(Some(Object::Int(1)))]),
                    ),
                    (
                        "Referencf",
                        Object::Array(vec![docmdp_reference(Some(Object::Int(3)))]),
                    ),
                ],
                Vec::new(),
                false,
                vec![(b"/Referencf".as_slice(), b"/Reference".as_slice())],
            );
            mutators::form_fill_text_value_and_ap(&signed).expect("the fill applies")
        }),
        signed_dupkey("lock_dupkey_p1_first_then_invisible_approval", || {
            let lock = |p: i64| {
                let mut lock = Dict::new();
                lock.insert("Type", Object::name("SigFieldLock"));
                lock.insert("Action", Object::name("Include"));
                lock.insert(
                    "Fields",
                    Object::Array(vec![Object::literal_string("Nothing")]),
                );
                lock.insert("P", Object::Int(p));
                Object::Dict(lock)
            };
            let signed = dupkey_signature(
                &syntax::minimal(),
                Vec::new(),
                vec![("Lock", lock(1)), ("Locj", lock(3))],
                false,
                vec![(b"/Locj".as_slice(), b"/Lock".as_slice())],
            );
            raw_approval(&signed, false)
        }),
        CertifyCase {
            known_failures: SIGNED_DUPLICATE_BYTE_RANGE,
            ..case("dupkey_byterange_fake_first", || {
                dupkey_signature(
                    &syntax::minimal(),
                    vec![
                        (
                            "Reference",
                            Object::Array(vec![docmdp_reference(Some(Object::Int(1)))]),
                        ),
                        (
                            "ByteRangf",
                            Object::Array([0, 10, 20, 30].map(Object::Int).to_vec()),
                        ),
                    ],
                    Vec::new(),
                    true,
                    vec![(b"/ByteRangf".as_slice(), b"/ByteRange".as_slice())],
                )
            })
        },
        CertifyCase {
            known_failures: PYHANKO_DOCMDP_P_MISSING,
            ..pyhanko_raises("docmdp_p_missing", || {
                raw_approval(
                    &declared_signature(vec![(
                        "Reference",
                        Object::Array(vec![docmdp_reference(None)]),
                    )]),
                    false,
                )
            })
        },
    ]
}

/// The oracle checks of [`CertifyCase::known_failures`] for a certification signature
/// (`signatures[0]`) whose DocMDP declaration pyHanko 0.37 cannot read: `docmdp_level` raises
/// (`SignatureValidationError: Failed to read document permissions`, a `KeyError` or a
/// `TypeError`), so pyHanko reports no status for it, while pdfsig and OpenSSL validate the
/// signature itself (manager ruling R-6).
pub const PYHANKO_DOCMDP_RAISES: &[(&str, &str)] = &[
    (
        "signatures[0].pyhanko",
        "R-6: pyHanko raises reading the DocMDP declaration (Folioxide: DocMdpInvalid with P = \
         1 in force, or the ISO 32000-2 Table 257 default P = 2 for a missing /P)",
    ),
    (
        "signatures[0].trusted.pyhanko",
        "R-6: pyHanko raises, so it reports no trust verdict",
    ),
    (
        "signatures[0].coverage.pyhanko",
        "R-6: pyHanko raises, so it reports no coverage",
    ),
    (
        "signatures[0].modification.pyhanko",
        "R-6: pyHanko raises, so it reports no modification level",
    ),
    (
        "signatures[0].docmdpOk.pyhanko",
        "R-6: pyHanko raises, so it reports no docmdp_ok",
    ),
];

/// [`PYHANKO_DOCMDP_RAISES`] for a certification without `/P` in its transform parameters, plus
/// the `docmdp` row: Folioxide reads the ISO 32000-2 Table 257 default 2, where pyHanko raises
/// (the [`DELIBERATE_DIFFERENCES`] row of `docmdp_p_missing`).
pub const PYHANKO_DOCMDP_P_MISSING: &[(&str, &str)] = &[
    (
        "signatures[0].pyhanko",
        "R-6: pyHanko raises on a DocMDP reference without /P (raw_get('/P'): 'Failed to read \
         document permissions'); Folioxide reads the ISO 32000-2 Table 257 default P = 2",
    ),
    (
        "signatures[0].trusted.pyhanko",
        "R-6: pyHanko raises, so it reports no trust verdict",
    ),
    (
        "signatures[0].coverage.pyhanko",
        "R-6: pyHanko raises, so it reports no coverage",
    ),
    (
        "signatures[0].modification.pyhanko",
        "R-6: pyHanko raises, so it reports no modification level",
    ),
    (
        "signatures[0].docmdp.pyhanko",
        "R-6: pyHanko raises, so it reports no DocMDP level (Folioxide: 2, Table 257)",
    ),
    (
        "signatures[0].docmdpOk.pyhanko",
        "R-6: pyHanko raises, so it reports no docmdp_ok",
    ),
];

/// The oracle check of a certification case whose signature itself signs a duplicate key (M4 QA
/// round 2, finding 8): qpdf (pikepdf) warns about it, by design.
pub const SIGNED_DUPLICATE_KEY: &[(&str, &str)] = &[(
    "structure.pikepdf",
    "duplicate key by design (M4 QA round 2, finding 8): the signature dictionary or its field, \
     in the signed bytes, writes a key twice, which qpdf reports ('dictionary has duplicated \
     key; last occurrence overrides earlier ones')",
)];

/// [`SIGNED_DUPLICATE_KEY`] for a signature dictionary with two `/ByteRange` entries, a fake one
/// first: the checks that read the last one validate the signature, as Folioxide's parser did
/// before (pyHanko reads the first: not intact; Folioxide now trusts neither reading).
pub const SIGNED_DUPLICATE_BYTE_RANGE: &[(&str, &str)] = &[
    (
        "structure.pikepdf",
        "duplicate key by design (M4 QA round 2, finding 8): the signature dictionary writes \
         /ByteRange twice, which qpdf reports",
    ),
    (
        "signatures[0].extract",
        "duplicate /ByteRange by design: extract_cms reads the first (fake) range, whose gap is \
         no <hex> string; pyHanko reads it too and reports the signature not intact, as \
         Folioxide does",
    ),
    (
        "signatures[0].pdfsig",
        "duplicate /ByteRange by design: poppler keeps the last value, the real range, and \
         validates the signature; pyHanko keeps the first and Folioxide trusts neither (not \
         intact, sigDictAmbiguous)",
    ),
];

/// A DocMDP signature reference dictionary (§12.8.1 Table 256) whose transform parameters have
/// `/P p` (none when `p` is `None`).
fn docmdp_reference(p: Option<Object>) -> Object {
    let mut params = Dict::new();
    params.insert("Type", Object::name("TransformParams"));
    if let Some(p) = p {
        params.insert("P", p);
    }
    params.insert("V", Object::name("1.2"));
    let mut reference = Dict::new();
    reference.insert("Type", Object::name("SigRef"));
    reference.insert("TransformMethod", Object::name("DocMDP"));
    reference.insert("TransformParams", Object::Dict(params));
    Object::Dict(reference)
}

/// `minimal.pdf` signed (raw, RSA-2048) in a new invisible field `Signature1` whose signature
/// dictionary carries `sig` and that the catalog's `/Perms /DocMDP` names: a certification
/// with the declaration `sig`, which Folioxide refuses to write when it is malformed.
fn declared_signature(sig: Vec<(&'static str, Object)>) -> Vec<u8> {
    super::sign_raw(
        &syntax::minimal(),
        &super::rsa2048(),
        &super::RawSignature {
            name: ATTACKED_FIELD.to_owned(),
            sig,
            perms: true,
            ..super::RawSignature::default()
        },
    )
}

/// `source` signed (raw, RSA-2048) in a new invisible field `Signature1` whose signature
/// dictionary carries `sig` and whose field carries `field` (the catalog's `/Perms /DocMDP`
/// naming it when `perms`), with the stand-in keys of `renames` renamed in the signed bytes to a
/// key written already: a signature that signs a duplicate key (M4 QA round 2, finding 8).
fn dupkey_signature(
    source: &[u8],
    sig: Vec<(&'static str, Object)>,
    field: Vec<(&'static str, Object)>,
    perms: bool,
    renames: Vec<(&'static [u8], &'static [u8])>,
) -> Vec<u8> {
    super::sign_raw(
        source,
        &super::rsa2048(),
        &super::RawSignature {
            name: ATTACKED_FIELD.to_owned(),
            sig,
            field,
            perms,
            renames,
            ..super::RawSignature::default()
        },
    )
}

/// `source` signed (raw, RSA-2048) in a new invisible field `Signature1` with `/Lock <</Type
/// /SigFieldLock /Action /Include /Fields [(Nothing)] /P p>>` (ISO 32000-2 §12.7.5.5): an
/// approval signature that sets DocMDP permissions `p` for the document.
/// A raw approval of our P-256 key in a new invisible field `Approver` whose field lock (ISO
/// 32000-2 §12.7.5.5) is `<< /Type /SigFieldLock /Action /Include /Fields [] /P p >>`, as the
/// expert's probe (pyHanko signing a field whose lock has `/P 3`).
pub fn locked_approval(pdf: &[u8], p: i64) -> Vec<u8> {
    let mut lock = Dict::new();
    lock.insert("Type", Object::name("SigFieldLock"));
    lock.insert("Action", Object::name("Include"));
    lock.insert("Fields", Object::Array(Vec::new()));
    lock.insert("P", Object::Int(p));
    super::sign_raw(
        pdf,
        &super::p256(),
        &super::RawSignature {
            name: "Approver".to_owned(),
            field: vec![("Lock", Object::Dict(lock))],
            ..super::RawSignature::default()
        },
    )
}

fn locked_signature(source: &[u8], p: i64) -> Vec<u8> {
    let mut lock = Dict::new();
    lock.insert("Type", Object::name("SigFieldLock"));
    lock.insert("Action", Object::name("Include"));
    lock.insert(
        "Fields",
        Object::Array(vec![Object::literal_string("Nothing")]),
    );
    lock.insert("P", Object::Int(p));
    super::sign_raw(
        source,
        &super::rsa2048(),
        &super::RawSignature {
            name: ATTACKED_FIELD.to_owned(),
            field: vec![("Lock", Object::Dict(lock))],
            ..super::RawSignature::default()
        },
    )
}

/// A later approval (raw, P-256: Folioxide refuses to sign on top of `P = 1`) in a new field
/// `Approval`, invisible, or visible over the page heading.
fn raw_approval(pdf: &[u8], visible: bool) -> Vec<u8> {
    if visible {
        return visible_approval(pdf);
    }
    super::sign_raw(
        pdf,
        &super::p256(),
        &super::RawSignature {
            name: "Approval".to_owned(),
            ..super::RawSignature::default()
        },
    )
}

/// The file of the certification case `name`.
pub fn certified_case(name: &str) -> Vec<u8> {
    let case = certify_corpus()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no certification case {name}"));
    (case.build)()
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

/// `existing_field_signed_ap_no_bbox` (M4 QA round 1, finding R5, QA variant
/// R5-ap-no-bbox-existing-field-sign): the form's empty visible signature field `Visible`
/// signed (ours, P-256, raw) with an appearance stream that is a form XObject without `/BBox`
/// and paints over the page: PDFium does not clip it to the widget's `/Rect`.
fn existing_field_signed_ap_no_bbox(pdf: &[u8]) -> Option<Vec<u8>> {
    let doc = Document::open(pdf.to_vec(), &OpenOptions::default()).ok()?;
    let has_field = folioxide_sign::field::signature_fields(&doc)
        .ok()?
        .iter()
        .any(|f| f.name == forms::VISIBLE && !f.signed);
    if !has_field {
        return None;
    }
    let mut form = Dict::new();
    form.insert("Type", Object::name("XObject"));
    form.insert("Subtype", Object::name("Form"));
    Some(super::sign_raw(
        pdf,
        &super::p256(),
        &super::RawSignature {
            name: forms::VISIBLE.to_owned(),
            existing: true,
            rect: forms::VISIBLE_RECT,
            appearance: Some(b"0 0 1 rg -300 -100 612 792 re f".to_vec()),
            appearance_dict: Some(form),
            ..super::RawSignature::default()
        },
    ))
}

/// The empty signature field `index` of `mutators::FLAGGED_SIG_FIELDS` in `pdf` (a signed
/// [`Base::FormFlagged`]) signed (ours, P-256, raw: Folioxide refuses to sign it visibly) with an
/// appearance that fills its `/Rect` when `visible`, else invisibly (M4 QA round 2, finding 5).
fn sign_flagged_field(pdf: &[u8], index: usize, visible: bool) -> Option<Vec<u8>> {
    let (name, _) = mutators::FLAGGED_SIG_FIELDS.get(index)?;
    let doc = Document::open(pdf.to_vec(), &OpenOptions::default()).ok()?;
    let has_field = folioxide_sign::field::signature_fields(&doc)
        .ok()?
        .iter()
        .any(|f| f.name == *name && !f.signed);
    if !has_field {
        return None;
    }
    Some(super::sign_raw(
        pdf,
        &super::p256(),
        &super::RawSignature {
            name: (*name).to_owned(),
            existing: true,
            rect: mutators::flagged_sig_field_rect(index),
            appearance: visible.then(|| b"0 0 1 rg 0 0 200 50 re f".to_vec()),
            ..super::RawSignature::default()
        },
    ))
}

/// `existing_field_signed_flags_norotate` (QA variant R3-existing-field-norotate-rot90): the
/// NoRotate field signed with an appearance, on the page rotated by 90.
fn existing_field_signed_flags_norotate(pdf: &[u8]) -> Option<Vec<u8>> {
    sign_flagged_field(pdf, 0, true)
}

/// `existing_field_signed_flags_nozoom`: the NoZoom field signed with an appearance.
fn existing_field_signed_flags_nozoom(pdf: &[u8]) -> Option<Vec<u8>> {
    sign_flagged_field(pdf, 1, true)
}

/// `existing_field_signed_flags_hidden`: the Hidden field signed with an appearance.
fn existing_field_signed_flags_hidden(pdf: &[u8]) -> Option<Vec<u8>> {
    sign_flagged_field(pdf, 2, true)
}

/// `existing_field_signed_flags_noview`: the NoView field signed with an appearance.
fn existing_field_signed_flags_noview(pdf: &[u8]) -> Option<Vec<u8>> {
    sign_flagged_field(pdf, 3, true)
}

/// `existing_field_hidden_signed_invisibly`: the control, the Hidden field signed without an
/// appearance (only its `/V`): form filling, as for pyHanko.
fn existing_field_hidden_signed_invisibly(pdf: &[u8]) -> Option<Vec<u8>> {
    sign_flagged_field(pdf, 2, false)
}

/// A later approval (ours, P-256) in a new invisible field [`COSIGNER_FIELD`]: the co-signing
/// flow of the expert's `nt-shared-2.pdf` (closing round, finding 10). `None` on a base whose
/// `/Fields` lacks the field parents of `form_ap_dict_*_parents_input` (the co-signature is a
/// legitimate later signature, not an attack, on any other base).
fn cosign(pdf: &[u8]) -> Option<Vec<u8>> {
    let store = folioxide_syntax::Store::open_bytes(pdf.to_vec(), &OpenOptions::default()).ok()?;
    let root = store.root_id()?;
    let acroform = store.resolve(root).ok()?.as_dict()?.get_ref(b"AcroForm")?;
    let fields = store
        .resolve(acroform)
        .ok()?
        .as_dict()?
        .get(b"Fields")?
        .clone();
    let fields = store.deref(&fields).ok()?.as_array()?.to_vec();
    let (parent, _, _) = mutators::AP_DICT_PARENTS.first()?;
    let has_parent = fields.iter().any(|field| {
        store.deref(field).ok().is_some_and(|field| {
            field
                .as_dict()
                .and_then(|dict| dict.get(b"T"))
                .and_then(Object::as_str_bytes)
                == Some(parent.as_bytes())
        })
    });
    has_parent.then(|| approve(pdf, COSIGNER_FIELD, false))
}

/// The `/Size` that [`size_over_declared_info_only`] declares: far above the highest object
/// number of its update (ISO 32000-2 §7.5.5 Table 15 wants that number + 1).
pub const OVER_DECLARED_SIZE: u32 = 100;

/// `parser_trailer_size_over_declared_info_only` (M4 final fix round 2, verification round,
/// expert finding 1: the expert's `gap3.pdf`): an `/Info`-only update whose trailer says
/// `/Size 100` over objects numbered up to 8. Non-conforming, but above every number the file
/// lists and not below the previous `/Size`, so no reader drops an object: `ltaUpdates`, as for
/// pyHanko.
fn size_over_declared_info_only(pdf: &[u8]) -> Option<Vec<u8>> {
    mutators::with_last_size(
        &mutators::isa_info_only(pdf)?,
        &OVER_DECLARED_SIZE.to_string(),
    )
}

/// `parser_trailer_size_over_declared_then_cosigned` (the expert's `gap4.pdf`): the same update,
/// then a co-signature of ours in [`COSIGNER_FIELD`]. The signer numbers its new objects from
/// the declared `/Size`, as pyHanko's writer does, so the co-signature's own `/Size` is not below
/// it (manager ruling R-26) and the attacked signature stays `formFilling`, as for pyHanko. It
/// was `other` while the signer numbered from the highest listed number + 1.
fn size_over_declared_then_cosigned(pdf: &[u8]) -> Option<Vec<u8>> {
    Some(approve(
        &size_over_declared_info_only(pdf)?,
        COSIGNER_FIELD,
        false,
    ))
}

/// `sigfield_ap_dict_shared_signed_next`, `_cert2_then_second` and `_control_private` (M4
/// final fix round 2, finding 1, variants R3-k-two-sigfields-shared-*): the empty field
/// [`forms::VISIBLE`] signed invisibly by our P-256 key, so its `/AP` stays the signed one.
fn sign_visible_field_invisibly(pdf: &[u8]) -> Option<Vec<u8>> {
    has_empty_visible_field(pdf).then(|| approve(pdf, forms::VISIBLE, true))
}

/// Whether `pdf` has the empty signature field [`forms::VISIBLE`] (`None` for the generators
/// that sign it, on a base without it).
fn has_empty_visible_field(pdf: &[u8]) -> bool {
    Document::open(pdf.to_vec(), &OpenOptions::default())
        .ok()
        .and_then(|doc| folioxide_sign::field::signature_fields(&doc).ok())
        .is_some_and(|fields| fields.iter().any(|f| f.name == forms::VISIBLE && !f.signed))
}

/// `sigfield_ap_dict_shared_visible_next` (variant
/// R3-k-two-sigfields-shared-ours-visible-appearance-on-second): the empty field
/// [`forms::VISIBLE`] signed with a new appearance of its own.
fn sign_visible_field_with_appearance(pdf: &[u8]) -> Option<Vec<u8>> {
    if !has_empty_visible_field(pdf) {
        return None;
    }
    Some(super::sign_raw(
        pdf,
        &super::p256(),
        &super::RawSignature {
            name: forms::VISIBLE.to_owned(),
            existing: true,
            rect: forms::VISIBLE_RECT,
            appearance: Some(b"0 0 1 rg 0 0 200 60 re f".to_vec()),
            ..super::RawSignature::default()
        },
    ))
}

/// The attacked file of `name`.
pub fn attacked(name: &str) -> Vec<u8> {
    let case = corpus()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no case {name}"));
    (case.generate)(&case.base.bytes()).unwrap_or_else(|| panic!("{name} does not apply"))
}

/// The report of the signature field `Signature1` (the attacked or certifying signature) in
/// `pdf`.
pub fn signature1(pdf: &[u8]) -> folioxide_sign::report::SignatureReport {
    super::verify_plain(pdf)
        .into_iter()
        .find(|r| r.field_name.as_deref() == Some(ATTACKED_FIELD))
        .unwrap_or_else(|| panic!("{ATTACKED_FIELD} is listed"))
}

/// The change classes a report names in its warning "changes after signing, by class: …"
/// (M4 brief V10), in their `as_str` spelling; empty when nothing changed.
pub fn change_classes(report: &folioxide_sign::report::SignatureReport) -> Vec<String> {
    const PREFIX: &str = "changes after signing, by class: ";
    report
        .warnings
        .iter()
        .find_map(|w| w.strip_prefix(PREFIX))
        .map(|list| list.split(", ").map(str::to_owned).collect())
        .unwrap_or_default()
}
