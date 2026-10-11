//! V1: which signature dictionaries the document has (brief §5 V1).
//!
//! The terminal signature fields of `/AcroForm /Fields` (`/FT /Sig`, the field's own or
//! inherited; `/Kids` followed to [`MAX_FIELD_DEPTH`](crate::field::MAX_FIELD_DEPTH) levels,
//! each object once) whose `/V` is set are candidates, in field order. `/V` must be an indirect
//! reference to a dictionary. Then every dictionary with `/Type /Sig` or `/Type /DocTimeStamp`
//! and a `/ByteRange` or `/Contents` that no field's `/V` refers to is an orphan candidate.
//!
//! The candidates are bounded, so the reports cannot grow with the file (R-18; QA finding: 100k
//! kid widgets sharing one `/V`): a signature dictionary is a candidate for at most
//! [`MAX_REPORTS_PER_SIGNATURE_DICTIONARY`] of the fields whose `/V` it is (the others are counted
//! in a warning of its reports), and there are at most [`MAX_REPORTS`] candidates in all (the
//! others are counted in a warning of every report).

use std::collections::HashMap;
use std::sync::Arc;

use folioxide_model::Document;
use folioxide_syntax::{Object, ObjectId};

use crate::error::Result;
use crate::field;
use crate::problem::ProblemCode;

use super::{MAX_REPORTS, MAX_REPORTS_PER_SIGNATURE_DICTIONARY, MAX_VERIFIED_SIGNATURES};

/// One signature dictionary to report on.
#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    /// The fully qualified field name; `None` for an orphan.
    pub(crate) field_name: Option<String>,
    /// The field's object, when it is indirect.
    pub(crate) field_id: Option<ObjectId>,
    /// The signature dictionary's object, when `/V` is an indirect reference.
    pub(crate) sig_id: Option<ObjectId>,
    /// The signature dictionary (shared with the store, never copied: one dictionary can be
    /// the value of many fields); `None` when `/V` is not a dictionary.
    pub(crate) dict: Option<Arc<Object>>,
    /// Problems found during discovery.
    pub(crate) problems: Vec<(ProblemCode, String)>,
    /// Warnings found during discovery.
    pub(crate) warnings: Vec<String>,
}

/// What discovery found.
#[derive(Clone, Debug, Default)]
pub(crate) struct Discovery {
    /// The candidates: fields in field order, then orphans by object number.
    pub(crate) candidates: Vec<Candidate>,
    /// Warnings for every report (for example a field tree cut at the depth limit).
    pub(crate) warnings: Vec<String>,
}

/// Finds the signature dictionaries of `doc` (brief §5 V1). Every object of the store must have
/// been resolved already (V0).
///
/// # Errors
/// The errors of [`Document::catalog`].
pub(crate) fn discover(doc: &Document) -> Result<Discovery> {
    let store = doc.store();
    let catalog = doc.catalog()?;
    let mut out = Discovery::default();

    let nodes = match field::acroform_of(store, catalog.as_dict()) {
        Ok(Some(acroform)) => match field::walk_fields_bounded(store, &acroform.dict) {
            Ok((nodes, truncated)) => {
                if truncated {
                    out.warnings.push(format!(
                        "the field tree is deeper than {} levels, or has more than {} fields or \
                         {} bytes of field names; the rest was not examined (signature \
                         dictionaries found nowhere else are reported as orphans)",
                        field::MAX_FIELD_DEPTH,
                        field::MAX_FIELDS,
                        field::MAX_FIELD_NAME_BYTES_TOTAL
                    ));
                }
                nodes
            }
            Err(err) => {
                out.warnings
                    .push(format!("the field tree could not be read: {err}"));
                Vec::new()
            }
        },
        Ok(None) => Vec::new(),
        Err(err) => {
            out.warnings
                .push(format!("the /AcroForm could not be read: {err}"));
            Vec::new()
        }
    };

    let mut names = field::NameBudget::new();
    // Per signature dictionary: the fields whose /V it is (every one, for the orphan check).
    let mut uses: HashMap<ObjectId, usize> = HashMap::new();
    // The candidates left out by MAX_REPORTS.
    let mut omitted: usize = 0;
    for (index, node) in nodes.iter().enumerate() {
        if !(node.terminal && node.is_signature()) {
            continue;
        }
        let Some(value) = node.dict.get(b"V") else {
            continue;
        };
        if matches!(value, Object::Null) {
            continue;
        }
        if let Object::Ref(id) = value {
            // A reference to a missing or free object is null: the field is not signed.
            if store.resolve(*id).is_ok_and(|resolved| resolved.is_null()) {
                continue;
            }
            let count = uses.entry(*id).or_default();
            *count = count.saturating_add(1);
            if *count > MAX_REPORTS_PER_SIGNATURE_DICTIONARY {
                continue; // counted in the warning of the dictionary's reports
            }
        }
        if out.candidates.len() >= MAX_REPORTS {
            omitted = omitted.saturating_add(1);
            continue;
        }
        let (name, shortened) = names.name(&nodes, index);
        let mut candidate = Candidate {
            field_name: Some(name),
            field_id: node.id,
            sig_id: None,
            dict: None,
            problems: Vec::new(),
            warnings: Vec::new(),
        };
        if shortened {
            candidate.warnings.push(format!(
                "the field name is longer than {} bytes (or the names of the document's fields \
                 together exceed {} bytes); it was shortened",
                field::MAX_FIELD_NAME_BYTES,
                field::MAX_FIELD_NAME_BYTES_TOTAL
            ));
        }
        match value {
            Object::Null => continue,
            Object::Ref(id) => match store.resolve(*id) {
                // A reference to a missing or free object is null: the field is not signed.
                Ok(resolved) if resolved.is_null() => continue,
                Ok(resolved) if resolved.as_dict().is_some() => {
                    candidate.sig_id = Some(*id);
                    candidate.dict = Some(resolved);
                }
                Ok(other) => {
                    candidate.sig_id = Some(*id);
                    candidate.problems.push((
                        ProblemCode::SigDictNotDictionary,
                        format!("/V of the field refers to a {}", other.type_name()),
                    ));
                }
                Err(err) => {
                    candidate.sig_id = Some(*id);
                    candidate.problems.push((
                        ProblemCode::SigDictNotDictionary,
                        format!("/V of the field cannot be read: {err}"),
                    ));
                }
            },
            Object::Dict(dict) => {
                candidate.dict = Some(Arc::new(Object::Dict(dict.clone())));
                candidate.problems.push((
                    ProblemCode::SigValueNotIndirect,
                    "/V of the field is a direct dictionary, not an indirect reference".to_owned(),
                ));
            }
            other => {
                candidate.problems.push((
                    ProblemCode::SigValueNotIndirect,
                    format!("/V of the field is a {}", other.type_name()),
                ));
                candidate.problems.push((
                    ProblemCode::SigDictNotDictionary,
                    format!(
                        "/V of the field is a {}, not a dictionary",
                        other.type_name()
                    ),
                ));
            }
        }
        out.candidates.push(candidate);
    }

    // A signature dictionary that two fields share is reported for each (up to
    // MAX_REPORTS_PER_SIGNATURE_DICTIONARY of them), with a warning.
    for candidate in &mut out.candidates {
        let Some(id) = candidate.sig_id else {
            continue;
        };
        let fields = uses.get(&id).copied().unwrap_or(0);
        if fields > MAX_REPORTS_PER_SIGNATURE_DICTIONARY {
            candidate.warnings.push(format!(
                "the signature dictionary {id} is the value of {fields} fields; it is reported \
                 for the first {MAX_REPORTS_PER_SIGNATURE_DICTIONARY} of them only"
            ));
        } else if fields > 1 {
            candidate.warnings.push(format!(
                "the signature dictionary {id} is the value of {fields} fields"
            ));
        }
    }

    // Orphans: signature dictionaries no field refers to.
    for id in store.object_ids() {
        if uses.contains_key(&id) {
            continue;
        }
        let Ok(value) = store.resolve(id) else {
            continue;
        };
        let Some(dict) = value.as_dict() else {
            continue;
        };
        let signature_type = dict.is_type(b"Sig") || dict.is_type(b"DocTimeStamp");
        if signature_type && (dict.contains_key(b"ByteRange") || dict.contains_key(b"Contents")) {
            if out.candidates.len() >= MAX_REPORTS {
                omitted = omitted.saturating_add(1);
                continue;
            }
            out.candidates.push(Candidate {
                field_name: None,
                field_id: None,
                sig_id: Some(id),
                dict: Some(Arc::clone(&value)),
                problems: vec![(
                    ProblemCode::Orphan,
                    format!("no signature field refers to the signature dictionary {id}"),
                )],
                warnings: Vec::new(),
            });
        }
    }
    if omitted > 0 {
        // Every report says so. The list stays fail-closed: with more than MAX_REPORTS
        // candidates, all but MAX_VERIFIED_SIGNATURES of the reports listed are not verified
        // (not valid), so a document cannot look validly signed by crowding a report out.
        out.warnings.push(format!(
            "the document has more than {MAX_REPORTS} signature dictionaries and signed \
             signature fields; {omitted} of them are not reported, and only \
             {MAX_VERIFIED_SIGNATURES} of those reported are verified in full"
        ));
    }
    Ok(out)
}
