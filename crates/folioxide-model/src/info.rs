//! The document information dictionary (ISO 32000-2 §14.3.3).
//!
//! The trailer's `/Info` dictionary holds the title, author and other metadata as text strings
//! (§7.9.2.2) and two dates (§7.9.4). PDF 2.0 deprecates it in favour of XMP metadata (§14.3.2)
//! except for `/CreationDate` and `/ModDate`, but every reader still shows it.

use std::collections::BTreeMap;

use folioxide_syntax::{DiagnosticKind, Dict, Error, Object, PdfString, Result, Store, keys};

use crate::date::PdfDate;
use crate::diag::ModelLog;
use crate::text::{decode_text_string, encode_text_string};

/// The `/Trapped` entry (§14.3.3): whether the document has been modified to include trapping
/// information (§14.11.6).
///
/// With the `serde` feature it is the string `"true"`, `"false"` or `"unknown"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub enum Trapped {
    /// `/True`: the document is fully trapped.
    True,
    /// `/False`: the document has not been trapped.
    False,
    /// `/Unknown`: unknown, or partly trapped.
    Unknown,
}

impl Trapped {
    /// The name this value is written as: `True`, `False` or `Unknown`.
    pub const fn as_name(self) -> &'static str {
        match self {
            Trapped::True => "True",
            Trapped::False => "False",
            Trapped::Unknown => "Unknown",
        }
    }

    /// Reads a `/Trapped` value: the names `/True`, `/False` and `/Unknown` (§14.3.3), and,
    /// leniently, a boolean or a string with one of those words (case-insensitive).
    pub fn from_object(value: &Object) -> Option<Trapped> {
        let word = match value {
            Object::Bool(true) => return Some(Trapped::True),
            Object::Bool(false) => return Some(Trapped::False),
            Object::Name(name) => name.as_bytes().to_vec(),
            Object::String(s) => decode_text_string(s.as_bytes()).into_bytes(),
            _ => return None,
        };
        match word.to_ascii_lowercase().as_slice() {
            b"true" => Some(Trapped::True),
            b"false" => Some(Trapped::False),
            b"unknown" => Some(Trapped::Unknown),
            _ => None,
        }
    }
}

/// The contents of the document information dictionary (§14.3.3), decoded.
///
/// Text entries are decoded text strings ([`decode_text_string`]); dates are parsed with
/// [`PdfDate::parse`]. Entries of the wrong type, and dates that do not parse, are left out
/// with a diagnostic. The struct is `#[non_exhaustive]`; it implements [`Default`].
///
/// With the `serde` feature its fields are `camelCase` (`creationDate`, `modDate`), absent
/// entries are left out, dates are PDF date strings and `/Trapped` is `"true"`, `"false"` or
/// `"unknown"`.
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", default)
)]
pub struct DocInfo {
    /// `/Title`: the document's title.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub title: Option<String>,
    /// `/Author`: the name of the person who created the document.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub author: Option<String>,
    /// `/Subject`: the subject of the document.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub subject: Option<String>,
    /// `/Keywords`: keywords associated with the document.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub keywords: Option<String>,
    /// `/Creator`: the application that created the original document.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub creator: Option<String>,
    /// `/Producer`: the application that converted it to PDF.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub producer: Option<String>,
    /// `/CreationDate`: when the document was created.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub creation_date: Option<PdfDate>,
    /// `/ModDate`: when the document was most recently modified.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub mod_date: Option<PdfDate>,
    /// `/Trapped`: whether the document includes trapping information.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    pub trapped: Option<Trapped>,
    /// Every other entry whose value is a text string, by key (the name's bytes read as UTF-8,
    /// lossily).
    pub custom: BTreeMap<String, String>,
}

/// The keys of the entries [`DocInfo`] and [`InfoUpdate`] have fields for (§14.3.3, Table 349).
const STANDARD_KEYS: [&str; 9] = [
    "Title",
    "Author",
    "Subject",
    "Keywords",
    "Creator",
    "Producer",
    "CreationDate",
    "ModDate",
    "Trapped",
];

/// The longest name, in bytes, that ISO 32000-1 Annex C (Table C.1) asks readers to accept:
/// poppler warns about a longer one ("name token is longer than what the specification says it
/// can be"), so a custom Info key is limited to it.
const MAX_NAME_LEN: usize = 127;

/// Changes to the document information dictionary (§14.3.3), for
/// [`Document::set_info`](crate::Document::set_info).
///
/// Every field is one change: `None` keeps the entry as it is, `Some(None)` removes it and
/// `Some(Some(value))` sets it. Text is written as a text string
/// ([`encode_text_string`]: PDFDocEncoding when it can, otherwise UTF-16BE), dates as PDF date
/// strings ([`PdfDate::to_pdf_string`]) and `/Trapped` as a name.
///
/// The struct is `#[non_exhaustive]`: start from [`InfoUpdate::default()`] (which changes
/// nothing) and use the `with_*` setters, or assign the fields.
///
/// ```
/// use folioxide_model::{InfoUpdate, PdfDate, Trapped};
///
/// let update = InfoUpdate::default()
///     .with_title(Some("Annual report"))
///     .with_author(None) // removes /Author
///     .with_mod_date(PdfDate::new(2026, 10, 10, 12, 0, 0))
///     .with_trapped(Some(Trapped::False))
///     .with_custom("Department", Some("Finance"));
/// assert_eq!(update.title, Some(Some("Annual report".to_owned())));
/// assert_eq!(update.author, Some(None));
/// assert_eq!(update.subject, None); // kept
/// ```
///
/// With the `serde` feature its fields are `camelCase` like [`DocInfo`]'s, and the three states
/// map to JSON as: field absent (keep), `null` (remove), a value (set).
#[non_exhaustive]
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase", default)
)]
pub struct InfoUpdate {
    /// `/Title`.
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            with = "crate::serde_util::double_option"
        )
    )]
    pub title: Option<Option<String>>,
    /// `/Author`.
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            with = "crate::serde_util::double_option"
        )
    )]
    pub author: Option<Option<String>>,
    /// `/Subject`.
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            with = "crate::serde_util::double_option"
        )
    )]
    pub subject: Option<Option<String>>,
    /// `/Keywords`.
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            with = "crate::serde_util::double_option"
        )
    )]
    pub keywords: Option<Option<String>>,
    /// `/Creator`.
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            with = "crate::serde_util::double_option"
        )
    )]
    pub creator: Option<Option<String>>,
    /// `/Producer`.
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            with = "crate::serde_util::double_option"
        )
    )]
    pub producer: Option<Option<String>>,
    /// `/CreationDate`.
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            with = "crate::serde_util::double_option"
        )
    )]
    pub creation_date: Option<Option<PdfDate>>,
    /// `/ModDate`. Setting the Info dictionary does not change it by itself: the core has no
    /// clock, so the caller passes the time.
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            with = "crate::serde_util::double_option"
        )
    )]
    pub mod_date: Option<Option<PdfDate>>,
    /// `/Trapped`.
    #[cfg_attr(
        feature = "serde",
        serde(
            skip_serializing_if = "Option::is_none",
            with = "crate::serde_util::double_option"
        )
    )]
    pub trapped: Option<Option<Trapped>>,
    /// Other entries, by key (the name's text, without the `/`): `None` removes the entry,
    /// `Some(text)` sets it to a text string. Entries not listed are kept. A key must not be one
    /// of the keys above (`Title`, `CreationDate`, …: use their fields). A key that is set must
    /// not be empty, be longer than 127 bytes in UTF-8 (the name length limit of ISO 32000-1
    /// Annex C) or contain a NUL character; any other key can be removed, so that an invalid
    /// entry a file holds can be taken out.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "BTreeMap::is_empty"))]
    pub custom: BTreeMap<String, Option<String>>,
}

impl InfoUpdate {
    /// An update that changes nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the update changes nothing: every field is `None` and `custom` is empty.
    pub fn is_empty(&self) -> bool {
        self == &InfoUpdate::default()
    }

    /// Sets [`InfoUpdate::title`]: `Some(text)` sets the title, `None` removes it.
    #[must_use]
    pub fn with_title(mut self, title: Option<&str>) -> Self {
        self.title = Some(title.map(str::to_owned));
        self
    }

    /// Sets [`InfoUpdate::author`]: `Some(text)` sets the author, `None` removes it.
    #[must_use]
    pub fn with_author(mut self, author: Option<&str>) -> Self {
        self.author = Some(author.map(str::to_owned));
        self
    }

    /// Sets [`InfoUpdate::subject`]: `Some(text)` sets the subject, `None` removes it.
    #[must_use]
    pub fn with_subject(mut self, subject: Option<&str>) -> Self {
        self.subject = Some(subject.map(str::to_owned));
        self
    }

    /// Sets [`InfoUpdate::keywords`]: `Some(text)` sets the keywords, `None` removes them.
    #[must_use]
    pub fn with_keywords(mut self, keywords: Option<&str>) -> Self {
        self.keywords = Some(keywords.map(str::to_owned));
        self
    }

    /// Sets [`InfoUpdate::creator`]: `Some(text)` sets the creator, `None` removes it.
    #[must_use]
    pub fn with_creator(mut self, creator: Option<&str>) -> Self {
        self.creator = Some(creator.map(str::to_owned));
        self
    }

    /// Sets [`InfoUpdate::producer`]: `Some(text)` sets the producer, `None` removes it.
    #[must_use]
    pub fn with_producer(mut self, producer: Option<&str>) -> Self {
        self.producer = Some(producer.map(str::to_owned));
        self
    }

    /// Sets [`InfoUpdate::creation_date`]: `Some(date)` sets it, `None` removes it.
    #[must_use]
    pub fn with_creation_date(mut self, date: Option<PdfDate>) -> Self {
        self.creation_date = Some(date);
        self
    }

    /// Sets [`InfoUpdate::mod_date`]: `Some(date)` sets it, `None` removes it.
    #[must_use]
    pub fn with_mod_date(mut self, date: Option<PdfDate>) -> Self {
        self.mod_date = Some(date);
        self
    }

    /// Sets [`InfoUpdate::trapped`]: `Some(value)` sets it, `None` removes it.
    #[must_use]
    pub fn with_trapped(mut self, trapped: Option<Trapped>) -> Self {
        self.trapped = Some(trapped);
        self
    }

    /// Adds a change of the custom entry `key` to [`InfoUpdate::custom`]: `Some(text)` sets it,
    /// `None` removes it.
    #[must_use]
    pub fn with_custom(mut self, key: &str, value: Option<&str>) -> Self {
        self.custom.insert(key.to_owned(), value.map(str::to_owned));
        self
    }

    /// Checks the custom keys (see [`InfoUpdate::custom`]).
    ///
    /// A key that is set becomes a name in the file, so it must be one every reader accepts. A
    /// key that is removed writes nothing, so it is not checked beyond not being a standard
    /// key: an invalid entry a file already has (a key with a NUL byte or of 300 bytes) can be
    /// removed.
    ///
    /// # Errors
    /// [`ErrorCode::InvalidArgument`](folioxide_syntax::ErrorCode::InvalidArgument) for a
    /// standard key, and, for a key that is set, an empty key, a key longer than 127 bytes in
    /// UTF-8 (ISO 32000-1 Annex C, Table C.1), or a key with a NUL character (§7.3.5).
    pub(crate) fn validate(&self) -> Result<()> {
        for (key, value) in &self.custom {
            if STANDARD_KEYS.contains(&key.as_str()) {
                return Err(Error::invalid_argument(format!(
                    "/{key} is a standard Info entry: set it with its own field, not as a \
                     custom entry"
                )));
            }
            if value.is_none() {
                continue;
            }
            if key.is_empty() {
                return Err(Error::invalid_argument(
                    "an Info dictionary key cannot be empty",
                ));
            }
            if key.len() > MAX_NAME_LEN {
                let start: String = key.chars().take(20).collect();
                return Err(Error::invalid_argument(format!(
                    "the Info dictionary key {start:?}… is {} bytes long in UTF-8; a name is \
                     limited to {MAX_NAME_LEN} bytes (ISO 32000-1 Annex C, Table C.1)",
                    key.len()
                )));
            }
            if key.contains('\0') {
                return Err(Error::invalid_argument(format!(
                    "the Info dictionary key {key:?} contains a NUL character, which a name \
                     cannot hold (§7.3.5)"
                )));
            }
        }
        Ok(())
    }

    /// Applies the update to `dict`; returns whether anything changed.
    pub(crate) fn apply(&self, dict: &mut Dict) -> bool {
        let text = |change: &Option<Option<String>>| {
            change
                .as_ref()
                .map(|value| value.as_deref().map(text_object))
        };
        let date = |change: &Option<Option<PdfDate>>| {
            change.as_ref().map(|value| {
                value.map(|d| Object::String(PdfString::new_literal(d.to_pdf_string())))
            })
        };
        let changes: [(&str, Option<Option<Object>>); 9] = [
            ("Title", text(&self.title)),
            ("Author", text(&self.author)),
            ("Subject", text(&self.subject)),
            ("Keywords", text(&self.keywords)),
            ("Creator", text(&self.creator)),
            ("Producer", text(&self.producer)),
            ("CreationDate", date(&self.creation_date)),
            ("ModDate", date(&self.mod_date)),
            (
                "Trapped",
                self.trapped
                    .map(|value| value.map(|t| Object::name(t.as_name()))),
            ),
        ];
        let custom = self
            .custom
            .iter()
            .map(|(key, value)| (key.as_str(), Some(value.as_deref().map(text_object))));
        let mut changed = false;
        for (key, change) in changes.into_iter().chain(custom) {
            match change {
                Some(None) => changed |= dict.remove(key.as_bytes()).is_some(),
                Some(Some(value))
                    if !dict
                        .get(key.as_bytes())
                        .is_some_and(|old| same_value(old, &value)) =>
                {
                    dict.insert(key, value);
                    changed = true;
                }
                // Kept, or set to the value it has.
                None | Some(Some(_)) => {}
            }
        }
        changed
    }
}

/// Whether an entry holding `old` already says `new`: equal objects, or strings with the same
/// bytes whatever their form (literal or hexadecimal, §7.3.4).
fn same_value(old: &Object, new: &Object) -> bool {
    match (old, new) {
        (Object::String(a), Object::String(b)) => a.as_bytes() == b.as_bytes(),
        _ => old == new,
    }
}

/// `text` as a text-string object (§7.9.2.2): literal when it is PDFDocEncoded, hexadecimal
/// when it is UTF-16BE.
fn text_object(text: &str) -> Object {
    let bytes = encode_text_string(text);
    if bytes.starts_with(&[0xFE, 0xFF]) {
        Object::String(PdfString::new_hex(bytes))
    } else {
        Object::String(PdfString::new_literal(bytes))
    }
}

/// Reads the Info dictionary of the document in `store`: empty when the trailer has none.
///
/// # Errors
/// The errors of [`Store::deref`].
pub(crate) fn read(store: &Store, log: &ModelLog) -> Result<DocInfo> {
    let mut info = DocInfo::default();
    let Some(value) = store.trailer().get(keys::INFO) else {
        return Ok(info);
    };
    let value = store.deref(value)?;
    let dict: &Dict = match &*value {
        Object::Dict(dict) => dict,
        Object::Null => return Ok(info),
        other => {
            log.report(
                DiagnosticKind::Metadata,
                format!(
                    "info: the trailer's /Info is {}, not a dictionary; ignored",
                    crate::type_phrase(other)
                ),
            );
            return Ok(info);
        }
    };
    for (key, value) in dict.iter() {
        let value = store.deref(value)?;
        if value.is_null() {
            continue;
        }
        let key_text = String::from_utf8_lossy(key.as_bytes());
        let text = value
            .as_pdf_string()
            .map(|s| decode_text_string(s.as_bytes()));
        let field = match key.as_bytes() {
            b"Title" => &mut info.title,
            b"Author" => &mut info.author,
            b"Subject" => &mut info.subject,
            b"Keywords" => &mut info.keywords,
            b"Creator" => &mut info.creator,
            b"Producer" => &mut info.producer,
            b"CreationDate" | b"ModDate" => {
                let date = text.as_deref().and_then(|t| PdfDate::parse(t.as_bytes()));
                if date.is_none() {
                    log.report(
                        DiagnosticKind::Metadata,
                        format!(
                            "info: /{key_text} is not a date ({}); ignored",
                            describe(&value, text.as_deref())
                        ),
                    );
                }
                if key.as_bytes() == b"CreationDate" {
                    info.creation_date = date;
                } else {
                    info.mod_date = date;
                }
                continue;
            }
            b"Trapped" => {
                info.trapped = Trapped::from_object(&value);
                if info.trapped.is_none() {
                    log.report(
                        DiagnosticKind::Metadata,
                        format!(
                            "info: /Trapped is not True, False or Unknown ({}); ignored",
                            describe(&value, text.as_deref())
                        ),
                    );
                }
                continue;
            }
            _ => {
                match text {
                    Some(text) => {
                        info.custom.insert(key_text.into_owned(), text);
                    }
                    None => log.report(
                        DiagnosticKind::Metadata,
                        format!(
                            "info: /{key_text} is {}, not a text string; ignored",
                            crate::type_phrase(&value)
                        ),
                    ),
                }
                continue;
            }
        };
        match text {
            Some(text) => *field = Some(text),
            None => log.report(
                DiagnosticKind::Metadata,
                format!(
                    "info: /{key_text} is {}, not a text string; ignored",
                    crate::type_phrase(&value)
                ),
            ),
        }
    }
    Ok(info)
}

/// A short description of an invalid value for a diagnostic: the decoded text of a string
/// (at most 40 characters), otherwise its type.
fn describe(value: &Object, text: Option<&str>) -> String {
    match text {
        Some(text) => {
            let short: String = text.chars().take(40).collect();
            format!("{short:?}")
        }
        None => crate::type_phrase(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trapped_values() {
        assert_eq!(
            Trapped::from_object(&Object::name("True")),
            Some(Trapped::True)
        );
        assert_eq!(
            Trapped::from_object(&Object::name("Unknown")),
            Some(Trapped::Unknown)
        );
        assert_eq!(
            Trapped::from_object(&Object::literal_string("false")),
            Some(Trapped::False)
        );
        assert_eq!(
            Trapped::from_object(&Object::Bool(true)),
            Some(Trapped::True)
        );
        assert_eq!(Trapped::from_object(&Object::name("Maybe")), None);
        assert_eq!(Trapped::from_object(&Object::Int(1)), None);
        assert_eq!(Trapped::Unknown.as_name(), "Unknown");
    }

    #[test]
    fn info_update_apply() {
        assert!(InfoUpdate::new().is_empty());
        assert!(!InfoUpdate::new().with_custom("A", None).is_empty());

        let mut dict = Dict::new();
        dict.insert("Title", Object::hex_string(b"Old".to_vec()));
        dict.insert("Author", Object::literal_string("Someone"));
        dict.insert("Company", Object::literal_string("ACME"));
        // The same bytes in another string form, and removals of absent entries, change nothing.
        let same = InfoUpdate::new()
            .with_title(Some("Old"))
            .with_subject(None)
            .with_custom("Missing", None);
        assert!(!same.apply(&mut dict));
        assert_eq!(
            dict.get(b"Title"),
            Some(&Object::hex_string(b"Old".to_vec()))
        );

        let date = PdfDate::new(2026, 10, 10, 12, 0, 0).and_then(|d| d.with_offset(Some(0)));
        let update = InfoUpdate::new()
            .with_title(Some("\u{65E5}\u{672C}"))
            .with_author(None)
            .with_mod_date(date)
            .with_trapped(Some(Trapped::True))
            .with_custom("Company", None)
            .with_custom("Dept", Some("R&D"));
        assert!(update.apply(&mut dict));
        assert_eq!(
            dict.get(b"Title"),
            Some(&Object::hex_string(b"\xFE\xFF\x65\xE5\x67\x2C".to_vec()))
        );
        assert_eq!(dict.get(b"Author"), None);
        assert_eq!(dict.get(b"Company"), None);
        assert_eq!(
            dict.get(b"ModDate"),
            Some(&Object::literal_string("D:20261010120000Z"))
        );
        assert_eq!(dict.get(b"Trapped"), Some(&Object::name("True")));
        assert_eq!(dict.get(b"Dept"), Some(&Object::literal_string("R&D")));
        // Applying it again changes nothing.
        assert!(!update.apply(&mut dict));
    }

    #[test]
    fn info_update_validate() {
        assert!(
            InfoUpdate::new()
                .with_custom("Dept", Some("x"))
                .validate()
                .is_ok()
        );
        for key in ["", "Title", "Producer", "CreationDate", "a\0"] {
            let err = InfoUpdate::new()
                .with_custom(key, Some("x"))
                .validate()
                .unwrap_err();
            assert_eq!(
                err.code(),
                folioxide_syntax::ErrorCode::InvalidArgument,
                "{key:?}"
            );
        }
    }

    /// A custom key is a name, limited to 127 bytes (ISO 32000-1 Annex C): counted in UTF-8
    /// bytes, not in characters.
    #[test]
    fn info_update_key_length() {
        let validate = |key: &str| InfoUpdate::new().with_custom(key, Some("v")).validate();
        assert!(validate(&"x".repeat(127)).is_ok());
        // 63 two-byte characters and one ASCII character: 127 bytes.
        assert!(validate(&format!("{}x", "é".repeat(63))).is_ok());
        for key in [
            "x".repeat(128),
            "x".repeat(300),
            "é".repeat(64),
            "日".repeat(43),
        ] {
            let err = validate(&key).unwrap_err();
            assert_eq!(
                err.code(),
                folioxide_syntax::ErrorCode::InvalidArgument,
                "{} bytes",
                key.len()
            );
            assert!(err.to_string().contains("127 bytes"), "{err}");
            // The message quotes the start of the key only.
            assert!(err.to_string().len() < 300, "{err}");
        }
        // Removing an entry writes no name: a long key, a NUL or an empty key that a file
        // holds can be removed. A standard key cannot, either way.
        for key in ["x".repeat(300), "a\0b".to_owned(), String::new()] {
            let update = InfoUpdate::new().with_custom(&key, None);
            assert!(update.validate().is_ok(), "{key:?}");
        }
        assert!(
            InfoUpdate::new()
                .with_custom("Title", None)
                .validate()
                .is_err()
        );
    }
}
