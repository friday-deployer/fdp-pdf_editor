//! The PDF object model (ISO 32000-2 §7.3, ARCHITECTURE §A.3).
//!
//! [`Object`] is the in-memory form of every PDF value. Reals are always `f64` (never `f32`),
//! strings remember whether they were written in literal or hexadecimal form, names hold their
//! decoded bytes, and dictionaries keep their key order so output is deterministic.

use std::borrow::{Borrow, Cow};
use std::fmt;
use std::ops::Range;

use indexmap::IndexMap;

use crate::error::{Error, Result};

/// The identifier of an indirect object: object number and generation number (§7.3.10).
///
/// Object number 0 is always free. In Rust 2024 `gen` is a reserved word, so the field is declared
/// as `r#gen`; [`ObjectId::generation`] is a plain accessor for it.
///
/// ```
/// use folioxide_syntax::ObjectId;
///
/// let id = ObjectId::new(12, 0);
/// assert_eq!(id.num, 12);
/// assert_eq!(id.generation(), 0);
/// assert_eq!(id.to_string(), "12 0 R");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct ObjectId {
    /// The object number.
    pub num: u32,
    /// The generation number (0–65535).
    pub r#gen: u16,
}

impl ObjectId {
    /// Creates an object identifier.
    pub const fn new(num: u32, r#gen: u16) -> Self {
        ObjectId { num, r#gen }
    }

    /// The object number.
    pub const fn number(self) -> u32 {
        self.num
    }

    /// The generation number.
    pub const fn generation(self) -> u16 {
        self.r#gen
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} R", self.num, self.r#gen)
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A PDF object (§7.3).
///
/// `Stream` is only valid as the top-level value of an indirect object; the parser never produces
/// it anywhere else.
#[derive(Clone, Debug, PartialEq, Default)]
pub enum Object {
    /// The null object (§7.3.9).
    #[default]
    Null,
    /// A boolean (§7.3.2).
    Bool(bool),
    /// An integer (§7.3.3).
    Int(i64),
    /// A real number (§7.3.3). Always `f64`; the parser never produces NaN or infinities.
    Real(f64),
    /// A string (§7.3.4).
    String(PdfString),
    /// A name (§7.3.5).
    Name(Name),
    /// An array (§7.3.6).
    Array(Vec<Object>),
    /// A dictionary (§7.3.7).
    Dict(Dict),
    /// A stream (§7.3.8).
    Stream(Box<Stream>),
    /// An indirect reference `N G R` (§7.3.10).
    Ref(ObjectId),
}

impl Object {
    /// Creates a name object.
    pub fn name(name: impl Into<Name>) -> Self {
        Object::Name(name.into())
    }

    /// Creates a string object written in literal form, `(...)`.
    pub fn literal_string(bytes: impl Into<Vec<u8>>) -> Self {
        Object::String(PdfString::new_literal(bytes))
    }

    /// Creates a string object written in hexadecimal form, `<...>`.
    pub fn hex_string(bytes: impl Into<Vec<u8>>) -> Self {
        Object::String(PdfString::new_hex(bytes))
    }

    /// The PDF type of this object, for messages: `"null"`, `"boolean"`, `"integer"`, `"real"`,
    /// `"string"`, `"name"`, `"array"`, `"dictionary"`, `"stream"` or `"reference"`.
    pub const fn type_name(&self) -> &'static str {
        match self {
            Object::Null => "null",
            Object::Bool(_) => "boolean",
            Object::Int(_) => "integer",
            Object::Real(_) => "real",
            Object::String(_) => "string",
            Object::Name(_) => "name",
            Object::Array(_) => "array",
            Object::Dict(_) => "dictionary",
            Object::Stream(_) => "stream",
            Object::Ref(_) => "reference",
        }
    }

    /// Whether this is the null object.
    pub const fn is_null(&self) -> bool {
        matches!(self, Object::Null)
    }

    /// The value of a boolean.
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Object::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The value of an integer.
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Object::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// The value of a number: an integer (converted, possibly rounding beyond 2^53) or a real.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Object::Int(i) => Some(*i as f64),
            Object::Real(r) => Some(*r),
            _ => None,
        }
    }

    /// The name, if this is a name.
    pub const fn as_name(&self) -> Option<&Name> {
        match self {
            Object::Name(n) => Some(n),
            _ => None,
        }
    }

    /// Whether this is the name `name`.
    ///
    /// ```
    /// use folioxide_syntax::Object;
    ///
    /// assert!(Object::name("Catalog").is_name(b"Catalog"));
    /// ```
    pub fn is_name(&self, name: &[u8]) -> bool {
        self.as_name().is_some_and(|n| n.as_bytes() == name)
    }

    /// The string, if this is a string.
    pub const fn as_pdf_string(&self) -> Option<&PdfString> {
        match self {
            Object::String(s) => Some(s),
            _ => None,
        }
    }

    /// The bytes of a string.
    pub fn as_str_bytes(&self) -> Option<&[u8]> {
        match self {
            Object::String(s) => Some(&s.bytes),
            _ => None,
        }
    }

    /// The elements of an array.
    pub fn as_array(&self) -> Option<&[Object]> {
        match self {
            Object::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The elements of an array, mutably.
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Object>> {
        match self {
            Object::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The dictionary, if this is a dictionary. A stream's dictionary is reached through
    /// [`Object::as_stream`].
    pub const fn as_dict(&self) -> Option<&Dict> {
        match self {
            Object::Dict(d) => Some(d),
            _ => None,
        }
    }

    /// The dictionary, mutably.
    pub fn as_dict_mut(&mut self) -> Option<&mut Dict> {
        match self {
            Object::Dict(d) => Some(d),
            _ => None,
        }
    }

    /// The stream, if this is a stream.
    pub fn as_stream(&self) -> Option<&Stream> {
        match self {
            Object::Stream(s) => Some(s),
            _ => None,
        }
    }

    /// The stream, mutably.
    pub fn as_stream_mut(&mut self) -> Option<&mut Stream> {
        match self {
            Object::Stream(s) => Some(s),
            _ => None,
        }
    }

    /// The target of an indirect reference.
    pub const fn as_ref(&self) -> Option<ObjectId> {
        match self {
            Object::Ref(id) => Some(*id),
            _ => None,
        }
    }

    /// The value of an integer, or a [`TypeMismatch`](crate::ErrorCode::TypeMismatch) error.
    pub fn try_int(&self) -> Result<i64> {
        self.as_int()
            .ok_or_else(|| Error::type_mismatch("integer", self.type_name()))
    }

    /// The value of a number, or a [`TypeMismatch`](crate::ErrorCode::TypeMismatch) error.
    pub fn try_f64(&self) -> Result<f64> {
        self.as_f64()
            .ok_or_else(|| Error::type_mismatch("number", self.type_name()))
    }

    /// The name, or a [`TypeMismatch`](crate::ErrorCode::TypeMismatch) error.
    pub fn try_name(&self) -> Result<&Name> {
        self.as_name()
            .ok_or_else(|| Error::type_mismatch("name", self.type_name()))
    }

    /// The array elements, or a [`TypeMismatch`](crate::ErrorCode::TypeMismatch) error.
    pub fn try_array(&self) -> Result<&[Object]> {
        self.as_array()
            .ok_or_else(|| Error::type_mismatch("array", self.type_name()))
    }

    /// The dictionary, or a [`TypeMismatch`](crate::ErrorCode::TypeMismatch) error.
    pub fn try_dict(&self) -> Result<&Dict> {
        self.as_dict()
            .ok_or_else(|| Error::type_mismatch("dictionary", self.type_name()))
    }
}

impl From<bool> for Object {
    fn from(v: bool) -> Self {
        Object::Bool(v)
    }
}

impl From<i64> for Object {
    fn from(v: i64) -> Self {
        Object::Int(v)
    }
}

impl From<i32> for Object {
    fn from(v: i32) -> Self {
        Object::Int(i64::from(v))
    }
}

impl From<u32> for Object {
    fn from(v: u32) -> Self {
        Object::Int(i64::from(v))
    }
}

impl From<f64> for Object {
    fn from(v: f64) -> Self {
        Object::Real(v)
    }
}

impl From<PdfString> for Object {
    fn from(v: PdfString) -> Self {
        Object::String(v)
    }
}

impl From<Name> for Object {
    fn from(v: Name) -> Self {
        Object::Name(v)
    }
}

impl From<Vec<Object>> for Object {
    fn from(v: Vec<Object>) -> Self {
        Object::Array(v)
    }
}

impl From<Dict> for Object {
    fn from(v: Dict) -> Self {
        Object::Dict(v)
    }
}

impl From<Stream> for Object {
    fn from(v: Stream) -> Self {
        Object::Stream(Box::new(v))
    }
}

impl From<ObjectId> for Object {
    fn from(v: ObjectId) -> Self {
        Object::Ref(v)
    }
}

/// A PDF string (§7.3.4): arbitrary bytes plus the form it is written in.
///
/// The form is kept so that a value can be written back the way it was read; signature
/// `/Contents` must stay hexadecimal, for example.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct PdfString {
    /// The decoded bytes (escapes and hex digits resolved).
    pub bytes: Vec<u8>,
    /// `true` for hexadecimal form `<...>`, `false` for literal form `(...)`.
    pub hex: bool,
}

impl PdfString {
    /// A string written in literal form.
    pub fn new_literal(bytes: impl Into<Vec<u8>>) -> Self {
        PdfString {
            bytes: bytes.into(),
            hex: false,
        }
    }

    /// A string written in hexadecimal form.
    pub fn new_hex(bytes: impl Into<Vec<u8>>) -> Self {
        PdfString {
            bytes: bytes.into(),
            hex: true,
        }
    }

    /// The decoded bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the string and returns its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The number of decoded bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the string is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for PdfString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.hex {
            f.write_str("<")?;
            for b in &self.bytes {
                write!(f, "{b:02X}")?;
            }
            f.write_str(">")
        } else {
            write!(f, "({})", self.bytes.escape_ascii())
        }
    }
}

impl From<&[u8]> for PdfString {
    fn from(v: &[u8]) -> Self {
        PdfString::new_literal(v)
    }
}

impl From<Vec<u8>> for PdfString {
    fn from(v: Vec<u8>) -> Self {
        PdfString::new_literal(v)
    }
}

impl From<&str> for PdfString {
    fn from(v: &str) -> Self {
        PdfString::new_literal(v.as_bytes())
    }
}

/// A PDF name (§7.3.5), holding its decoded bytes (`#xx` escapes resolved), without the
/// leading `/`.
///
/// Names compare equal to byte strings and string slices, and implement `Borrow<[u8]>` so a
/// [`Dict`] can be indexed with `&[u8]`. Common keys are available as constants in
/// [`keys`].
///
/// ```
/// use folioxide_syntax::Name;
///
/// let name = Name::from("Lime Green");
/// assert_eq!(name, *b"Lime Green");
/// assert_eq!(name.to_string(), "/Lime#20Green");
/// ```
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Name(Box<[u8]>);

impl Name {
    /// Creates a name from its decoded bytes.
    pub fn new(bytes: impl Into<Box<[u8]>>) -> Self {
        Name(bytes.into())
    }

    /// The decoded bytes, without the leading `/`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The name as UTF-8, if it is valid UTF-8.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Consumes the name and returns its bytes.
    pub fn into_bytes(self) -> Box<[u8]> {
        self.0
    }

    /// The number of decoded bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the name is empty (written `/`, which is a valid name).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Borrow<[u8]> for Name {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Name {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq<[u8]> for Name {
    fn eq(&self, other: &[u8]) -> bool {
        *self.0 == *other
    }
}

impl PartialEq<&[u8]> for Name {
    fn eq(&self, other: &&[u8]) -> bool {
        *self.0 == **other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Name {
    fn eq(&self, other: &[u8; N]) -> bool {
        *self.0 == *other.as_slice()
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for Name {
    fn eq(&self, other: &&[u8; N]) -> bool {
        *self.0 == *other.as_slice()
    }
}

impl PartialEq<str> for Name {
    fn eq(&self, other: &str) -> bool {
        *self.0 == *other.as_bytes()
    }
}

impl PartialEq<&str> for Name {
    fn eq(&self, other: &&str) -> bool {
        *self.0 == *other.as_bytes()
    }
}

impl From<&[u8]> for Name {
    fn from(v: &[u8]) -> Self {
        Name(v.into())
    }
}

impl<const N: usize> From<&[u8; N]> for Name {
    fn from(v: &[u8; N]) -> Self {
        Name(v.as_slice().into())
    }
}

impl From<Vec<u8>> for Name {
    fn from(v: Vec<u8>) -> Self {
        Name(v.into_boxed_slice())
    }
}

impl From<Box<[u8]>> for Name {
    fn from(v: Box<[u8]>) -> Self {
        Name(v)
    }
}

impl From<Cow<'_, [u8]>> for Name {
    fn from(v: Cow<'_, [u8]>) -> Self {
        Name(v.into_owned().into_boxed_slice())
    }
}

impl From<&str> for Name {
    fn from(v: &str) -> Self {
        Name(v.as_bytes().into())
    }
}

impl From<String> for Name {
    fn from(v: String) -> Self {
        Name(v.into_bytes().into_boxed_slice())
    }
}

impl fmt::Display for Name {
    /// Writes the name in PDF syntax, with the leading `/` and `#xx` escapes (§7.3.5).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = Vec::with_capacity(self.0.len() + 1);
        crate::serialize::write_name(&self.0, &mut out);
        // `write_name` only emits printable ASCII.
        f.write_str(&String::from_utf8_lossy(&out))
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A PDF dictionary (§7.3.7): an insertion-ordered map from [`Name`] to [`Object`].
///
/// Insertion order is preserved so output is deterministic and diffs stay readable. Replacing
/// the value of an existing key keeps the key's position; [`Dict::remove`] keeps the order of
/// the remaining keys. Equality ignores order.
///
/// The map is boxed, so a dictionary takes one pointer inside its [`Object`] and an `Object` is
/// 32 bytes: arrays of numbers and references, by far the most common values, take less than
/// half the memory an inline map would cost them.
///
/// ```
/// use folioxide_syntax::{keys, Dict, Object, ObjectId};
///
/// let mut page = Dict::new();
/// page.insert("Type", Object::name("Page"));
/// page.insert(keys::PARENT, ObjectId::new(2, 0));
/// assert!(page.is_type(b"Page"));
/// assert_eq!(page.get_ref(b"Parent"), Some(ObjectId::new(2, 0)));
/// ```
#[derive(Clone, PartialEq, Default)]
pub struct Dict(Box<IndexMap<Name, Object>>);

impl Dict {
    /// Creates an empty dictionary.
    pub fn new() -> Self {
        Dict(Box::default())
    }

    /// Creates an empty dictionary with room for `capacity` entries.
    pub fn with_capacity(capacity: usize) -> Self {
        Dict(Box::new(IndexMap::with_capacity(capacity)))
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the dictionary has no entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The value for `key`. Note that a `null` value is returned as `Some(&Object::Null)`,
    /// although §7.3.7 treats it like an absent entry; the typed getters return `None` for it.
    pub fn get(&self, key: &[u8]) -> Option<&Object> {
        self.0.get(key)
    }

    /// The value for `key`, mutably.
    pub fn get_mut(&mut self, key: &[u8]) -> Option<&mut Object> {
        self.0.get_mut(key)
    }

    /// Whether `key` is present (with any value, including `null`).
    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.0.contains_key(key)
    }

    /// Inserts or replaces an entry and returns the previous value. A replaced key keeps its
    /// position; a new key is appended.
    pub fn insert(&mut self, key: impl Into<Name>, value: impl Into<Object>) -> Option<Object> {
        self.0.insert(key.into(), value.into())
    }

    /// Removes an entry and returns its value, keeping the order of the remaining entries.
    pub fn remove(&mut self, key: &[u8]) -> Option<Object> {
        self.0.shift_remove(key)
    }

    /// Iterates over the entries in order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&Name, &Object)> + DoubleEndedIterator {
        self.0.iter()
    }

    /// Iterates over the entries in order, with mutable values.
    pub fn iter_mut(
        &mut self,
    ) -> impl ExactSizeIterator<Item = (&Name, &mut Object)> + DoubleEndedIterator {
        self.0.iter_mut()
    }

    /// Iterates over the keys in order.
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &Name> + DoubleEndedIterator {
        self.0.keys()
    }

    /// Iterates over the values in order.
    pub fn values(&self) -> impl ExactSizeIterator<Item = &Object> + DoubleEndedIterator {
        self.0.values()
    }

    /// The integer value of `key`.
    pub fn get_int(&self, key: &[u8]) -> Option<i64> {
        self.get(key).and_then(Object::as_int)
    }

    /// The numeric value of `key` (integer or real).
    pub fn get_f64(&self, key: &[u8]) -> Option<f64> {
        self.get(key).and_then(Object::as_f64)
    }

    /// The boolean value of `key`.
    pub fn get_bool(&self, key: &[u8]) -> Option<bool> {
        self.get(key).and_then(Object::as_bool)
    }

    /// The name value of `key`.
    pub fn get_name(&self, key: &[u8]) -> Option<&Name> {
        self.get(key).and_then(Object::as_name)
    }

    /// The string value of `key`.
    pub fn get_string(&self, key: &[u8]) -> Option<&PdfString> {
        self.get(key).and_then(Object::as_pdf_string)
    }

    /// The bytes of the string value of `key`.
    pub fn get_str_bytes(&self, key: &[u8]) -> Option<&[u8]> {
        self.get(key).and_then(Object::as_str_bytes)
    }

    /// The array value of `key`.
    pub fn get_array(&self, key: &[u8]) -> Option<&[Object]> {
        self.get(key).and_then(Object::as_array)
    }

    /// The dictionary value of `key`.
    pub fn get_dict(&self, key: &[u8]) -> Option<&Dict> {
        self.get(key).and_then(Object::as_dict)
    }

    /// The reference value of `key`.
    pub fn get_ref(&self, key: &[u8]) -> Option<ObjectId> {
        self.get(key).and_then(Object::as_ref)
    }

    /// Releases the spare capacity the map grew while it was filled (the parser calls this
    /// when a dictionary is complete).
    pub(crate) fn shrink_to_fit(&mut self) {
        self.0.shrink_to_fit();
    }

    /// Whether `/Type` is the name `ty`.
    pub fn is_type(&self, ty: &[u8]) -> bool {
        self.get_name(crate::keys::TYPE)
            .is_some_and(|n| n.as_bytes() == ty)
    }
}

impl fmt::Debug for Dict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.0.iter()).finish()
    }
}

impl FromIterator<(Name, Object)> for Dict {
    fn from_iter<I: IntoIterator<Item = (Name, Object)>>(iter: I) -> Self {
        Dict(Box::new(iter.into_iter().collect()))
    }
}

impl Extend<(Name, Object)> for Dict {
    fn extend<I: IntoIterator<Item = (Name, Object)>>(&mut self, iter: I) {
        self.0.extend(iter);
    }
}

impl IntoIterator for Dict {
    type Item = (Name, Object);
    type IntoIter = indexmap::map::IntoIter<Name, Object>;

    fn into_iter(self) -> Self::IntoIter {
        let map = *self.0;
        map.into_iter()
    }
}

impl<'a> IntoIterator for &'a Dict {
    type Item = (&'a Name, &'a Object);
    type IntoIter = indexmap::map::Iter<'a, Name, Object>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// A PDF stream (§7.3.8): a dictionary plus data.
#[derive(Clone, Debug, PartialEq)]
pub struct Stream {
    /// The stream dictionary (`/Length`, `/Filter`, `/DecodeParms`, ...).
    pub dict: Dict,
    /// Where the data is and in which form.
    pub data: StreamData,
}

impl Stream {
    /// Creates a stream.
    pub fn new(dict: Dict, data: StreamData) -> Self {
        Stream { dict, data }
    }
}

/// The data of a [`Stream`].
#[derive(Clone, PartialEq, Eq)]
pub enum StreamData {
    /// Still-encoded bytes inside the source buffer, as a byte range (zero-copy; resolved
    /// through the document that owns the buffer).
    Source(Range<u64>),
    /// Owned bytes, encoded as described by the dictionary's `/Filter`.
    Encoded(Vec<u8>),
    /// Owned plain bytes; a writer encodes them and fixes `/Length`, `/Filter` and
    /// `/DecodeParms`.
    Decoded(Vec<u8>),
}

impl fmt::Debug for StreamData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamData::Source(r) => write!(f, "Source({}..{})", r.start, r.end),
            StreamData::Encoded(v) => write!(f, "Encoded(<{} bytes>)", v.len()),
            StreamData::Decoded(v) => write!(f, "Decoded(<{} bytes>)", v.len()),
        }
    }
}

/// Byte-string constants for common dictionary keys and name values, for use with
/// [`Dict::get`] and the typed getters.
pub mod keys {
    /// `/Type`
    pub const TYPE: &[u8] = b"Type";
    /// `/Subtype`
    pub const SUBTYPE: &[u8] = b"Subtype";
    /// `/Length` (stream length, §7.3.8.2)
    pub const LENGTH: &[u8] = b"Length";
    /// `/Filter` (§7.3.8.2)
    pub const FILTER: &[u8] = b"Filter";
    /// `/DecodeParms` (§7.3.8.2)
    pub const DECODE_PARMS: &[u8] = b"DecodeParms";
    /// `/DL` (decoded length, §7.3.8.2)
    pub const DL: &[u8] = b"DL";
    /// `/F` (external file of a stream, and other uses)
    pub const F: &[u8] = b"F";
    /// `/Root` (trailer, §7.5.5)
    pub const ROOT: &[u8] = b"Root";
    /// `/Info` (trailer)
    pub const INFO: &[u8] = b"Info";
    /// `/Encrypt` (trailer)
    pub const ENCRYPT: &[u8] = b"Encrypt";
    /// `/ID` (trailer)
    pub const ID: &[u8] = b"ID";
    /// `/Size` (trailer)
    pub const SIZE: &[u8] = b"Size";
    /// `/Prev` (trailer)
    pub const PREV: &[u8] = b"Prev";
    /// `/XRefStm` (hybrid-reference trailer, §7.5.8.4)
    pub const XREF_STM: &[u8] = b"XRefStm";
    /// `/W` (cross-reference stream field widths, §7.5.8.2)
    pub const W: &[u8] = b"W";
    /// `/Index` (cross-reference stream subsections)
    pub const INDEX: &[u8] = b"Index";
    /// `/N` (object stream object count, §7.5.7)
    pub const N: &[u8] = b"N";
    /// `/First` (object stream first offset)
    pub const FIRST: &[u8] = b"First";
    /// `/Extends` (object stream chain)
    pub const EXTENDS: &[u8] = b"Extends";
    /// `/Version` (catalog)
    pub const VERSION: &[u8] = b"Version";
    /// `/Pages` (catalog)
    pub const PAGES: &[u8] = b"Pages";
    /// `/Kids` (page tree)
    pub const KIDS: &[u8] = b"Kids";
    /// `/Parent` (page tree)
    pub const PARENT: &[u8] = b"Parent";
    /// `/Count` (page tree)
    pub const COUNT: &[u8] = b"Count";
    /// `/Resources`
    pub const RESOURCES: &[u8] = b"Resources";
    /// `/Contents`
    pub const CONTENTS: &[u8] = b"Contents";
    /// `/MediaBox`
    pub const MEDIA_BOX: &[u8] = b"MediaBox";
    /// `/Catalog` (value of `/Type`)
    pub const CATALOG: &[u8] = b"Catalog";
    /// `/Page` (value of `/Type`)
    pub const PAGE: &[u8] = b"Page";
    /// `/ObjStm` (value of `/Type`)
    pub const OBJ_STM: &[u8] = b"ObjStm";
    /// `/XRef` (value of `/Type`)
    pub const XREF: &[u8] = b"XRef";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objects_are_small() {
        // Every array element and dictionary value is an `Object`: its size is what a file of
        // `[0 0 0 ...]` costs per element.
        assert!(std::mem::size_of::<Object>() <= 32);
        assert!(std::mem::size_of::<Dict>() <= 8);
        let mut d: Dict = (0..100)
            .map(|i| (Name::from(format!("K{i}").as_str()), Object::Int(i)))
            .collect();
        d.shrink_to_fit();
        assert_eq!(d.len(), 100);
        assert_eq!(
            d.into_iter().map(|(_, v)| v.as_int().unwrap()).sum::<i64>(),
            4950
        );
    }

    #[test]
    fn object_model_is_send_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<Object>();
        assert_send_sync::<Dict>();
        assert_send_sync::<Stream>();
        assert_send_sync::<Name>();
        assert_send_sync::<PdfString>();
        assert_send_sync::<ObjectId>();
    }

    #[test]
    fn object_accessors() {
        assert_eq!(Object::Bool(true).as_bool(), Some(true));
        assert_eq!(Object::Int(7).as_int(), Some(7));
        assert_eq!(Object::Int(7).as_f64(), Some(7.0));
        assert_eq!(Object::Real(1.5).as_f64(), Some(1.5));
        assert_eq!(Object::Real(1.5).as_int(), None);
        assert!(Object::name("A").is_name(b"A"));
        assert_eq!(Object::name("A").as_name(), Some(&Name::from("A")));
        assert_eq!(Object::literal_string("x").as_str_bytes(), Some(&b"x"[..]));
        assert!(
            Object::hex_string("x")
                .as_pdf_string()
                .is_some_and(|s| s.hex)
        );
        assert_eq!(
            Object::Ref(ObjectId::new(3, 1)).as_ref(),
            Some(ObjectId::new(3, 1))
        );
        assert_eq!(
            Object::Array(vec![Object::Null]).as_array(),
            Some(&[Object::Null][..])
        );
        assert!(Object::Dict(Dict::new()).as_dict().is_some());
        assert!(Object::Null.is_null());
        assert_eq!(Object::default(), Object::Null);
        let stream: Object = Stream::new(Dict::new(), StreamData::Decoded(vec![1])).into();
        assert!(stream.as_stream().is_some());
        assert!(stream.as_dict().is_none());
        assert_eq!(stream.type_name(), "stream");
    }

    #[test]
    fn mutable_accessors() {
        let mut a = Object::Array(vec![]);
        a.as_array_mut().unwrap().push(Object::Int(1));
        assert_eq!(a.as_array().unwrap().len(), 1);
        let mut d = Object::Dict(Dict::new());
        d.as_dict_mut().unwrap().insert("K", 1);
        assert_eq!(d.as_dict().unwrap().get_int(b"K"), Some(1));
        let mut s: Object = Stream::new(Dict::new(), StreamData::Decoded(vec![])).into();
        s.as_stream_mut().unwrap().dict.insert("K", true);
        assert_eq!(s.as_stream().unwrap().dict.get_bool(b"K"), Some(true));
    }

    #[test]
    fn try_accessors_report_type_mismatch() {
        let err = Object::Null.try_dict().unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::TypeMismatch);
        assert_eq!(
            err.to_string(),
            "type mismatch: expected dictionary, found null"
        );
        assert_eq!(Object::Int(3).try_int().unwrap(), 3);
        assert_eq!(Object::Int(3).try_f64().unwrap(), 3.0);
        assert!(Object::Int(3).try_name().is_err());
        assert!(Object::Int(3).try_array().is_err());
    }

    #[test]
    fn dict_keeps_order_and_typed_getters_work() {
        let mut d = Dict::new();
        d.insert("Type", Object::name("Page"));
        d.insert("Count", 3);
        d.insert("Scale", 0.5);
        d.insert("Flag", true);
        d.insert("T", PdfString::from("title"));
        d.insert("Kids", vec![Object::Ref(ObjectId::new(4, 0))]);
        d.insert("Res", Dict::new());
        d.insert("Parent", ObjectId::new(2, 0));
        d.insert("Gone", Object::Null);
        let keys: Vec<&[u8]> = d.keys().map(Name::as_bytes).collect();
        assert_eq!(
            keys,
            [
                &b"Type"[..],
                b"Count",
                b"Scale",
                b"Flag",
                b"T",
                b"Kids",
                b"Res",
                b"Parent",
                b"Gone"
            ]
        );
        assert!(d.is_type(b"Page"));
        assert_eq!(d.get_int(b"Count"), Some(3));
        assert_eq!(d.get_f64(b"Count"), Some(3.0));
        assert_eq!(d.get_f64(b"Scale"), Some(0.5));
        assert_eq!(d.get_bool(b"Flag"), Some(true));
        assert_eq!(d.get_str_bytes(b"T"), Some(&b"title"[..]));
        assert!(d.get_string(b"T").is_some());
        assert_eq!(d.get_array(b"Kids").map(<[Object]>::len), Some(1));
        assert!(d.get_dict(b"Res").is_some());
        assert_eq!(d.get_ref(b"Parent"), Some(ObjectId::new(2, 0)));
        assert!(d.get_name(b"Type").is_some_and(|n| n == b"Page"));
        assert!(d.contains_key(b"Gone"));
        assert_eq!(d.get_int(b"Gone"), None);

        // Replacing keeps the position; removing keeps the order of the rest.
        assert_eq!(d.insert("Count", 4), Some(Object::Int(3)));
        assert_eq!(d.keys().nth(1).map(Name::as_bytes), Some(&b"Count"[..]));
        assert_eq!(d.remove(b"Type"), Some(Object::name("Page")));
        assert_eq!(d.keys().next().map(Name::as_bytes), Some(&b"Count"[..]));
        assert_eq!(d.len(), 8);
        assert!(!d.is_empty());
        if let Some(v) = d.get_mut(b"Count") {
            *v = Object::Int(5);
        }
        assert_eq!(d.get_int(b"Count"), Some(5));
        for (_, v) in d.iter_mut() {
            *v = Object::Null;
        }
        assert!(d.values().all(Object::is_null));
    }

    #[test]
    fn dict_iterators_and_equality() {
        let d: Dict = [
            (Name::from("A"), Object::Int(1)),
            (Name::from("B"), Object::Int(2)),
        ]
        .into_iter()
        .collect();
        let reversed: Dict = d
            .iter()
            .rev()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        // Equality ignores order.
        assert_eq!(d, reversed);
        let mut e = Dict::with_capacity(1);
        e.extend(d.clone());
        assert_eq!(e, d);
        let pairs: Vec<_> = (&d).into_iter().collect();
        assert_eq!(pairs.len(), 2);
        assert_eq!(format!("{d:?}"), "{/A: Int(1), /B: Int(2)}");
    }

    #[test]
    fn name_comparisons_and_conversions() {
        let n = Name::from("Type");
        assert_eq!(n, *b"Type");
        assert_eq!(n, b"Type");
        assert_eq!(n, b"Type"[..]);
        assert_eq!(n, &b"Type"[..]);
        assert_eq!(n, *"Type");
        assert_eq!(n, "Type");
        assert_eq!(n.as_str(), Some("Type"));
        assert_eq!(n.len(), 4);
        assert!(!n.is_empty());
        assert!(Name::default().is_empty());
        assert_eq!(Name::from(b"Type"), n);
        assert_eq!(Name::from(b"Type".to_vec()), n);
        assert_eq!(Name::from(String::from("Type")), n);
        assert_eq!(Name::from(Cow::Borrowed(&b"Type"[..])), n);
        assert_eq!(Name::new(b"Type".to_vec().into_boxed_slice()), n);
        assert_eq!(&*n.clone().into_bytes(), b"Type");
        assert_eq!(<Name as AsRef<[u8]>>::as_ref(&n), b"Type");
        assert_eq!(Name::from(&[0xFFu8][..]).as_str(), None);
        assert_eq!(format!("{:?}", Name::from("A B")), "/A#20B");
    }

    #[test]
    fn pdf_string_forms() {
        let s = PdfString::new_literal("a(b)");
        assert!(!s.hex);
        assert_eq!(s.len(), 4);
        assert!(!s.is_empty());
        assert_eq!(format!("{s:?}"), "(a(b))");
        let h = PdfString::new_hex(vec![0x01, 0xAB]);
        assert_eq!(format!("{h:?}"), "<01AB>");
        assert_eq!(h.as_bytes(), [0x01, 0xAB]);
        assert_eq!(h.clone().into_bytes(), vec![0x01, 0xAB]);
        assert_ne!(PdfString::new_hex("x"), PdfString::new_literal("x"));
        assert_eq!(PdfString::from(&b"x"[..]), PdfString::from(b"x".to_vec()));
    }

    #[test]
    fn object_id_formatting() {
        let id = ObjectId::new(7, 2);
        assert_eq!(id.to_string(), "7 2 R");
        assert_eq!(format!("{id:?}"), "7 2 R");
        assert_eq!(id.number(), 7);
        assert_eq!(id.generation(), 2);
        assert!(ObjectId::new(1, 5) < ObjectId::new(2, 0));
        assert_eq!(format!("{:?}", Object::Ref(id)), "Ref(7 2 R)");
    }

    #[test]
    fn stream_data_debug_is_compact() {
        assert_eq!(format!("{:?}", StreamData::Source(3..9)), "Source(3..9)");
        assert_eq!(
            format!("{:?}", StreamData::Encoded(vec![0; 100])),
            "Encoded(<100 bytes>)"
        );
        assert_eq!(
            format!("{:?}", StreamData::Decoded(vec![0; 2])),
            "Decoded(<2 bytes>)"
        );
    }

    #[test]
    fn from_impls() {
        assert_eq!(Object::from(true), Object::Bool(true));
        assert_eq!(Object::from(1i64), Object::Int(1));
        assert_eq!(Object::from(1i32), Object::Int(1));
        assert_eq!(Object::from(1u32), Object::Int(1));
        assert_eq!(Object::from(1.5), Object::Real(1.5));
        assert_eq!(Object::from(Name::from("N")), Object::name("N"));
        assert_eq!(
            Object::from(PdfString::from("s")),
            Object::literal_string("s")
        );
        assert_eq!(Object::from(vec![]), Object::Array(vec![]));
        assert_eq!(Object::from(Dict::new()), Object::Dict(Dict::new()));
        assert_eq!(
            Object::from(ObjectId::new(1, 0)),
            Object::Ref(ObjectId::new(1, 0))
        );
    }
}
