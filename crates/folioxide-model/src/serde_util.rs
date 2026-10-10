//! Helpers for the `serde` feature: the representations the DTOs use that a plain derive does
//! not give (M2 brief "DTOs", ARCHITECTURE §A.8 point 4).

use serde::Deserialize;

use crate::page::Rect;

/// A [`Rect`] as its four fields, for deserializing: [`Rect`] is built from it with
/// [`Rect::new`], which normalizes the corners.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RawRect {
    llx: f64,
    lly: f64,
    urx: f64,
    ury: f64,
}

impl From<RawRect> for Rect {
    fn from(raw: RawRect) -> Rect {
        Rect::new(raw.llx, raw.lly, raw.urx, raw.ury)
    }
}

/// `Option<Option<T>>` for a field that has three states: absent (`None`, left out when
/// serializing, with `#[serde(default, skip_serializing_if = "Option::is_none")]`), `null`
/// (`Some(None)`) and a value (`Some(Some(v))`). Plain serde reads `null` as `None`.
pub(crate) mod double_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// Writes `Some(inner)` as `inner` (`null` or the value); `None` as `null` (callers skip
    /// it).
    pub(crate) fn serialize<T, S>(
        value: &Option<Option<T>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: Serializer,
    {
        match value {
            Some(inner) => inner.serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    /// Reads a present field: `null` as `Some(None)`, a value as `Some(Some(v))`. An absent
    /// field never gets here; `#[serde(default)]` makes it `None`.
    pub(crate) fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Some)
    }
}
