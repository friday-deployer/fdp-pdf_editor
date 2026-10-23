//! What a new annotation or a new appearance can paint, and where (M4 QA round 1, manager
//! rulings R-2 and R-3, finding R5): the checks that keep every appearance a level below `Other`
//! allows inside the `/Rect` that M4 brief §5.5 (ii) makes the allowed region.
//!
//! - [`appearance_stream_problem`]: an appearance stream (`/AP /N`, `/D` or `/R`) must be a form
//!   XObject (§8.10.1: `/Subtype /Form`) with a direct `/BBox` of four finite numbers and, if
//!   present, a direct `/Matrix` of six finite numbers. Conforming viewers clip the appearance to
//!   its `/BBox` and map the transformed box onto the annotation's `/Rect` (§12.5.5); PDFium
//!   paints an appearance without a `/BBox` unclipped, over the whole page (QA finding R5).
//! - [`annotation_flags_problem`]: the annotation flags (§12.5.3) a new annotation or signature
//!   widget may carry. NoZoom and NoRotate make viewers draw the appearance at a fixed size, or
//!   unrotated on a rotated page, at a place derived from the `/Rect`'s corner rather than inside
//!   it (QA findings R3 and A2: poppler paints a NoRotate widget of a page rotated by 90 outside
//!   its `/Rect`); Hidden, NoView and ToggleNoView show other content on screen than in print.
//! - [`markup_geometry_problem`]: the geometry keys of a new markup annotation (`/QuadPoints`,
//!   `/InkList`, `/L` and its leader lines, `/Vertices`, `/Path`, `/CL`), widened by the border
//!   width and the line endings, must lie inside its `/Rect`, and `/RD` and `/BE` must not draw
//!   outside it. poppler draws a highlight from its `/QuadPoints` even when the annotation has
//!   an appearance stream, with rounded caps that reach a quarter of the quadrilateral's height
//!   past it (`AnnotTextMarkup::draw`), and viewers synthesize the other subtypes from these
//!   keys when they have no appearance (QA finding A2).
//!
//! Every check reads only the dictionary it is given (and the stream dictionaries its direct
//! references name), in one pass over bounded arrays. A geometry array must be **direct**, with
//! direct numbers, so the work of checking an annotation is bounded by its own bytes (M4 QA
//! round 2, finding 1: thousands of annotations naming one shared 65,536-number array made the
//! check cost references times numbers); every other value is read with its length checked
//! first, and [`geometry_work`] is charged to the verification's work budget.

use folioxide_syntax::{Dict, Object, Store};

/// The annotation flags (§12.5.3, Table 167) a new annotation may carry: Invisible (1, which
/// applies only to annotation types a viewer does not know), Print (4), ReadOnly (64), Locked
/// (128) and LockedContents (512). Every other flag, and every reserved bit, is refused: Hidden
/// (2), NoZoom (8), NoRotate (16), NoView (32) and ToggleNoView (256).
pub(crate) const ALLOWED_ANNOTATION_FLAGS: i64 = 1 | 4 | 64 | 128 | 512;

/// The most numbers a geometry array of a new annotation may hold; a longer one is refused
/// (a reviewer's ink stroke has a few hundred).
const MAX_GEOMETRY_NUMBERS: usize = 65_536;

/// The largest magnitude of a coordinate of a new widget's or annotation's `/Rect`, of an entry
/// of a new appearance stream's `/BBox` and `/Matrix`, of a corner of that `/BBox` mapped
/// through that `/Matrix`, and of a geometry number of a new annotation (manager ruling R-21):
/// 10^5. ISO 32000-2 Annex C limits user space to 14,400 units, so signers and form fillers
/// stay far below it. PDFium maps these in single precision: a widget whose `/Rect` reached
/// 10^9, or an appearance whose `/Matrix` translated by 2,147,483,647, was painted outside the
/// `/Rect` (M4 QA round 4, findings 4 and 13: 3,800 and 3,270 pixels), and at the earlier bound
/// of 10^7 a `/BBox [0 0 1 1]` translated by 10^7 still was (M4 QA round 5, finding 28: 3,540
/// pixels; none at 10^5). Folioxide's signer refuses a larger appearance rectangle
/// (`InvalidArgument`).
pub(crate) const MAX_GEOMETRY_MAGNITUDE: f64 = 1e5;

/// The largest amplification of single-precision rounding an appearance may have (M4 final fix
/// round 2, findings 2 and 4): the largest magnitude of a coordinate of its `/BBox` mapped
/// through its `/Matrix`, times the scale that maps that box onto the annotation's `/Rect`
/// (`max(Rw / Mw, Rh / Mh)`), at most 2^20. PDFium maps the box onto the `/Rect` in single
/// precision (`CFX_Matrix::MatchRect`: `a = Rw / Mw`, `e = Rx − Mx · a`, then the matrices are
/// concatenated in `float`), so a coordinate `x` of the mapped box is off by about
/// `2^-24 · |x| · Rw / Mw` units on the page: a `/BBox [0 0 0.01 0.01]` translated by 99,999
/// onto a 200-unit widget (`2 · 10^9`) was drawn 2,100 pixels outside it although every number
/// is within ±10^5. At 2^20 the error stays below 1/16 unit; an appearance whose box has the
/// size of its `/Rect` (what signers and form fillers write) has a scale of about 1, so the
/// bound only refuses boxes much smaller than their `/Rect` that lie far from the origin.
pub(crate) const MAX_APPEARANCE_AMPLIFICATION: f64 = 1_048_576.0;

/// Whether `value` is a finite number of magnitude at most [`MAX_GEOMETRY_MAGNITUDE`].
fn within_magnitude(value: f64) -> bool {
    value.is_finite() && value.abs() <= MAX_GEOMETRY_MAGNITUDE
}

/// A normalized rectangle `[x1 y1 x2 y2]` (`x1 <= x2`, `y1 <= y2`) of finite numbers.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Rect {
    x1: f64,
    y1: f64,
    x2: f64,
    y2: f64,
}

impl Rect {
    /// Whether the rectangle has an area.
    pub(super) fn has_area(&self) -> bool {
        self.x2 > self.x1 && self.y2 > self.y1
    }

    /// The width and the height.
    fn size(&self) -> (f64, f64) {
        (self.x2 - self.x1, self.y2 - self.y1)
    }

    /// Whether `(x, y)` lies inside the rectangle shrunk by `margin` on every side.
    fn contains(&self, x: f64, y: f64, margin: f64) -> bool {
        x >= self.x1 + margin
            && x <= self.x2 - margin
            && y >= self.y1 + margin
            && y <= self.y2 - margin
    }
}

/// The keys of a markup annotation whose values are geometry arrays (§12.5.6): each must be a
/// direct array of direct numbers ([`direct_numbers`]); `/InkList` and `/Path` are direct arrays
/// of such arrays.
const GEOMETRY_KEYS: &[&[u8]] = &[
    b"QuadPoints",
    b"InkList",
    b"L",
    b"Vertices",
    b"Path",
    b"CL",
    b"RD",
];

/// The numbers of the **direct** array `value` when every element is a direct finite number of
/// magnitude at most [`MAX_GEOMETRY_MAGNITUDE`] (manager ruling R-21) and there are at most `max`
/// of them. A reference (to the array or to a number in it) is refused:
/// what an annotation's geometry costs to check is then bounded by the annotation's own bytes,
/// and a shared array is never read again for every annotation that names it (M4 QA round 2,
/// finding 1). Writers put an annotation's geometry in the annotation (Acrobat, pdf.js, PDFium,
/// Folioxide's testkit); pyHanko never reaches the `Annotations` level at all.
fn direct_numbers(value: &Object, max: usize) -> Option<Vec<f64>> {
    let items = value.as_array()?;
    if items.len() > max {
        return None;
    }
    items
        .iter()
        .map(|item| item.as_f64().filter(|n| within_magnitude(*n)))
        .collect()
}

/// The number of geometry values of the markup annotation `dict` ([`GEOMETRY_KEYS`], with the
/// arrays nested in `/InkList` and `/Path`): the work [`markup_geometry_problem`] does, which
/// the classifier charges to the verification's work budget before calling it (QA round 2,
/// finding 1). Only direct arrays count (an indirect one is refused without reading it), and
/// reading the lengths costs one step per element of the outer arrays.
pub(super) fn geometry_work(dict: &Dict) -> u64 {
    let mut work: u64 = 0;
    for key in GEOMETRY_KEYS {
        let Some(Object::Array(items)) = dict.get(key) else {
            continue;
        };
        work = work.saturating_add(items.len() as u64);
        if matches!(*key, b"InkList" | b"Path") && items.len() <= MAX_GEOMETRY_NUMBERS {
            for item in items {
                if let Object::Array(inner) = item {
                    work = work.saturating_add(inner.len() as u64);
                }
            }
        }
    }
    work
}

/// The `/Rect` of `dict`, normalized; `None` unless it is four finite numbers of magnitude at
/// most [`MAX_GEOMETRY_MAGNITUDE`] (the array and its numbers may be references: a `/Rect` is
/// four values, whose length is checked before any is read).
pub(super) fn rect_of(store: &Store, dict: &Dict) -> Option<Rect> {
    let value = store.deref(dict.get(b"Rect")?).ok()?;
    let [a, b, c, d] = value.as_array()? else {
        return None;
    };
    let number = |value: &Object| {
        store
            .deref(value)
            .ok()
            .and_then(|n| n.as_f64())
            .filter(|n| within_magnitude(*n))
    };
    let (a, b, c, d) = (number(a)?, number(b)?, number(c)?, number(d)?);
    Some(Rect {
        x1: a.min(c),
        y1: b.min(d),
        x2: a.max(c),
        y2: b.max(d),
    })
}

/// Why the annotation flags `/F` of `dict` are not ones a new annotation or signature widget may
/// carry ([`ALLOWED_ANNOTATION_FLAGS`]); `None` when they are (or there is no `/F`).
pub(crate) fn annotation_flags_problem(store: &Store, dict: &Dict) -> Option<String> {
    let value = dict.get(b"F")?;
    let Some(flags) = store.deref(value).ok().and_then(|f| f.as_int()) else {
        return Some("has an /F that is not an integer".to_owned());
    };
    let refused = flags & !ALLOWED_ANNOTATION_FLAGS;
    if refused == 0 {
        return None;
    }
    let mut names = Vec::new();
    for (bit, name) in [
        (2, "Hidden"),
        (8, "NoZoom"),
        (16, "NoRotate"),
        (32, "NoView"),
        (256, "ToggleNoView"),
    ] {
        if refused & bit != 0 {
            names.push(name);
        }
    }
    if refused & !(2 | 8 | 16 | 32 | 256) != 0 {
        names.push("a reserved bit");
    }
    Some(format!(
        "sets the annotation flag(s) {} (/F {flags}): viewers then draw it hidden, at a fixed \
         size or unrotated, outside its /Rect, or only on screen or only in print (ISO 32000-2 \
         §12.5.3)",
        names.join(", ")
    ))
}

/// The annotation flags a widget of the signed revision may carry for a form fill to be judged
/// (§12.5.3, Table 167): every defined flag but NoZoom (8) and NoRotate (16). A widget with
/// either is drawn at a fixed size, or upright on a rotated page, anchored at its `/Rect`'s
/// upper-left corner (§12.5.3), so a new value or appearance it shows paints outside the `/Rect`
/// (M4 QA round 2, expert finding: 12,067 pixels on a page rotated by 90 in poppler). Hidden,
/// NoView and ToggleNoView change whether it is shown, not where.
pub(crate) const FORM_WIDGET_FLAGS: i64 = 1 | 2 | 4 | 32 | 64 | 128 | 256 | 512;

/// Whether the annotation flags `/F` of the widget `dict` (in `store`) let it be filled
/// ([`FORM_WIDGET_FLAGS`]): `false` for NoZoom, NoRotate, a reserved bit, or an `/F` that is not
/// an integer.
pub(crate) fn form_widget_flags_ok(store: &Store, dict: &Dict) -> bool {
    let Some(value) = dict.get(b"F") else {
        return true;
    };
    store
        .deref(value)
        .ok()
        .and_then(|f| f.as_int())
        .is_some_and(|flags| flags & !FORM_WIDGET_FLAGS == 0)
}

/// Why the appearance `value` (an `/N`, `/D` or `/R` entry of an appearance dictionary, in
/// `store`) is not a form XObject that viewers clip to its `/BBox` mapped onto the annotation's
/// `/Rect` (§12.5.5, §8.10.1): it is not an indirect reference to a stream (a dictionary of
/// appearance states is refused too), has no `/Subtype /Form`, no direct `/BBox` of four finite
/// numbers (with an area, when `visible`: the annotation's `/Rect` has one), or a `/Matrix` that
/// is not six finite numbers (an invertible one, when `visible`), or a box that single-precision
/// viewers map onto the `/Rect` (`rect`, the annotation's [`rect_of`]) imprecisely
/// ([`form_dict_problem`]). `None` when it is one.
pub(super) fn appearance_stream_problem(
    store: &Store,
    value: &Object,
    visible: bool,
    rect: Option<Rect>,
) -> Option<String> {
    let id = match value {
        Object::Ref(id) => id,
        Object::Dict(_) => {
            return Some(
                "is a dictionary (of appearance states), not an appearance stream".to_owned(),
            );
        }
        _ => return Some("is not a reference to an appearance stream".to_owned()),
    };
    match store.resolve(*id).as_deref() {
        Ok(Object::Stream(stream)) => {
            form_dict_problem(&stream.dict, &id.to_string(), visible, rect)
        }
        Ok(Object::Dict(_)) => Some(format!(
            "{id} is a dictionary (of appearance states), not an appearance stream"
        )),
        _ => Some(format!("{id} is not a stream")),
    }
}

/// [`appearance_stream_problem`] for the dictionary `stream` of the appearance stream `id`, shown
/// in the annotation `/Rect` `rect` when `visible` (`None`: a `/Rect` that cannot be read, taken
/// as the largest one the bound allows).
pub(super) fn form_dict_problem(
    stream: &Dict,
    id: &str,
    visible: bool,
    rect: Option<Rect>,
) -> Option<String> {
    if !stream.get_name(b"Subtype").is_some_and(|s| s == b"Form") {
        return Some(format!(
            "{id} is not a form XObject (/Subtype /Form, ISO 32000-2 §8.10.1)"
        ));
    }
    // Lengths are checked before any value is read: a shared appearance stream with a long
    // /BBox must not cost its length for every annotation that names it (QA round 2, finding 1).
    let beyond = format!(
        "beyond ±{MAX_GEOMETRY_MAGNITUDE:e}, which viewers that map the appearance onto the \
         /Rect in single precision (PDFium) place elsewhere"
    );
    // Read as any numbers first (direct, finite), so a number beyond the bound is named as such.
    let numbers = |value: &Object, len: usize| -> Option<Vec<f64>> {
        let items = value.as_array().filter(|items| items.len() == len)?;
        items
            .iter()
            .map(|item| item.as_f64().filter(|n| n.is_finite()))
            .collect()
    };
    let bbox = stream.get(b"BBox").and_then(|value| numbers(value, 4));
    let Some([a, b, c, d]) = bbox.as_deref().and_then(|v| <[f64; 4]>::try_from(v).ok()) else {
        return Some(format!(
            "{id} has no direct /BBox of four numbers, so viewers need not clip it to the \
             annotation's /Rect (PDFium paints it unclipped; ISO 32000-2 §12.5.5)"
        ));
    };
    if visible && ((c - a) * (d - b)).abs() <= 0.0 {
        return Some(format!("{id}'s /BBox has no area"));
    }
    if ![a, b, c, d].into_iter().all(within_magnitude) {
        return Some(format!("{id}'s /BBox has an entry {beyond}"));
    }
    let mut matrix = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];
    if let Some(value) = stream.get(b"Matrix") {
        let values = numbers(value, 6);
        let Some(values) = values.as_deref().and_then(|v| <[f64; 6]>::try_from(v).ok()) else {
            return Some(format!(
                "{id} has a /Matrix that is not a direct array of six numbers"
            ));
        };
        if !values.into_iter().all(within_magnitude) {
            return Some(format!("{id}'s /Matrix has an entry {beyond}"));
        }
        let [ma, mb, mc, md, ..] = values;
        if visible && (ma * md - mb * mc).abs() <= 0.0 {
            return Some(format!("{id}'s /Matrix is not invertible"));
        }
        matrix = values;
    }
    // Manager ruling R-21: the /BBox mapped through the /Matrix (§8.10.1, the box §12.5.5 maps
    // onto the /Rect) stays within the bound too, so a small box translated far away is refused.
    let [ma, mb, mc, md, me, mf] = matrix;
    let corners =
        [(a, b), (c, b), (a, d), (c, d)].map(|(x, y)| (ma * x + mc * y + me, mb * x + md * y + mf));
    if !corners
        .iter()
        .all(|&(x, y)| within_magnitude(x) && within_magnitude(y))
    {
        return Some(format!(
            "{id}'s /BBox mapped through its /Matrix reaches {beyond}"
        ));
    }
    // Final fix round 2, findings 2 and 4: the precision of mapping that box onto the /Rect in
    // single precision (§12.5.5 steps b and c; MAX_APPEARANCE_AMPLIFICATION).
    if visible {
        let (low_x, high_x, low_y, high_y) = corners.iter().fold(
            (
                f64::INFINITY,
                f64::NEG_INFINITY,
                f64::INFINITY,
                f64::NEG_INFINITY,
            ),
            |(lx, hx, ly, hy), &(x, y)| (lx.min(x), hx.max(x), ly.min(y), hy.max(y)),
        );
        let (box_w, box_h) = (high_x - low_x, high_y - low_y);
        let largest = 2.0 * MAX_GEOMETRY_MAGNITUDE;
        let (rect_w, rect_h) = rect.map_or((largest, largest), |r| r.size());
        let reach = corners
            .iter()
            .fold(0.0_f64, |m, &(x, y)| m.max(x.abs()).max(y.abs()));
        let scale = |rect: f64, mapped: f64| {
            if rect <= 0.0 {
                0.0
            } else if mapped > 0.0 {
                rect / mapped
            } else {
                f64::INFINITY
            }
        };
        let amplification = reach * scale(rect_w, box_w).max(scale(rect_h, box_h));
        // NaN (a box without area) is refused too.
        if amplification.is_nan() || amplification > MAX_APPEARANCE_AMPLIFICATION {
            return Some(format!(
                "{id}'s /BBox mapped through its /Matrix is {box_w}×{box_h} units, up to \
                 {reach} units from the origin, and is scaled onto its /Rect: viewers that do \
                 that in single precision (PDFium) place it up to {:.1} units off, outside the \
                 /Rect (the coordinate times the scale is above 2^20)",
                amplification / 16_777_216.0
            ));
        }
    }
    None
}

/// The border width of an annotation (§12.5.4): `/BS /W`, else the third value of `/Border`,
/// else 1; the larger when both are given. `Err` for a value that is not a non-negative finite
/// number.
fn border_width(store: &Store, dict: &Dict) -> std::result::Result<f64, String> {
    let mut width: Option<f64> = None;
    if let Some(bs) = dict.get(b"BS") {
        // Read in place (never copied: a shared dictionary costs one lookup per annotation).
        let bs = store
            .deref(bs)
            .map_err(|_| "has a /BS that cannot be read".to_owned())?;
        let bs = bs
            .as_dict()
            .ok_or_else(|| "has a /BS that is not a dictionary".to_owned())?;
        if let Some(w) = bs.get(b"W") {
            let w = store
                .deref(w)
                .ok()
                .and_then(|w| w.as_f64())
                .filter(|w| w.is_finite() && *w >= 0.0)
                .ok_or_else(|| "has a /BS /W that is not a non-negative number".to_owned())?;
            width = Some(w);
        }
    }
    if let Some(border) = dict.get(b"Border") {
        let values = store
            .deref(border)
            .map_err(|_| "has a /Border that cannot be read".to_owned())?;
        // §12.5.2 Table 166: three numbers and an optional dash array.
        let values = values.as_array().filter(|v| v.len() <= 4).ok_or_else(|| {
            "has a /Border that is not an array of at most four entries".to_owned()
        })?;
        if let Some(w) = values.get(2) {
            let w = w
                .as_f64()
                .filter(|w| w.is_finite() && *w >= 0.0)
                .ok_or_else(|| {
                    "has a /Border width that is not a non-negative number".to_owned()
                })?;
            width = Some(width.map_or(w, |seen| seen.max(w)));
        }
    }
    Ok(width.unwrap_or(1.0))
}

/// Whether `/LE` of `dict` (a name, or an array of two names, Tables 178 and 181) draws a line
/// ending other than `/None`; anything else counts as drawing one (the larger margin).
fn has_line_endings(store: &Store, dict: &Dict) -> bool {
    let Some(value) = dict.get(b"LE") else {
        return false;
    };
    let Ok(value) = store.deref(value) else {
        return true;
    };
    let none = |o: &Object| o.is_name(b"None");
    match &*value {
        Object::Array(items) if items.len() <= 2 => !items.iter().all(none),
        Object::Array(_) => true,
        other => !none(other),
    }
}

/// Why the geometry of the new markup annotation `dict` (of `subtype`, in `store`) may paint
/// outside its `/Rect`; `None` when it stays inside. See the module documentation.
pub(super) fn markup_geometry_problem(
    store: &Store,
    subtype: &[u8],
    dict: &Dict,
) -> Option<String> {
    let Some(rect) = rect_of(store, dict) else {
        return Some(format!(
            "has no /Rect of four finite numbers within ±{MAX_GEOMETRY_MAGNITUDE:e}"
        ));
    };
    if subtype == b"Popup" {
        return None;
    }
    if !rect.has_area() {
        return Some("has a /Rect without an area".to_owned());
    }
    let width = match border_width(store, dict) {
        Ok(width) => width,
        Err(reason) => return Some(reason),
    };
    // §12.5.4: a stroke is centred on the path; poppler's line endings reach 6 border widths
    // along the line and half that across it.
    let stroke = width / 2.0;
    let endings = if has_line_endings(store, dict) {
        3.0 * width.max(1.0)
    } else {
        0.0
    };
    let outside = |key: &str| {
        Some(format!(
            "has a /{key} that reaches outside its /Rect (with the border width and line \
             endings), where viewers draw it (ISO 32000-2 §12.5.6)"
        ))
    };
    let malformed = |key: &str| {
        Some(format!(
            "has a /{key} that is not a direct array of numbers (geometry is written in the \
             annotation itself: an indirect array or number is refused, M4 QA round 2)"
        ))
    };
    // At most MAX_GEOMETRY_NUMBERS values in all (a reviewer's ink has a few hundred points).
    if geometry_work(dict) > MAX_GEOMETRY_NUMBERS as u64 {
        return Some(format!(
            "has more than {MAX_GEOMETRY_NUMBERS} geometry values (/QuadPoints, /InkList, /L, \
             /Vertices, /Path, /CL, /RD)"
        ));
    }
    let numbers = |value: &Object| direct_numbers(value, MAX_GEOMETRY_NUMBERS);
    // Every (x, y) pair of `values` inside the rect shrunk by `margin`.
    let pairs_inside = |values: &[f64], margin: f64| {
        values.len().is_multiple_of(2)
            && !values.is_empty()
            && values
                .chunks_exact(2)
                .all(|p| matches!(p, [x, y] if rect.contains(*x, *y, margin)))
    };
    if let Some(be) = dict.get(b"BE") {
        let solid = store.deref(be).ok().is_some_and(|be| {
            be.as_dict()
                .is_some_and(|be| be.get(b"S").is_none_or(|s| s.is_name(b"S")))
        });
        if !solid {
            return Some(
                "has a border effect /BE other than none (/S /S): a cloudy border is drawn \
                 around the shape, which viewers may place outside its /Rect"
                    .to_owned(),
            );
        }
    }
    if let Some(rd) = dict.get(b"RD") {
        let ok = direct_numbers(rd, 4).is_some_and(|v| match v.as_slice() {
            [l, t, r, b] => {
                [l, t, r, b].iter().all(|n| **n >= 0.0)
                    && l + r < rect.x2 - rect.x1
                    && t + b < rect.y2 - rect.y1
            }
            _ => false,
        });
        if !ok {
            return Some(
                "has an /RD that is not four non-negative insets that fit its /Rect (ISO \
                 32000-2 §12.5.6.8: a negative one draws outside it)"
                    .to_owned(),
            );
        }
    }
    match subtype {
        b"Highlight" | b"Underline" | b"Squiggly" | b"StrikeOut" => {
            let Some(values) = dict.get(b"QuadPoints").and_then(numbers) else {
                return malformed("QuadPoints");
            };
            if values.is_empty() || !values.len().is_multiple_of(8) {
                return malformed("QuadPoints");
            }
            // poppler's caps reach a quarter of the quadrilateral's height past it, and the
            // underline, strike-out and squiggle strokes half a unit.
            let ok = values.chunks_exact(8).all(|quad| {
                let [_, y1, _, y2, _, y3, _, y4] = quad else {
                    return false;
                };
                let ys = [*y1, *y2, *y3, *y4];
                let height = ys.iter().copied().fold(f64::MIN, f64::max)
                    - ys.iter().copied().fold(f64::MAX, f64::min);
                pairs_inside(quad, height / 4.0 + 0.5)
            });
            if !ok {
                return outside("QuadPoints");
            }
        }
        b"Ink" => {
            let Some(Object::Array(strokes)) = dict.get(b"InkList") else {
                return malformed("InkList");
            };
            if strokes.is_empty() || strokes.len() > MAX_GEOMETRY_NUMBERS {
                return malformed("InkList");
            }
            for stroke_points in strokes {
                let Some(values) = numbers(stroke_points) else {
                    return malformed("InkList");
                };
                if !pairs_inside(&values, stroke) {
                    return outside("InkList");
                }
            }
        }
        b"Line" => {
            let Some(values) = dict.get(b"L").and_then(|l| direct_numbers(l, 4)) else {
                return malformed("L");
            };
            let [x1, y1, x2, y2] = values.as_slice() else {
                return malformed("L");
            };
            if !pairs_inside(&values, stroke + endings) {
                return outside("L");
            }
            if let Some(problem) = leader_lines(store, dict, [*x1, *y1, *x2, *y2], &rect, stroke) {
                return Some(problem);
            }
        }
        b"Polygon" | b"PolyLine" => {
            let Some(values) = dict.get(b"Vertices").and_then(numbers) else {
                return malformed("Vertices");
            };
            if !pairs_inside(&values, stroke + endings) {
                return outside("Vertices");
            }
        }
        b"FreeText" => {
            if let Some(cl) = dict.get(b"CL") {
                let Some(values) = direct_numbers(cl, 6) else {
                    return malformed("CL");
                };
                if !matches!(values.len(), 4 | 6) || !pairs_inside(&values, stroke + endings) {
                    return outside("CL");
                }
            }
        }
        _ => {}
    }
    if let Some(path) = dict.get(b"Path") {
        // PDF 2.0 paths (Ink, Polygon, PolyLine): arrays of 2 (a point) or 6 (a Bézier
        // segment) numbers; a curve lies in the convex hull of its control points.
        let Object::Array(segments) = path else {
            return malformed("Path");
        };
        if segments.len() > MAX_GEOMETRY_NUMBERS {
            return malformed("Path");
        }
        for segment in segments {
            let Some(values) = direct_numbers(segment, 6) else {
                return malformed("Path");
            };
            if !matches!(values.len(), 2 | 6) || !pairs_inside(&values, stroke + endings) {
                return outside("Path");
            }
        }
    }
    None
}

/// Why the leader lines of a Line annotation (§12.5.6.7: `/LL`, `/LLE`, `/LLO` perpendicular to
/// the line `[x1 y1 x2 y2]`) or its caption (`/Cap true`) may paint outside `rect`.
fn leader_lines(
    store: &Store,
    dict: &Dict,
    [x1, y1, x2, y2]: [f64; 4],
    rect: &Rect,
    stroke: f64,
) -> Option<String> {
    let number = |key: &[u8]| -> std::result::Result<f64, ()> {
        match dict.get(key) {
            None => Ok(0.0),
            Some(value) => store
                .deref(value)
                .ok()
                .and_then(|v| v.as_f64())
                .filter(|v| v.is_finite())
                .ok_or(()),
        }
    };
    if dict
        .get(b"Cap")
        .and_then(|c| store.deref(c).ok())
        .is_some_and(|c| !matches!(&*c, Object::Bool(false)))
    {
        return Some(
            "has a caption (/Cap), whose text viewers place beside the line, not within a \
             bounded part of its /Rect"
                .to_owned(),
        );
    }
    let (Ok(ll), Ok(lle), Ok(llo)) = (number(b"LL"), number(b"LLE"), number(b"LLO")) else {
        return Some("has an /LL, /LLE or /LLO that is not a number".to_owned());
    };
    if lle < 0.0 || llo < 0.0 {
        return Some("has a negative /LLE or /LLO (ISO 32000-2 Table 178)".to_owned());
    }
    if ll == 0.0 {
        return None;
    }
    let (dx, dy) = (x2 - x1, y2 - y1);
    let length = dx.hypot(dy);
    if length <= 0.0 {
        return Some("has leader lines on a line of no length".to_owned());
    }
    // The leader lines go perpendicular to the line, a positive /LL "up" from it (the line
    // turned 90 degrees counter-clockwise), through /LLO, /LL and /LLE beyond.
    let (nx, ny) = (-dy / length, dx / length);
    let sign = ll.signum();
    for (px, py) in [(x1, y1), (x2, y2)] {
        for distance in [sign * llo, ll, ll + sign * lle] {
            if !rect.contains(px + nx * distance, py + ny * distance, stroke) {
                return Some(
                    "has leader lines (/LL, /LLE, /LLO) that reach outside its /Rect".to_owned(),
                );
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use folioxide_syntax::OpenOptions;

    fn parse(text: &str) -> Dict {
        folioxide_syntax::parse_object(text.as_bytes(), 0, &folioxide_syntax::ParseCtx::default())
            .unwrap()
            .0
            .as_dict()
            .unwrap()
            .clone()
    }

    fn store() -> Store {
        Store::open_bytes(
            folioxide_testkit::fixtures::syntax::minimal(),
            &OpenOptions::default(),
        )
        .unwrap()
    }

    #[test]
    fn appearances_are_mapped_onto_the_rect_precisely() {
        // M4 final fix round 2, findings 2 and 4 (variants F4-k-pdfium-bbox-*,
        // R3-k-pdfium-late-bbox-*): a small /BBox far from the origin, scaled onto a 200 × 30
        // widget, is placed imprecisely by single-precision viewers although every number is
        // within ±10^5.
        let rect = rect_of(&store(), &parse("<< /Rect [100 700 300 730] >>"));
        let check = |bbox: &str, matrix: &str| {
            let dict = parse(&format!(
                "<< /Subtype /Form /BBox [{bbox}] /Matrix [{matrix}] >>"
            ));
            form_dict_problem(&dict, "8 0 R", true, rect)
        };
        for (bbox, matrix) in [
            ("0 0 .01 .01", "1 0 0 1 99999 0"),
            ("0 0 .01 .01", "1 0 0 1 50000 0"),
            ("0 0 .01 .01", "1 0 0 1 10000 0"),
            ("0 0 .1 .1", "1 0 0 1 99999.9 0"),
            ("0 0 .1 .1", "1 0 0 1 0 99999"),
            ("99999 0 99999.01 .01", "1 0 0 1 0 0"),
            ("0 0 1 1", "1 0 0 1 99000 0"),
        ] {
            let problem = check(bbox, matrix).unwrap_or_default();
            assert!(
                problem.contains("single precision"),
                "{bbox} {matrix}: {problem}"
            );
        }
        // What signers and form fillers write: a box of the widget's size, wherever it is, and
        // a small box near the origin.
        for (bbox, matrix) in [
            ("0 0 200 30", "1 0 0 1 0 0"),
            ("0 0 200 30", "1 0 0 1 99000 -99000"),
            ("100 700 300 730", "1 0 0 1 0 0"),
            ("0 0 30 200", "0 1 -1 0 30 0"),
            ("0 0 2000 300", ".1 0 0 .1 0 0"),
            ("0 0 1 1", "1 0 0 1 0 0"),
            ("0 0 .01 .01", "1 0 0 1 0 0"),
            ("0 0 1 1", "1 0 0 1 5000 0"),
        ] {
            assert_eq!(check(bbox, matrix), None, "{bbox} {matrix}");
        }
        // Folioxide's own appearances (a /BBox of the widget's size, rotated by its /Matrix)
        // pass at the edges of the rects its signer accepts (within ±10^5, any rotation).
        let store = store();
        for [x1, y1, x2, y2] in [
            [300.0, 100.0, 500.0, 160.0],
            [-100_000.0, -100_000.0, -99_800.0, -99_940.0],
            [0.0, 0.0, 100_000.0, 100_000.0],
            [99_999.0, 99_999.0, 99_999.5, 99_999.25],
        ] {
            let model_rect = folioxide_model::Rect::new(x1, y1, x2, y2);
            let widget = parse(&format!("<< /Rect [{x1} {y1} {x2} {y2}] >>"));
            for rotation in [
                folioxide_model::Rotation::R0,
                folioxide_model::Rotation::R90,
                folioxide_model::Rotation::R180,
                folioxide_model::Rotation::R270,
            ] {
                let mut numbers = crate::field::NewNumbers::new(&store);
                let appearance = crate::appearance::SignatureAppearance::new(model_rect)
                    .with_text(crate::appearance::AppearanceText::Lines(Vec::new()));
                let built =
                    crate::appearance::build(&appearance, model_rect, rotation, &[], &mut numbers)
                        .unwrap();
                let form = built.objects[0].1.as_stream().unwrap();
                assert_eq!(
                    form_dict_problem(&form.dict, "n", true, rect_of(&store, &widget)),
                    None,
                    "{x1} {y1} {x2} {y2} {rotation:?}"
                );
            }
        }
        // An invisible annotation is not mapped; an unreadable /Rect counts as the largest.
        let dict = parse("<< /Subtype /Form /BBox [0 0 .01 .01] /Matrix [1 0 0 1 99999 0] >>");
        assert_eq!(form_dict_problem(&dict, "8 0 R", false, None), None);
        let dict = parse("<< /Subtype /Form /BBox [0 0 200 30] /Matrix [1 0 0 1 99000 0] >>");
        assert!(form_dict_problem(&dict, "8 0 R", true, None).is_some());
        assert_eq!(form_dict_problem(&dict, "8 0 R", true, rect), None);
    }

    #[test]
    fn flags_are_a_whitelist() {
        let store = store();
        for (flags, ok) in [
            (0, true),
            (4, true),
            (132, true),
            (1 | 4 | 64 | 128 | 512, true),
            (2, false),
            (6, false),
            (8, false),
            (16, false),
            (20, false),
            (28, false),
            (32, false),
            (256, false),
            (1024, false),
        ] {
            let dict = parse(&format!("<< /F {flags} >>"));
            assert_eq!(
                annotation_flags_problem(&store, &dict).is_none(),
                ok,
                "/F {flags}"
            );
        }
        assert!(annotation_flags_problem(&store, &parse("<< >>")).is_none());
        assert!(annotation_flags_problem(&store, &parse("<< /F /Print >>")).is_some());
        let problem = annotation_flags_problem(&store, &parse("<< /F 20 >>")).unwrap();
        assert!(problem.contains("NoRotate"), "{problem}");
    }

    #[test]
    fn highlights_keep_their_caps_inside_the_rect() {
        let store = store();
        let check = |rect: &str, quad: &str| {
            markup_geometry_problem(
                &store,
                b"Highlight",
                &parse(&format!("<< /Rect {rect} /QuadPoints {quad} >>")),
            )
        };
        let quad = "[70 740 300 740 70 715 300 715]";
        // The quadrilateral's bounding box itself is not enough: the caps reach 25/4 + 0.5.
        assert!(check("[70 715 300 740]", quad).is_some());
        assert!(check("[63 708 307 747]", quad).is_none());
        // Far outside a small rect (QA variant A2-highlight-noAP-quadpoints-outside-rect).
        assert!(check("[60 330 80 350]", "[60 390 560 390 60 330 560 330]").is_some());
        assert!(check("[63 708 307 747]", "[70 740 300 740 70 715]").is_some());
        assert!(check("[63 708 307 747]", "[]").is_some());
    }

    #[test]
    fn geometry_of_each_subtype_is_checked() {
        let store = store();
        let check =
            |subtype: &[u8], text: &str| markup_geometry_problem(&store, subtype, &parse(text));
        assert!(
            check(
                b"Ink",
                "<< /Rect [100 200 300 260] /InkList [[110 210 290 250]] >>"
            )
            .is_none()
        );
        assert!(
            check(
                b"Ink",
                "<< /Rect [100 200 300 260] /InkList [[110 210 590 250]] >>"
            )
            .is_some()
        );
        assert!(
            check(
                b"Ink",
                "<< /Rect [100 200 300 260] /InkList [[100 200 290 250]] >>"
            )
            .is_some(),
            "the stroke"
        );
        assert!(check(b"Line", "<< /Rect [0 0 100 100] /L [10 10 90 90] >>").is_none());
        assert!(check(b"Line", "<< /Rect [0 0 100 100] /L [10 10 190 90] >>").is_some());
        assert!(
            check(
                b"Line",
                "<< /Rect [0 0 100 100] /L [1 1 90 90] /LE [/OpenArrow /None] >>"
            )
            .is_some(),
            "line endings"
        );
        assert!(check(b"Line", "<< /Rect [0 0 100 100] /L [10 50 90 50] /LL 20 >>").is_none());
        assert!(check(b"Line", "<< /Rect [0 0 100 100] /L [10 50 90 50] /LL 60 >>").is_some());
        assert!(
            check(
                b"Line",
                "<< /Rect [0 0 100 100] /L [10 50 90 50] /Cap true >>"
            )
            .is_some()
        );
        assert!(
            check(
                b"Polygon",
                "<< /Rect [0 0 100 100] /Vertices [10 10 90 10 50 90] >>"
            )
            .is_none()
        );
        assert!(
            check(
                b"PolyLine",
                "<< /Rect [0 0 100 100] /Vertices [10 10 190 10] >>"
            )
            .is_some()
        );
        assert!(
            check(
                b"Polygon",
                "<< /Rect [0 0 100 100] /Path [[10 10] [20 20 30 30 200 40]] >>"
            )
            .is_some()
        );
        assert!(
            check(
                b"FreeText",
                "<< /Rect [0 0 100 100] /CL [10 10 50 50 60 60] >>"
            )
            .is_none()
        );
        assert!(check(b"FreeText", "<< /Rect [0 0 100 100] /CL [10 10 500 50] >>").is_some());
        assert!(check(b"Square", "<< /Rect [0 0 100 100] /RD [1 1 1 1] >>").is_none());
        assert!(check(b"Square", "<< /Rect [0 0 100 100] /RD [-10 1 1 1] >>").is_some());
        assert!(check(b"Square", "<< /Rect [0 0 100 100] /RD [60 1 60 1] >>").is_some());
        assert!(check(b"Square", "<< /Rect [0 0 100 100] /BE << /S /C /I 2 >> >>").is_some());
        assert!(check(b"Square", "<< /Rect [0 0 100 100] /BE << /S /S >> >>").is_none());
        assert!(check(b"Square", "<< /Rect [0 0 100 100] /BS << /W -1 >> >>").is_some());
        assert!(check(b"Text", "<< /Rect [0 0 0 0] >>").is_some(), "no area");
        assert!(check(b"Popup", "<< /Rect [0 0 0 0] >>").is_none());
        assert!(check(b"Text", "<< /Rect [0 0 1 (x)] >>").is_some());
    }
}
