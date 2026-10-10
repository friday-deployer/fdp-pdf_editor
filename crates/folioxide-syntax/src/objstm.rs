//! Object streams (ISO 32000-2 §7.5.7).
//!
//! An object stream packs many non-stream objects into one compressed stream. Its decoded data
//! starts with `/N` pairs of integers (`object-number offset`), followed, from byte `/First` on,
//! by the objects themselves; each offset is relative to `/First`. Objects inside an object
//! stream always have generation 0, and cannot be streams.
//!
//! [`ObjStm::parse`] validates `/N`, `/First` and every offset, without trusting any of them for
//! an allocation. Each member is parsed only within its own region (up to the next member's
//! offset), and members of different numbers never share a region, which keeps parsing every
//! member of a hostile container linear in its size. The [`Store`](crate::Store) decodes a
//! container when one of its objects is first loaded and keeps it in a cache of bounded size
//! ([`Limits::max_objstm_cache`](crate::Limits::max_objstm_cache)).
//!
//! # Memory
//!
//! A container costs its decoded data plus 20 bytes per member (a 12-byte entry in header order
//! and an 8-byte entry in the index by number), see [`ObjStm::weight`]. The store caps the
//! decoded data ([`Limits::max_objstm_decoded`](crate::Limits::max_objstm_decoded)) and the
//! members of one container ([`LimitKind::ObjectCap`](crate::LimitKind::ObjectCap)): a header of
//! millions of `1 0` pairs from a few kilobytes of compressed data cannot make it build tables of
//! gigabytes. A file cannot have more objects than that cap anyway.

use std::fmt;

use crate::diag::{Diagnostic, DiagnosticSink};
use crate::error::{Error, Result};
use crate::lexer::{Lexer, Token, TokenKind};
use crate::object::{Object, ObjectId};
use crate::parser::{ParseCtx, parse_object};
use crate::xref::object_header_at;

/// A decoded, validated object stream.
pub(crate) struct ObjStm {
    /// The object number of the container.
    pub num: u32,
    /// The decoded data (at most `u32::MAX` bytes).
    data: Vec<u8>,
    /// One entry per header pair read, in header order (so the cross-reference index addresses
    /// it directly). Invalid pairs are kept with object number 0.
    members: Vec<Entry>,
    /// `(object number, index)` of the valid members, sorted, for lookups by number.
    by_number: Vec<(u32, u32)>,
    /// `/Extends`: the object stream this one extends, if any.
    pub extends: Option<ObjectId>,
    /// Set when the header lists more pairs than the member cap given to [`ObjStm::parse`];
    /// the rest were ignored.
    pub capped: bool,
}

/// One header pair as stored: 12 bytes. `num` is 0 for an invalid pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    num: u32,
    start: u32,
    end: u32,
}

impl Entry {
    const INVALID: Entry = Entry {
        num: 0,
        start: 0,
        end: 0,
    };

    fn is_valid(self) -> bool {
        self.num != 0
    }
}

/// One object of an object stream: its number and its byte region in the decoded data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Member {
    pub num: u32,
    start: usize,
    end: usize,
}

impl Member {
    fn of(entry: Entry) -> Option<Member> {
        entry.is_valid().then_some(Member {
            num: entry.num,
            start: entry.start as usize,
            end: entry.end as usize,
        })
    }
}

impl fmt::Debug for ObjStm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjStm")
            .field("num", &self.num)
            .field("len", &self.data.len())
            .field("members", &self.members.len())
            .field("extends", &self.extends)
            .field("capped", &self.capped)
            .finish()
    }
}

/// The header values of an object stream dictionary, already resolved to direct values.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ObjStmHeader {
    /// `/N`
    pub n: Option<i64>,
    /// `/First`
    pub first: Option<i64>,
    /// `/Extends`
    pub extends: Option<ObjectId>,
}

impl ObjStm {
    /// Validates the header of the decoded container `data` (object `num`), reading at most
    /// `max_members` header pairs (see [`ObjStm::capped`]).
    ///
    /// `repair` applies the leniency policy to a repairable problem: it records a diagnostic and
    /// returns `Ok` in lenient mode, or returns an error in strict mode.
    pub fn parse(
        num: u32,
        header: ObjStmHeader,
        mut data: Vec<u8>,
        max_members: usize,
        repair: &dyn Fn(String) -> Result<()>,
    ) -> Result<ObjStm> {
        let invalid = |message: String| Error::Other {
            code: crate::ErrorCode::Syntax,
            offset: None,
            message: format!("object stream {num}: {message}").into(),
        };
        // Members are addressed with 32-bit offsets (the store never decodes more).
        let Ok(len) = u32::try_from(data.len()) else {
            return Err(invalid(format!(
                "{} decoded bytes are more than an object stream may hold",
                data.len()
            )));
        };
        // The decoder grew the buffer as it went; the container may stay cached for long.
        data.shrink_to_fit();
        let n = header
            .n
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(|| invalid("/N is missing or negative".to_owned()))?;
        let first = header
            .first
            .and_then(|f| usize::try_from(f).ok())
            .filter(|&f| f <= data.len())
            .ok_or_else(|| {
                invalid(format!(
                    "/First is missing or outside the {} decoded bytes",
                    data.len()
                ))
            })?;

        // The header: `/N` pairs of integers in data[..first]. `/N` is not trusted for an
        // allocation; the vector grows with the pairs actually present, up to `max_members`.
        let head = data.get(..first).unwrap_or_default();
        let mut lexer = Lexer::new(head, 0);
        let mut members: Vec<Entry> = Vec::new();
        let mut problems = 0usize;
        let mut capped = false;
        while (members.len() as u64) < n {
            if members.len() >= max_members {
                capped = true;
                break;
            }
            let (Some(obj_num), Some(offset)) = (next_int(&mut lexer), next_int(&mut lexer)) else {
                repair(format!(
                    "object stream {num}: /N is {n} but the header holds {} pairs",
                    members.len()
                ))?;
                break;
            };
            let start = usize::try_from(offset)
                .ok()
                .and_then(|o| first.checked_add(o))
                .filter(|&s| s < data.len())
                .and_then(|s| u32::try_from(s).ok());
            match (u32::try_from(obj_num).ok().filter(|&o| o > 0), start) {
                (Some(obj_num), Some(start)) => members.push(Entry {
                    num: obj_num,
                    start,
                    end: len,
                }),
                _ => {
                    problems += 1;
                    members.push(Entry::INVALID);
                }
            }
        }
        members.shrink_to_fit();
        if problems > 0 {
            repair(format!(
                "object stream {num}: {problems} header entries have an invalid object number \
                 or an offset outside the data"
            ))?;
        }
        let mut previous: Option<u32> = None;
        let mut decreasing = false;
        for entry in members.iter().filter(|e| e.is_valid()) {
            if previous.is_some_and(|p| p >= entry.start) {
                decreasing = true;
                break;
            }
            previous = Some(entry.start);
        }
        if decreasing {
            repair(format!("object stream {num}: offsets are not increasing"))?;
        }

        // Each member ends where the next member (by position) starts. Members of different
        // numbers at one offset would each parse the same bytes, once per number: a hostile
        // header listing thousands of numbers at the offset of one large value makes resolving
        // them all quadratic. The first such member (in header order) keeps the region; the
        // others get an empty one, so they read as unreadable (`null`).
        let mut order: Vec<u32> = (0..members.len())
            .filter(|&i| members.get(i).is_some_and(|e| e.is_valid()))
            .filter_map(|i| u32::try_from(i).ok())
            .collect();
        let start_of = |members: &[Entry], i: u32| {
            members
                .get(i as usize)
                .map_or(u32::MAX, |entry| entry.start)
        };
        order.sort_unstable_by_key(|&i| (start_of(&members, i), i));
        let mut shared = 0usize;
        let mut group = 0;
        while let Some(&head_index) = order.get(group) {
            let start = start_of(&members, head_index);
            let size = order
                .get(group..)
                .unwrap_or_default()
                .iter()
                .take_while(|&&i| start_of(&members, i) == start)
                .count();
            let end = order
                .get(group + size)
                .map_or(len, |&i| start_of(&members, i));
            let owner = members.get(head_index as usize).map_or(0, |e| e.num);
            for &i in order.get(group..group + size).unwrap_or_default() {
                if let Some(entry) = members.get_mut(i as usize) {
                    if entry.num == owner {
                        entry.end = end;
                    } else {
                        entry.end = entry.start;
                        shared += 1;
                    }
                }
            }
            group += size.max(1);
        }
        drop(order);
        if shared > 0 {
            repair(format!(
                "object stream {num}: {shared} header entries share the offset of another object"
            ))?;
        }
        let mut by_number: Vec<(u32, u32)> = members
            .iter()
            .enumerate()
            .filter(|(_, e)| e.is_valid())
            .filter_map(|(i, e)| Some((e.num, u32::try_from(i).ok()?)))
            .collect();
        by_number.sort_unstable();
        by_number.shrink_to_fit();
        Ok(ObjStm {
            num,
            data,
            members,
            by_number,
            extends: header.extends,
            capped,
        })
    }

    /// The length of the decoded data.
    pub fn decoded_len(&self) -> usize {
        self.data.len()
    }

    /// The memory this container holds, in bytes: its data and its member tables (for the
    /// store's cache budget).
    pub fn weight(&self) -> u64 {
        let entries = self
            .members
            .capacity()
            .saturating_mul(std::mem::size_of::<Entry>());
        let index = self
            .by_number
            .capacity()
            .saturating_mul(std::mem::size_of::<(u32, u32)>());
        (std::mem::size_of::<ObjStm>() as u64)
            .saturating_add(self.data.capacity() as u64)
            .saturating_add(entries as u64)
            .saturating_add(index as u64)
    }

    /// The member at header position `index`, if it holds object `num`.
    pub fn member_at(&self, index: u32, num: u32) -> Option<Member> {
        let member = Member::of(*self.members.get(usize::try_from(index).ok()?)?)?;
        (member.num == num).then_some(member)
    }

    /// The first member that holds object `num`, by header position.
    pub fn find(&self, num: u32) -> Option<(u32, Member)> {
        let at = self.by_number.partition_point(|&(n, _)| n < num);
        let &(found, index) = self.by_number.get(at)?;
        if found != num {
            return None;
        }
        Some((index, self.member_at(index, num)?))
    }

    /// Every valid member with its header position.
    pub fn members(&self) -> impl Iterator<Item = (u32, Member)> + '_ {
        self.members
            .iter()
            .enumerate()
            .filter_map(|(i, &e)| Some((u32::try_from(i).ok()?, Member::of(e)?)))
    }

    /// Whether the region of `member` contains `needle` (used to find the catalog when the
    /// trailer must be rebuilt).
    pub fn member_contains(&self, member: Member, needle: &[u8]) -> bool {
        self.data
            .get(member.start..member.end)
            .is_some_and(|region| crate::lexer::find_bytes(region, needle, 0).is_some())
    }

    /// Parses `member`. Its region bounds the parse; offsets in errors and diagnostics are
    /// relative to the decoded data.
    pub fn parse_member(&self, member: Member, ctx: &ParseCtx<'_>) -> Result<Object> {
        let region = self.data.get(..member.end).unwrap_or_default();
        let mut pos = member.start;
        // Some writers put an `N G obj` header inside the container; skip it.
        if let Some((id, after)) = object_header_at(region, pos)
            && id.num == member.num
        {
            ctx.recover(
                crate::DiagnosticKind::ObjectStream,
                Some(pos as u64),
                || {
                    format!(
                        "object {} has an `obj` header inside object stream {}",
                        id.num, self.num
                    )
                },
            )?;
            pos = after;
        }
        let (object, _) = parse_object(region, pos, ctx)?;
        Ok(object)
    }
}

/// The next token as an integer.
fn next_int(lexer: &mut Lexer<'_>) -> Option<i64> {
    match lexer.next_token() {
        Ok(Some(Token {
            kind: TokenKind::Integer(n),
            ..
        })) => Some(n),
        _ => None,
    }
}

/// Forwards diagnostics from parsing inside an object stream, whose offsets are relative to the
/// decoded container and so cannot be reported as file offsets.
pub(crate) struct ContainerSink<'s> {
    pub inner: &'s dyn DiagnosticSink,
    pub stream: u32,
}

impl DiagnosticSink for ContainerSink<'_> {
    fn report(&self, diagnostic: Diagnostic) {
        let message = match diagnostic.offset {
            Some(at) => format!(
                "in object stream {} (decoded byte {at}): {}",
                self.stream, diagnostic.message
            ),
            None => format!("in object stream {}: {}", self.stream, diagnostic.message),
        };
        self.inner
            .report(Diagnostic::new(diagnostic.kind, None, message));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;
    use std::cell::RefCell;

    fn header(n: i64, first: i64) -> ObjStmHeader {
        ObjStmHeader {
            n: Some(n),
            first: Some(first),
            extends: None,
        }
    }

    fn lenient(log: &RefCell<Vec<String>>) -> impl Fn(String) -> Result<()> + '_ {
        move |m| {
            log.borrow_mut().push(m);
            Ok(())
        }
    }

    fn strict(m: String) -> Result<()> {
        Err(Error::new(ErrorCode::Syntax, m))
    }

    /// Builds the decoded data of an object stream from `(number, body)` pairs.
    fn container(objects: &[(u32, &str)]) -> (Vec<u8>, i64) {
        let mut head = String::new();
        let mut body = String::new();
        for (num, text) in objects {
            head.push_str(&format!("{num} {} ", body.len()));
            body.push_str(text);
            body.push(' ');
        }
        let first = head.len() as i64;
        ((head + &body).into_bytes(), first)
    }

    #[test]
    fn parses_members() {
        let (data, first) = container(&[(10, "<< /A 1 >>"), (11, "[1 2 3]"), (12, "42")]);
        let log = RefCell::new(Vec::new());
        let stm = ObjStm::parse(5, header(3, first), data, usize::MAX, &lenient(&log)).unwrap();
        assert!(log.borrow().is_empty(), "{:?}", log.borrow());
        let ctx = ParseCtx::default();
        let m = stm.member_at(1, 11).unwrap();
        assert_eq!(
            stm.parse_member(m, &ctx).unwrap(),
            Object::Array(vec![Object::Int(1), Object::Int(2), Object::Int(3)])
        );
        assert_eq!(stm.member_at(1, 12), None);
        let (index, m) = stm.find(12).unwrap();
        assert_eq!(index, 2);
        assert_eq!(stm.parse_member(m, &ctx).unwrap(), Object::Int(42));
        assert_eq!(stm.find(13), None);
        assert_eq!(stm.members().count(), 3);
        assert!(stm.member_contains(stm.member_at(0, 10).unwrap(), b"/A"));
        assert!(!stm.member_contains(stm.member_at(0, 10).unwrap(), b"[1"));
        assert!(format!("{stm:?}").contains("members: 3"));
    }

    #[test]
    fn members_are_bounded_by_the_next_offset() {
        // Object 10 is an unterminated array; it must not swallow object 11.
        let (data, first) = container(&[(10, "[1 2"), (11, "7")]);
        let stm = ObjStm::parse(5, header(2, first), data, usize::MAX, &strict).unwrap();
        let ctx = ParseCtx::default();
        assert!(
            stm.parse_member(stm.member_at(0, 10).unwrap(), &ctx)
                .is_err()
        );
        assert_eq!(
            stm.parse_member(stm.member_at(1, 11).unwrap(), &ctx)
                .unwrap(),
            Object::Int(7)
        );
    }

    #[test]
    fn validates_n_first_and_offsets() {
        let (data, first) = container(&[(10, "1"), (11, "2")]);
        let bad = |n: Option<i64>, f: Option<i64>| {
            ObjStm::parse(
                5,
                ObjStmHeader {
                    n,
                    first: f,
                    extends: None,
                },
                data.clone(),
                usize::MAX,
                &strict,
            )
            .unwrap_err()
        };
        assert_eq!(bad(None, Some(first)).code(), ErrorCode::Syntax);
        assert_eq!(bad(Some(-1), Some(first)).code(), ErrorCode::Syntax);
        assert_eq!(bad(Some(2), None).code(), ErrorCode::Syntax);
        assert_eq!(bad(Some(2), Some(-1)).code(), ErrorCode::Syntax);
        assert_eq!(bad(Some(2), Some(10_000)).code(), ErrorCode::Syntax);
        // /N larger than the header: lenient keeps what is there; strict refuses.
        let log = RefCell::new(Vec::new());
        let stm = ObjStm::parse(
            5,
            header(1_000_000_000, first),
            data.clone(),
            usize::MAX,
            &lenient(&log),
        )
        .unwrap();
        assert_eq!(stm.members().count(), 2);
        assert_eq!(log.borrow().len(), 1);
        assert!(ObjStm::parse(5, header(3, first), data.clone(), usize::MAX, &strict).is_err());
        // Offsets past the data and invalid object numbers are dropped.
        let data = b"10 0 0 2 11 999 12 4 1 2 3".to_vec();
        let log = RefCell::new(Vec::new());
        let stm = ObjStm::parse(5, header(4, 21), data, usize::MAX, &lenient(&log)).unwrap();
        assert_eq!(
            stm.members().map(|(_, m)| m.num).collect::<Vec<_>>(),
            [10, 12]
        );
        assert_eq!(stm.member_at(1, 0), None);
        assert_eq!(stm.find(12).unwrap().0, 3);
        assert_eq!(log.borrow().len(), 1);
        // Decreasing offsets are reported.
        let data = b"10 2 11 0 7 8".to_vec();
        let log = RefCell::new(Vec::new());
        let stm = ObjStm::parse(5, header(2, 10), data, usize::MAX, &lenient(&log)).unwrap();
        assert_eq!(log.borrow().len(), 1);
        let ctx = ParseCtx::default();
        assert_eq!(
            stm.parse_member(stm.member_at(0, 10).unwrap(), &ctx)
                .unwrap(),
            Object::Int(8)
        );
        assert_eq!(
            stm.parse_member(stm.member_at(1, 11).unwrap(), &ctx)
                .unwrap(),
            Object::Int(7)
        );
    }

    #[test]
    fn members_sharing_an_offset_do_not_share_the_work() {
        // 20,000 numbers at the offset of one 1 MiB string: parsing it once per number would
        // copy 20 GB. Only the first number keeps the region; the same number twice is fine.
        let big = format!("({})", "x".repeat(1 << 20));
        let mut head = String::from("7 0 7 0 ");
        for num in 10..20_010 {
            head.push_str(&format!("{num} 0 "));
        }
        let first = head.len() as i64;
        let data = (head + &big).into_bytes();
        let log = RefCell::new(Vec::new());
        let stm =
            ObjStm::parse(5, header(20_002, first), data, usize::MAX, &lenient(&log)).unwrap();
        // Equal offsets are also not increasing.
        assert_eq!(log.borrow().len(), 2, "{:?}", log.borrow());
        assert!(log.borrow()[1].contains("20000 header entries share"));
        let ctx = ParseCtx::default();
        let started = std::time::Instant::now();
        let mut values = 0;
        for (_, member) in stm.members() {
            if stm.parse_member(member, &ctx).is_ok() {
                values += 1;
            }
        }
        assert!(started.elapsed().as_secs() < 30);
        // Object 7, listed twice, reads the string both times; the others are unreadable.
        assert_eq!(values, 2);
        let seven = stm
            .parse_member(stm.member_at(1, 7).unwrap(), &ctx)
            .unwrap();
        assert_eq!(seven.as_str_bytes().map(<[u8]>::len), Some(1 << 20));
        assert!(stm.parse_member(stm.find(10).unwrap().1, &ctx).is_err());
        // Strict mode refuses the container.
        let data = b"10 0 11 0 (x)".to_vec();
        assert!(ObjStm::parse(5, header(2, 10), data, usize::MAX, &strict).is_err());
    }

    #[test]
    fn header_pairs_are_capped_and_compact() {
        // 200,000 pairs `1 0` (800 KB of header) for one string: at most `max_members` pairs
        // are read, and each costs 20 bytes of tables.
        let pairs = 200_000usize;
        let mut data = "1 0 ".repeat(pairs).into_bytes();
        let first = data.len() as i64;
        data.extend_from_slice(b"(one)");
        let log = RefCell::new(Vec::new());
        let capped = ObjStm::parse(
            5,
            header(pairs as i64, first),
            data.clone(),
            1000,
            &lenient(&log),
        )
        .unwrap();
        assert!(capped.capped);
        assert_eq!(capped.members().count(), 1000);
        assert!(format!("{capped:?}").contains("capped: true"));
        let all = ObjStm::parse(
            5,
            header(pairs as i64, first),
            data.clone(),
            usize::MAX,
            &lenient(&log),
        )
        .unwrap();
        assert!(!all.capped);
        assert_eq!(all.members().count(), pairs);
        let tables = all.weight() - data.len() as u64;
        assert!(
            tables <= pairs as u64 * 20 + 256,
            "{tables} bytes of tables"
        );
        assert!(capped.weight() <= data.len() as u64 + 1000 * 20 + 256);
        // Every pair is object 1 at offset 0: the same number keeps the whole region.
        let ctx = ParseCtx::default();
        let last = all.member_at(pairs as u32 - 1, 1).unwrap();
        assert_eq!(
            all.parse_member(last, &ctx).unwrap().as_str_bytes(),
            Some(&b"one"[..])
        );
        // A cap of zero reads no member at all.
        let none = ObjStm::parse(5, header(1, first), data, 0, &lenient(&log)).unwrap();
        assert!(none.capped);
        assert_eq!(none.members().count(), 0);
    }

    #[test]
    fn regions_end_at_the_next_offset_in_any_header_order() {
        // Offsets out of order and repeated: each member ends at the next distinct offset; a
        // second number at a taken offset gets an empty region.
        let data = b"10 4 11 0 12 4 10 4 (b) (a) ".to_vec();
        let log = RefCell::new(Vec::new());
        let stm = ObjStm::parse(5, header(4, 20), data, usize::MAX, &lenient(&log)).unwrap();
        let ctx = ParseCtx::default();
        let text = |index: u32, num: u32| {
            stm.parse_member(stm.member_at(index, num).unwrap(), &ctx)
                .ok()
                .and_then(|o| o.as_str_bytes().map(<[u8]>::to_vec))
        };
        assert_eq!(text(1, 11).as_deref(), Some(&b"b"[..]));
        assert_eq!(text(0, 10).as_deref(), Some(&b"a"[..]));
        assert_eq!(text(3, 10).as_deref(), Some(&b"a"[..]));
        assert_eq!(text(2, 12), None);
        assert_eq!(stm.find(12).unwrap().0, 2);
        assert_eq!(log.borrow().len(), 2, "{:?}", log.borrow());
    }

    #[test]
    fn header_inside_container_is_skipped() {
        let (data, first) = container(&[(10, "10 0 obj << /A 1 >> endobj")]);
        let stm = ObjStm::parse(5, header(1, first), data, usize::MAX, &strict).unwrap();
        let seen = RefCell::new(Vec::new());
        let sink = |d: Diagnostic| seen.borrow_mut().push(d.kind);
        let ctx = ParseCtx::default().with_diagnostics(&sink);
        let obj = stm
            .parse_member(stm.member_at(0, 10).unwrap(), &ctx)
            .unwrap();
        assert_eq!(obj.as_dict().unwrap().get_int(b"A"), Some(1));
        assert_eq!(*seen.borrow(), [crate::DiagnosticKind::ObjectStream]);
    }

    #[test]
    fn container_sink_drops_relative_offsets() {
        let seen = RefCell::new(Vec::new());
        let inner = |d: Diagnostic| seen.borrow_mut().push(d);
        let sink = ContainerSink {
            inner: &inner,
            stream: 9,
        };
        sink.report(Diagnostic::new(crate::DiagnosticKind::Other, Some(4), "x"));
        sink.report(Diagnostic::new(crate::DiagnosticKind::Other, None, "y"));
        let seen = seen.into_inner();
        assert_eq!(seen[0].offset, None);
        assert_eq!(seen[0].message, "in object stream 9 (decoded byte 4): x");
        assert_eq!(seen[1].message, "in object stream 9: y");
    }
}
