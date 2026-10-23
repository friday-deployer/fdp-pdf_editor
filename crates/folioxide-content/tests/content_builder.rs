//! `ContentBuilder` (M4 brief §3.2, §6.2 "Content"): the exact bytes of every operator, operands
//! that read back through the M1 lexer as the values the serializer's rules give, and the
//! refusal of operands PDF cannot hold.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use folioxide_content::builder::ContentBuilder;
use folioxide_syntax::serialize::{MAX_REAL, canonical_real};
use folioxide_syntax::{ErrorCode, Lexer, Strictness, TokenKind};

/// A token of a content stream, as the M1 lexer reads it.
#[derive(Debug, PartialEq)]
enum Tok {
    Num(f64),
    Name(Vec<u8>),
    Str(Vec<u8>),
    Op(String),
}

/// Lexes `content` in strict mode; every token must be a number, name, literal string or
/// operator keyword.
fn lex(content: &[u8]) -> Vec<Tok> {
    let mut lexer = Lexer::new(content, 0).with_strictness(Strictness::Strict);
    let mut out = Vec::new();
    while let Some(token) = lexer.next_token().unwrap() {
        out.push(match token.kind {
            TokenKind::Integer(i) => Tok::Num(i as f64),
            TokenKind::Real(r) => Tok::Num(r),
            TokenKind::Name(n) => Tok::Name(n.into_owned()),
            TokenKind::LiteralString(s) => Tok::Str(s.into_owned()),
            TokenKind::Keyword(k) => Tok::Op(String::from_utf8(k.to_vec()).unwrap()),
            other => panic!("unexpected token {other:?}"),
        });
    }
    out
}

fn op(operands: &[f64], name: &str) -> Vec<Tok> {
    let mut out: Vec<Tok> = operands
        .iter()
        .map(|&v| Tok::Num(canonical_real(v)))
        .collect();
    out.push(Tok::Op(name.to_owned()));
    out
}

#[test]
fn content_builder_operators_golden() {
    let third = 1.0 / 3.0;
    let mut b = ContentBuilder::new();
    b.save()
        .concat([1.0, 0.0, 0.0, 1.0, 10.5, -20.25])
        .line_width(0.75)
        .stroke_gray(0.0)
        .fill_gray(1.0)
        .fill_rgb(1.0, 0.5, 0.0)
        .stroke_rgb(0.2, 0.4, 0.6)
        .rect(0.5, 0.5, 199.0, 59.0)
        .stroke()
        .rect(2.0, 2.0, 10.0, 10.0)
        .fill()
        .move_to(0.0, 0.0)
        .line_to(third, 2.0 * third)
        .close_path()
        .stroke()
        .rect(0.0, 0.0, 200.0, 60.0)
        .clip()
        .end_path()
        .save()
        .concat([48.0, 0.0, 0.0, 32.0, 2.0, 14.0])
        .draw_xobject(b"Im1")
        .restore()
        .begin_text()
        .font(b"F1", 12.0)
        .fill_gray(0.0)
        .move_text(2.0, 49.384)
        .show(b"Digitally signed by (A) \\ B")
        .move_text(0.0, -14.4)
        .show(b"Date: 2026-10-11 \x85 \xE9")
        .text_matrix([1.0, 0.0, 0.0, 1.0, 5.0, 5.0])
        .end_text()
        .restore();
    let content = b.finish().unwrap();
    let expected: &[u8] = b"q\n\
        1 0 0 1 10.5 -20.25 cm\n\
        0.75 w\n\
        0 G\n\
        1 g\n\
        1 0.5 0 rg\n\
        0.2 0.4 0.6 RG\n\
        0.5 0.5 199 59 re\n\
        S\n\
        2 2 10 10 re\n\
        f\n\
        0 0 m\n\
        0.3333333333 0.6666666667 l\n\
        h\n\
        S\n\
        0 0 200 60 re\n\
        W\n\
        n\n\
        n\n\
        q\n\
        48 0 0 32 2 14 cm\n\
        /Im1 Do\n\
        Q\n\
        BT\n\
        /F1 12 Tf\n\
        0 g\n\
        2 49.384 Td\n\
        (Digitally signed by \\(A\\) \\\\ B) Tj\n\
        0 -14.4 Td\n\
        (Date: 2026-10-11 \x85 \xE9) Tj\n\
        1 0 0 1 5 5 Tm\n\
        ET\n\
        Q\n";
    assert_eq!(content, expected, "\n{}", String::from_utf8_lossy(&content));

    // The M1 lexer reads the stream back as the operands and operators that were built.
    let mut tokens = Vec::new();
    tokens.extend(op(&[], "q"));
    tokens.extend(op(&[1.0, 0.0, 0.0, 1.0, 10.5, -20.25], "cm"));
    tokens.extend(op(&[0.75], "w"));
    tokens.extend(op(&[0.0], "G"));
    tokens.extend(op(&[1.0], "g"));
    tokens.extend(op(&[1.0, 0.5, 0.0], "rg"));
    tokens.extend(op(&[0.2, 0.4, 0.6], "RG"));
    tokens.extend(op(&[0.5, 0.5, 199.0, 59.0], "re"));
    tokens.extend(op(&[], "S"));
    tokens.extend(op(&[2.0, 2.0, 10.0, 10.0], "re"));
    tokens.extend(op(&[], "f"));
    tokens.extend(op(&[0.0, 0.0], "m"));
    tokens.extend(op(&[third, 2.0 * third], "l"));
    tokens.extend(op(&[], "h"));
    tokens.extend(op(&[], "S"));
    tokens.extend(op(&[0.0, 0.0, 200.0, 60.0], "re"));
    tokens.extend(op(&[], "W"));
    tokens.extend(op(&[], "n"));
    tokens.extend(op(&[], "n"));
    tokens.extend(op(&[], "q"));
    tokens.extend(op(&[48.0, 0.0, 0.0, 32.0, 2.0, 14.0], "cm"));
    tokens.push(Tok::Name(b"Im1".to_vec()));
    tokens.extend(op(&[], "Do"));
    tokens.extend(op(&[], "Q"));
    tokens.extend(op(&[], "BT"));
    tokens.push(Tok::Name(b"F1".to_vec()));
    tokens.extend(op(&[12.0], "Tf"));
    tokens.extend(op(&[0.0], "g"));
    tokens.extend(op(&[2.0, 49.384], "Td"));
    tokens.push(Tok::Str(b"Digitally signed by (A) \\ B".to_vec()));
    tokens.extend(op(&[], "Tj"));
    tokens.extend(op(&[0.0, -14.4], "Td"));
    tokens.push(Tok::Str(b"Date: 2026-10-11 \x85 \xE9".to_vec()));
    tokens.extend(op(&[], "Tj"));
    tokens.extend(op(&[1.0, 0.0, 0.0, 1.0, 5.0, 5.0], "Tm"));
    tokens.extend(op(&[], "ET"));
    tokens.extend(op(&[], "Q"));
    assert_eq!(lex(&content), tokens);
}

/// The layout of a signature appearance (brief §4.7 "Operators"): every value reads back as
/// the serializer's canonical real, and the WinAnsi bytes come back unchanged.
#[test]
fn content_builder_appearance_sequence_reads_back() {
    let (w, h, bw, s) = (200.0, 60.0, 1.0, 7.5);
    let y0 = h - 2.0 - s * 718.0 / 1000.0;
    let lines: [&[u8]; 3] = [
        b"Digitally signed by Zo\xEB (test)",
        b"Date: 2026-10-11 12:00:30 +02:00",
        b"Reason: \x93approved\x94 \\ \r\n",
    ];
    let mut b = ContentBuilder::new();
    b.save()
        .line_width(bw)
        .stroke_gray(0.0)
        .rect(bw / 2.0, bw / 2.0, w - bw, h - bw)
        .stroke()
        .save()
        .concat([40.0, 0.0, 0.0, 26.666666666666668, 3.0, 16.666666666666664])
        .draw_xobject(b"Im1")
        .restore()
        .begin_text()
        .font(b"F1", s)
        .fill_gray(0.0)
        .move_text(46.0, y0);
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            b.move_text(0.0, -1.2 * s);
        }
        b.show(line);
    }
    b.end_text().restore();
    let content = b.finish().unwrap();
    let tokens = lex(&content);
    let strings: Vec<&[u8]> = tokens
        .iter()
        .filter_map(|t| match t {
            Tok::Str(s) => Some(s.as_slice()),
            _ => None,
        })
        .collect();
    assert_eq!(strings, lines);
    let numbers: Vec<f64> = tokens
        .iter()
        .filter_map(|t| match t {
            Tok::Num(n) => Some(*n),
            _ => None,
        })
        .collect();
    let expected: Vec<f64> = [
        vec![bw, 0.0, bw / 2.0, bw / 2.0, w - bw, h - bw],
        vec![40.0, 0.0, 0.0, 26.666666666666668, 3.0, 16.666666666666664],
        vec![s, 0.0, 46.0, y0, 0.0, -1.2 * s, 0.0, -1.2 * s],
    ]
    .concat()
    .into_iter()
    .map(canonical_real)
    .collect();
    assert_eq!(numbers, expected);
    let text = String::from_utf8_lossy(&content);
    assert!(
        text.contains(" 0 0 26.6666666667 3 16.6666666667 cm\n"),
        "{text}"
    );
    assert!(text.contains("\n46 52.615 Td\n"), "{text}");
    assert!(text.contains("\n0 -9 Td\n"), "{text}");
}

#[test]
fn content_builder_rejects_non_finite() {
    type Call = fn(&mut ContentBuilder, f64, usize);
    // Each operator with numeric operands, with the operand at `position` set to the value.
    let operators: &[(&str, usize, Call)] = &[
        ("cm", 6, |b, v, p| {
            let mut m = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];
            m[p] = v;
            b.concat(m);
        }),
        ("Tm", 6, |b, v, p| {
            let mut m = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];
            m[p] = v;
            b.text_matrix(m);
        }),
        ("re", 4, |b, v, p| {
            let mut r = [0.0, 0.0, 1.0, 1.0];
            r[p] = v;
            b.rect(r[0], r[1], r[2], r[3]);
        }),
        ("rg", 3, |b, v, p| {
            let mut c = [0.0; 3];
            c[p] = v;
            b.fill_rgb(c[0], c[1], c[2]);
        }),
        ("RG", 3, |b, v, p| {
            let mut c = [0.0; 3];
            c[p] = v;
            b.stroke_rgb(c[0], c[1], c[2]);
        }),
        ("Td", 2, |b, v, p| {
            let mut t = [0.0; 2];
            t[p] = v;
            b.move_text(t[0], t[1]);
        }),
        ("m", 2, |b, v, p| {
            let mut t = [0.0; 2];
            t[p] = v;
            b.move_to(t[0], t[1]);
        }),
        ("l", 2, |b, v, p| {
            let mut t = [0.0; 2];
            t[p] = v;
            b.line_to(t[0], t[1]);
        }),
        ("w", 1, |b, v, _| {
            b.line_width(v);
        }),
        ("g", 1, |b, v, _| {
            b.fill_gray(v);
        }),
        ("G", 1, |b, v, _| {
            b.stroke_gray(v);
        }),
        ("Tf", 1, |b, v, _| {
            b.font(b"F1", v);
        }),
    ];
    let bad = [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        MAX_REAL * 1.0001,
        -1e300,
    ];
    for &(name, arity, call) in operators {
        for position in 0..arity {
            for value in bad {
                let mut b = ContentBuilder::new();
                b.save();
                call(&mut b, value, position);
                // Later valid operators do not clear the error.
                b.restore().fill_gray(0.5);
                let err = b.finish().unwrap_err();
                assert_eq!(err.code(), ErrorCode::InvalidArgument, "{name} {value}");
                let message = err.to_string();
                assert!(
                    message.contains(&format!(
                        "operand {} of the content operator `{name}`",
                        position + 1
                    )),
                    "{message}"
                );
            }
            // The largest real PDF readers must accept is still fine.
            let mut b = ContentBuilder::new();
            call(&mut b, -MAX_REAL, position);
            assert!(b.finish().is_ok(), "{name} -MAX_REAL");
        }
    }

    // Only the first error is reported.
    let mut b = ContentBuilder::new();
    b.line_width(f64::NAN).move_text(f64::INFINITY, 0.0);
    let message = b.finish().unwrap_err().to_string();
    assert!(message.contains("`w`"), "{message}");
}
