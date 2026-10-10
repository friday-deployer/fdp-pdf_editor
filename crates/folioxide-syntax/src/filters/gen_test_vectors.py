#!/usr/bin/env python3
"""Generates `test_vectors.rs` (filter test vectors) next to this file.

Run from the repository root with the oracle venv (pikepdf drives qpdf's decoders):

    .venv/bin/python -I crates/folioxide-syntax/src/filters/gen_test_vectors.py \
        > crates/folioxide-syntax/src/filters/test_vectors.rs

Every vector is checked against a decoder that is independent of Folioxide before it is
written, and every expected output is that decoder's output:

- Flate: Python's `zlib` module (the zlib C library) encodes; zlib's own streaming decoder gives
  the expected partial length for the truncated case.
- LZW, RunLength, PNG and TIFF predictors: our encoders below produce the data, qpdf (through
  pikepdf `Stream.read_bytes`) decodes it, and the qpdf output is what the Rust tests expect.
- ASCII85: Python's `base64.a85encode`.

The plain inputs come from a 32-bit LCG and a text template that the Rust side regenerates
(`lcg_bytes` in `tests.rs`, `flate_text` below), so only encoded bytes are embedded.
"""

import base64
import sys
import zlib

import pikepdf
from pikepdf import Dictionary, Name, StreamDecodeLevel


def lcg_bytes(seed, n, alphabet=256):
    x = seed & 0xFFFFFFFF
    out = bytearray()
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        out.append((x >> 16) % alphabet)
    return bytes(out)


def flate_text():
    return "".join(
        f"BT /F1 {8 + i % 5} Tf 72 {720 - 12 * i} Td (Line {i} of the test text) Tj ET\n"
        for i in range(300)
    ).encode()


def qpdf_decode(data, filt, parms=None, level=StreamDecodeLevel.generalized):
    pdf = pikepdf.new()
    stream = pikepdf.Stream(pdf, b"")
    stream.write(data, filter=filt, decode_parms=parms)
    return stream.read_bytes(decode_level=level)


# --- LZW (ISO 32000-2 §7.4.4.2), MSB-first codes, clear first, clear when the table is full ---


def lzw_width(next_entry, early):
    n = next_entry + early
    return 9 if n < 512 else 10 if n < 1024 else 11 if n < 2048 else 12


def lzw_encode(data, early):
    bits = []

    def emit(code, emitted):
        # The decoder lags one code behind: reading code k it holds k - 2 entries.
        width = lzw_width(258 + max(emitted - 1, 0), early)
        bits.append(format(code, f"0{width}b"))

    table = {bytes([i]): i for i in range(256)}
    emitted = 0
    emit(256, emitted)
    word = b""
    for byte in data:
        ext = word + bytes([byte])
        if len(ext) == 1 or ext in table:
            word = ext
            continue
        emit(table[word], emitted)
        emitted += 1
        entry = 258 + emitted - 1
        table[ext] = entry
        if entry == 4095:
            emit(256, emitted)
            table = {bytes([i]): i for i in range(256)}
            emitted = 0
        word = bytes([byte])
    if word:
        emit(table[word], emitted)
        emitted += 1
    emit(257, emitted)
    s = "".join(bits)
    s += "0" * (-len(s) % 8)
    return bytes(int(s[i : i + 8], 2) for i in range(0, len(s), 8))


# --- Predictors (§7.4.4.4) ---


def png_paeth(a, b, c):
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def png_encode(original, row_len, bpp, tags):
    out = bytearray()
    prev = bytes(row_len)
    for r, tag in enumerate(tags):
        row = original[r * row_len : (r + 1) * row_len]
        out.append(tag)
        for j, x in enumerate(row):
            a = row[j - bpp] if j >= bpp else 0
            b = prev[j]
            c = prev[j - bpp] if j >= bpp else 0
            pred = [0, a, b, (a + b) // 2, png_paeth(a, b, c)][tag]
            out.append((x - pred) & 0xFF)
        prev = row
    return bytes(out)


def pack_samples(samples, bpc):
    if bpc == 16:
        return b"".join(s.to_bytes(2, "big") for s in samples)
    if bpc == 8:
        return bytes(samples)
    s = "".join(format(v, f"0{bpc}b") for v in samples)
    s += "0" * (-len(s) % 8)
    return bytes(int(s[i : i + 8], 2) for i in range(0, len(s), 8))


def tiff_encode(rows, colors, bpc):
    out = b""
    for samples in rows:
        diffs = [
            (v - samples[i - colors]) % (1 << bpc) if i >= colors else v
            for i, v in enumerate(samples)
        ]
        out += pack_samples(diffs, bpc)
    return out


# --- Rust output helpers ---


def rust_hex(name, data, doc):
    h = data.hex()
    lines = [h[i : i + 92] for i in range(0, len(h), 92)] or [""]
    body = "\\\n    ".join(lines)
    return f"/// {doc}\npub(super) const {name}: &str = \"\\\n    {body}\";\n"


def rust_bytes(data):
    return 'b"' + "".join(chr(b) if 0x20 <= b < 0x7F and b not in b'"\\' else f"\\x{b:02X}" for b in data) + '"'


def main():
    out = []
    w = out.append
    w("//! Filter test vectors. **Generated** by `gen_test_vectors.py` in this directory; do not edit.\n")
    w("//!\n")
    w("//! Each encoded vector was checked against a decoder independent of Folioxide (zlib, qpdf or\n")
    w("//! Python's `base64`), and each expected output is that decoder's output; see the generator.\n")
    w("//! Hex strings are decoded by `tests::hex`.\n\n")
    w("use super::tests::lcg_bytes;\n\n")

    # Flate.
    text = flate_text()
    z = zlib.compress(text, 9)
    assert zlib.decompress(z) == text
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    raw = co.compress(text) + co.flush()
    assert zlib.decompress(raw, -15) == text
    cut = len(z) // 2
    partial = zlib.decompressobj().decompress(z[:cut])
    assert text.startswith(partial) and len(partial) > 0
    flush_point = 5000
    co = zlib.compressobj(6)
    flushed = co.compress(text[:flush_point]) + co.flush(zlib.Z_FULL_FLUSH)
    assert zlib.decompressobj().decompress(flushed) == text[:flush_point]
    corrupt = flushed + b"\xff\xff\xff"
    try:
        zlib.decompress(corrupt)
        raise AssertionError("corrupt flate vector decoded")
    except zlib.error as e:
        assert "invalid block type" in str(e), e
    w(
        "/// The plain text behind the Flate vectors (300 content-stream-like lines).\n"
        "pub(super) fn flate_text() -> Vec<u8> {\n"
        "    (0..300i64)\n"
        "        .map(|i| {\n"
        "            format!(\n"
        '                "BT /F1 {} Tf 72 {} Td (Line {} of the test text) Tj ET\\n",\n'
        "                8 + i % 5,\n"
        "                720 - 12 * i,\n"
        "                i\n"
        "            )\n"
        "        })\n"
        "        .collect::<String>()\n"
        "        .into_bytes()\n"
        "}\n\n"
    )
    w(rust_hex("FLATE_TEXT_ZLIB", z, "`zlib.compress(flate_text(), 9)`."))
    w(rust_hex("FLATE_RAW_DEFLATE", raw, "`flate_text()` as raw deflate data (no zlib header), by zlib."))
    w(f"/// `FLATE_TEXT_ZLIB` cut to this many bytes is the truncated case.\n")
    w(f"pub(super) const FLATE_TEXT_TRUNCATED_AT: usize = {cut};\n")
    w(f"/// What zlib's streaming decoder recovers from that prefix.\n")
    w(f"pub(super) const FLATE_TEXT_TRUNCATED_ZLIB_LEN: usize = {len(partial)};\n")
    w(f"/// Bytes of `flate_text()` before the full flush in `FLATE_FLUSHED_THEN_CORRUPT`.\n")
    w(f"pub(super) const FLATE_FLUSH_POINT: usize = {flush_point};\n")
    w(
        rust_hex(
            "FLATE_FLUSHED_THEN_CORRUPT",
            corrupt,
            "zlib stream of the first `FLATE_FLUSH_POINT` bytes, `Z_FULL_FLUSH`, then `FF FF FF` (a\n"
            "/// final block of the reserved type 3, which zlib rejects with \"invalid block type\").",
        )
    )
    w("\n")

    # LZW.
    spec = lzw_encode(b"-----A---B", 1)
    assert spec == bytes.fromhex("800b6050220c0c8501"), spec.hex()
    lzw_cases = [
        ("LZW_EC1", 1, 7, 10000, 16, "lzw_ec1_data"),
        ("LZW_EC0", 0, 8, 2000, 16, "lzw_ec0_data"),
    ]
    for name, early, seed, n, alphabet, fn in lzw_cases:
        data = lcg_bytes(seed, n, alphabet)
        enc = lzw_encode(data, early)
        dec = qpdf_decode(enc, Name.LZWDecode, Dictionary(EarlyChange=early))
        assert dec == data, name
        # The other EarlyChange setting must not decode it (qpdf errors or differs).
        try:
            other = qpdf_decode(enc, Name.LZWDecode, Dictionary(EarlyChange=1 - early))
            assert other != data
        except (pikepdf.PdfError, RuntimeError):
            pass
        w(
            f"/// The plain data behind `{name}`.\n"
            f"pub(super) fn {fn}() -> Vec<u8> {{\n"
            f"    lcg_bytes({seed}, {n}, {alphabet})\n"
            f"}}\n"
        )
        w(rust_hex(name, enc, f"`{fn}()` LZW-encoded with `/EarlyChange {early}`; qpdf decodes it."))
    w("\n")

    # RunLength.
    rl = (
        bytes([0]) + b"a"
        + bytes([4]) + b"hello"
        + bytes([257 - 2]) + b"x"
        + bytes([127]) + lcg_bytes(3, 128)
        + bytes([257 - 128, 0x55])
        + bytes([257 - 100, 0xAA])
        + bytes([2]) + b"end"
        + bytes([128])
    )
    rl_dec = qpdf_decode(rl, Name.RunLengthDecode, level=StreamDecodeLevel.specialized)
    assert rl_dec == b"ahelloxx" + lcg_bytes(3, 128) + b"\x55" * 128 + b"\xaa" * 100 + b"end"
    w(rust_hex("RUN_LENGTH_ENCODED", rl, "RunLength data with literal and repeat runs of every size class."))
    w(rust_hex("RUN_LENGTH_QPDF", rl_dec, "qpdf's decoding of `RUN_LENGTH_ENCODED`."))
    w("\n")

    # Predictors.
    w(
        "/// A predictor test case: `encoded` is predicted (not compressed) data, `expected` is what\n"
        "/// qpdf decodes it to.\n"
        "pub(super) struct PredictorVector {\n"
        "    pub colors: u8,\n"
        "    pub bits_per_component: u8,\n"
        "    pub columns: u32,\n"
        "    pub encoded: &'static str,\n"
        "    pub expected: &'static str,\n"
        "}\n\n"
    )
    hand = bytes([0, 10, 20, 30, 1, 1, 2, 3, 2, 5, 5, 250, 3, 4, 4, 4, 4, 1, 1, 1])
    assert qpdf_decode(
        zlib.compress(hand), Name.FlateDecode, Dictionary(Predictor=12, Colors=1, BitsPerComponent=8, Columns=3)
    ) == bytes([10, 20, 30, 1, 3, 6, 6, 8, 0, 7, 11, 9, 8, 12, 10])

    png_configs = [(1, 8, 7), (3, 8, 5), (2, 8, 4), (1, 1, 13), (2, 4, 5), (3, 16, 3), (4, 16, 2), (4, 8, 3)]
    vectors = []
    for k, (colors, bpc, columns) in enumerate(png_configs):
        row_len = (colors * bpc * columns + 7) // 8
        bpp = max(1, (colors * bpc + 7) // 8)
        rows = 10
        tags = [(r * 3 + k) % 5 for r in range(rows)]
        original = lcg_bytes(100 + k, rows * row_len)
        enc = png_encode(original, row_len, bpp, tags)
        dec = qpdf_decode(
            zlib.compress(enc),
            Name.FlateDecode,
            Dictionary(Predictor=15, Colors=colors, BitsPerComponent=bpc, Columns=columns),
        )
        assert dec == original, (colors, bpc, columns)
        vectors.append((colors, bpc, columns, enc, dec))
    emit_vectors(w, "PNG_VECTORS", "PNG predictor vectors (tags 0–4 in every row position).", vectors)

    tiff_configs = [(1, 1, 21), (2, 2, 7), (3, 4, 5), (3, 8, 6), (2, 16, 4), (4, 8, 2), (1, 16, 5)]
    vectors = []
    for k, (colors, bpc, columns) in enumerate(tiff_configs):
        rows = [list(lcg_bytes(200 + 10 * k + r, colors * columns, 1 << min(bpc, 8))) for r in range(4)]
        if bpc == 16:
            rows = [
                [((v << 8) | ((v * 37 + i) & 0xFF)) for i, v in enumerate(row)]
                for row in rows
            ]
        original = b"".join(pack_samples(row, bpc) for row in rows)
        enc = tiff_encode(rows, colors, bpc)
        dec = qpdf_decode(
            zlib.compress(enc),
            Name.FlateDecode,
            Dictionary(Predictor=2, Colors=colors, BitsPerComponent=bpc, Columns=columns),
        )
        assert dec == original, (colors, bpc, columns)
        vectors.append((colors, bpc, columns, enc, dec))
    emit_vectors(w, "TIFF_VECTORS", "TIFF predictor 2 vectors for 1, 2, 4, 8 and 16 bits per component.", vectors)

    # ASCII85.
    inputs = [
        b"",
        b"\x00",
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x00\x00",
        b"\x00\x00\x00\x00abc\x00\x00\x00\x00\x00\x00\x00\x00",
        b"M",
        b"Ma",
        b"Man",
        b"Man is distinguished",
        b"\xff",
        b"\xff\xff\xff\xff",
        lcg_bytes(5, 31),
        bytes(range(256)),
    ]
    w("/// `(input, base64.a85encode(input) + b\"~>\")` pairs from Python.\n")
    w("pub(super) const ASCII85_PYTHON: &[(&[u8], &[u8])] = &[\n")
    for data in inputs:
        enc = base64.a85encode(data) + b"~>"
        assert base64.a85decode(enc[:-2]) == data
        w(f"    (\n        {rust_bytes(data)},\n        {rust_bytes(enc)},\n    ),\n")
    w("];\n")

    sys.stdout.write("".join(out))


def emit_vectors(w, name, doc, vectors):
    w(f"/// {doc}\n")
    w(f"pub(super) const {name}: &[PredictorVector] = &[\n")
    for colors, bpc, columns, enc, dec in vectors:
        w("    PredictorVector {\n")
        w(f"        colors: {colors},\n")
        w(f"        bits_per_component: {bpc},\n")
        w(f"        columns: {columns},\n")
        w(f'        encoded: "{enc.hex()}",\n')
        w(f'        expected: "{dec.hex()}",\n')
        w("    },\n")
    w("];\n\n")


if __name__ == "__main__":
    main()
