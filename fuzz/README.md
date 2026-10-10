# Fuzz targets

cargo-fuzz targets for Folioxide (ARCHITECTURE §A.9, layer 4). This crate is outside the
workspace and needs the nightly toolchain and `cargo install cargo-fuzz`. CI fuzzes every
`[[bin]]` of `Cargo.toml` nightly (`.github/workflows/fuzz-nightly.yml`).

| Target | What it exercises | Input |
|---|---|---|
| `fuzz_lexer` | `Lexer`, `parse_object`, `parse_indirect_header`, `parse_indirect_at`; serialize → parse round trip of every parsed object | byte 0: bit 0 strict, bit 1 tiny limits, bits 2–7 start offset; the rest is PDF text |
| `fuzz_filters` | `decode` and `decode_chain` for every `Filter::ALL` (predictors included), `decode` ≡ one-filter chain, passthrough handling, chains of up to 5 filters, encoder round trips | bytes 0–5: predictor, colors, bits per component, columns, early change and the chain; the rest is encoded data |
| `fuzz_parse_document` | `Store::open`, then `resolve` of every object (twice: cached), `deref` of every reference, `raw_stream_data` and `stream_data` of every stream, and a page-tree walk; in lenient and strict mode with smaller decoding limits (8 MiB per stream, 32 MiB per document), and in tiny-limits mode. Asserts the store's documented guarantees (`folioxide_testkit::exercise`) and a per-input time budget | the whole input is the PDF file |
| `fuzz_parse_document_default_limits` | the same read path with `Limits::default()` as shipped (512 MiB per stream, 4 GiB per document), lenient and strict, so amplification that only the default limits allow is reachable. Asserts the same guarantees and the per-input time budget; libFuzzer's 2 GB RSS limit applies | the whole input is the PDF file |

### Time and memory budgets

A hostile input that makes the reader do far more work than its size justifies is a bug even
when nothing panics. Both document targets therefore judge every input by
`folioxide_testkit::budget::WorkBudget::FUZZ`: 2 s, plus 300 ns per input byte, 40 µs per object
resolved or reference followed, and 20 ns per byte the store decoded (about four times what
reading costs in the sanitizer build). An input over its allowance fails an assertion, so
libFuzzer saves it as a crash. An input still running after a hard limit (60 s for
`fuzz_parse_document`, 300 s for `fuzz_parse_document_default_limits`) is aborted by
`folioxide_testkit::budget::Watchdog`, which libFuzzer also saves as a crash; its own `-timeout`
(20 minutes by default) is only a backstop. libFuzzer's `-rss_limit_mb` (2048 by default) is the
memory budget: an input that makes the store hold more is reported as out-of-memory.

## Running

From the repository root:

```sh
cargo +nightly fuzz build                                   # all targets
cargo +nightly fuzz run fuzz_lexer -- -max_total_time=60    # one target for 60 s
cargo +nightly fuzz run fuzz_lexer fuzz/artifacts/fuzz_lexer/crash-<hash>   # reproduce
```

Corpora (`fuzz/corpus/`) and crash artifacts (`fuzz/artifacts/`) are never committed. A useful
seed corpus is every committed PDF under `fixtures/` (both document targets take them as they
are), which is what the nightly workflow uses:

- `fixtures/syntax/`: healthy files of every cross-reference kind and the broken repair cases;
- `fixtures/qpdf/`: linearized files written by qpdf (tables, and object streams);
- `fixtures/hostile/`: small instances of the resource-exhaustion shapes
  (`folioxide_testkit::fixtures::hostile::seeds`: `/Prev` chains of cross-reference streams,
  overlapping sections, outsized `/Index` arrays, object-stream bombs, object-stream headers
  with thousands of members, an object stream holding one huge array, unterminated trailers),
  written by `cargo xtask fixtures`. Mutations around them are where amplification bugs hide;
  the `no_panic_on_mutated_input` test already mutates them, and the scaled-up versions are
  tested at the default limits in `crates/folioxide-syntax/tests/hostile_default_limits.rs`.

```sh
for target in fuzz_parse_document fuzz_parse_document_default_limits; do
  mkdir -p "fuzz/corpus/$target"
  find fixtures -type f -name '*.pdf' -size -1024k -exec cp {} "fuzz/corpus/$target/" \;
done
```

The seed file names are distinct across those directories (the hostile ones start with
`hostile-`), so they can share one corpus directory.

Every crash is a bug: the targets only assert properties that the library documents (no panic,
bounded output, consistent results, lossless round trips).
