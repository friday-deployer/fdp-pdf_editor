//! Fixture generators, grouped by the layer they test.
//!
//! [`syntax`] and the [`hostile::seeds`] are committed under `fixtures/syntax/` and
//! `fixtures/hostile/` with `cargo xtask fixtures`, which writes the files byte for byte as
//! generated; `cargo xtask fixtures --check` fails when the committed files differ. Large
//! fixtures (such as [`syntax::lazy_pages`]) and the scaled-up resource-exhaustion files of
//! [`hostile`] are generated at test time and never committed. [`qpdf`] reads the files that
//! qpdf writes into `fixtures/qpdf/` (`tools/fixtures/qpdf.py`).

pub mod hostile;
pub mod qpdf;
pub mod syntax;
// M2 WP2.2: document-model fixtures, generated at test time.
pub mod model;
// M3 WP3.1A-pre: byte-level generators for the signed-PDF attack corpus (brief §5.1).
pub mod sign_attacks;
// M4 WP4.1A: AcroForm documents and form-filling and annotating updates (M4 brief §3.4).
pub mod forms;

use std::path::{Path, PathBuf};

/// The workspace root, derived from this crate's location (`<workspace>/crates/folioxide-testkit`).
pub fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    // Two levels up is the workspace root. Lexical, so the result has no `..` components.
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(manifest_dir)
        .to_path_buf()
}

/// The committed fixtures directory, `<workspace>/fixtures`.
pub fn fixtures_dir() -> PathBuf {
    workspace_root().join("fixtures")
}

/// A deterministic 16-byte file identifier derived from `seed` (two FNV-1a 64-bit hashes), for
/// the trailer `/ID` of generated files (ISO 32000-2 §14.4). Generated files must be
/// reproducible, so they never use random or time-based identifiers.
pub fn file_id(seed: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let (first, second) = out.split_at_mut(8);
    first.copy_from_slice(&fnv1a64(seed.as_bytes(), 0xcbf2_9ce4_8422_2325).to_be_bytes());
    second.copy_from_slice(&fnv1a64(seed.as_bytes(), 0x6c62_272e_07bb_0142).to_be_bytes());
    out
}

/// The `/ID` array text `[<id> <id>]` for [`file_id`]`(seed)`: both elements equal, as for a
/// file that has never been updated.
///
/// ```
/// let id = folioxide_testkit::fixtures::id_array("minimal");
/// assert!(id.starts_with("[<") && id.ends_with(">]"));
/// assert_eq!(id.len(), 2 * 34 + 3);
/// ```
pub fn id_array(seed: &str) -> String {
    let hex = hex_upper(&file_id(seed));
    format!("[<{hex}> <{hex}>]")
}

/// The `/ID` array text for an updated file: the original first element, and a second element
/// derived from `update_seed` (§14.4: the second element changes with each revision).
pub fn id_array_updated(seed: &str, update_seed: &str) -> String {
    format!(
        "[<{}> <{}>]",
        hex_upper(&file_id(seed)),
        hex_upper(&file_id(update_seed))
    )
}

/// Upper-case hexadecimal digits for `bytes`.
pub fn hex_upper(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        for nibble in [b >> 4, b & 0x0F] {
            out.push(char::from(
                DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    out
}

fn fnv1a64(data: &[u8], basis: u64) -> u64 {
    data.iter().fold(basis, |hash, &b| {
        (hash ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_deterministic_and_distinct() {
        assert_eq!(file_id("a"), file_id("a"));
        assert_ne!(file_id("a"), file_id("b"));
        // FNV-1a 64 of "a" with the standard offset basis.
        assert_eq!(&file_id("a")[..8], &0xaf63_dc4c_8601_ec8c_u64.to_be_bytes());
        let updated = id_array_updated("a", "b");
        assert!(updated.starts_with(&id_array("a")[..34]));
        assert_ne!(updated, id_array("a"));
    }

    #[test]
    fn hex() {
        assert_eq!(hex_upper(&[0x00, 0xAB, 0x5f]), "00AB5F");
    }

    #[test]
    fn committed_file_names_are_distinct() {
        // The fuzz workflow copies every committed PDF into one corpus directory.
        let mut names = std::collections::BTreeSet::new();
        let all = syntax::infos()
            .iter()
            .map(|i| i.name)
            .chain(qpdf::infos().iter().map(|i| i.name))
            .chain(hostile::seed_infos().iter().map(|i| i.name));
        for name in all {
            assert!(names.insert(name), "{name} is used twice");
        }
    }

    #[test]
    fn dirs() {
        assert!(workspace_root().join("Cargo.toml").is_file());
        assert!(fixtures_dir().join("README.md").is_file());
    }
}
