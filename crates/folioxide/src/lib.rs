//! # folioxide: a pure-Rust PDF editing engine
//!
//! This is the facade crate and the only crate with a semver promise. Applications (the Node
//! addon, and later a Tauri app) depend on it alone. It re-exports the public API of the layered
//! `folioxide-*` crates, owns the unified `Error`, the serde DTOs and the `std::fs` helpers, and
//! selects functionality through feature flags:
//!
//! | Feature | Default | Enables |
//! |---|---|---|
//! | `encryption` | yes | open and save encrypted documents (`folioxide-security`) |
//! | `signatures` | yes | digital signatures (`folioxide-sign`, RustCrypto) |
//! | `pkcs12-legacy` | yes | RC2-40 and 3DES PKCS#12 files |
//! | `fonts` | yes | TrueType/OpenType embedding and subsetting |
//! | `images` | yes | PNG decoding (JPEG passthrough is always on) |
//! | `interactive` | yes | annotations and forms (`folioxide-interactive`) |
//! | `jpeg-decode` | no | JPEG pixel decoding |
//! | `shaping` | no | complex-script shaping and bidi |
//! | `redact` | no | true redaction (`folioxide-redact`) |
//! | `render` | no | page rendering (`folioxide-render`) |
//! | `serde` | no | `Serialize`/`Deserialize` on all DTOs |
//! | `std-fs` | no | path helpers, `SystemClock`, optional mmap |
//!
//! No feature adds threads or network I/O.
//!
//! **Status:** pre-alpha. M0 provides the crate layout only; see `docs/ROADMAP.md`.

/// The version of the `folioxide` crate, for example `"0.1.0"`.
///
/// The Node package exposes the same value as `version()`, which lets callers check that the
/// JavaScript wrapper and the native addon come from the same release.
///
/// ```
/// assert_eq!(folioxide::VERSION.split('.').count(), 3);
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_semver_core() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "VERSION {VERSION:?} is not MAJOR.MINOR.PATCH"
        );
        for part in parts {
            assert!(
                !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()),
                "VERSION {VERSION:?} has a non-numeric component"
            );
        }
    }
}
