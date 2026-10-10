//! # folioxide-sign: layer L5, digital signatures
//!
//! PDF signing and verification (ISO 32000-2 §12.8, ETSI EN 319 142-1 PAdES):
//!
//! - key loading from PKCS#12 and PEM, and a pluggable `Signer` trait
//! - CMS `SignedData` assembly with the PAdES signed attributes (RFC 5652, RFC 5035)
//! - RFC 3161 timestamps through a pluggable timestamper, with no network I/O in the core
//! - signature fields, the `/ByteRange` placeholder, one-step `sign` and the two-phase
//!   `prepare`/`finish` flow for external (HSM/KMS) signers
//! - certification signatures (DocMDP), verification and modification analysis
//!
//! RustCrypto types never appear in the public API: signatures take and return DER bytes and
//! Folioxide's own enums, because several RustCrypto crates are pre-releases
//! (`docs/ARCHITECTURE.md` §A.5).
//!
//! Dependency direction: `folioxide-model + folioxide-content ← folioxide-sign`.
//!
//! **Status:** scaffolding only (M0). The crate already depends on the pinned RustCrypto stack
//! (`rsa`, `cms`, `p12-keystore`, `x509-cert`, `der`) to prove that the graph resolves to a single
//! `cms` version. Signing lands in M3.
