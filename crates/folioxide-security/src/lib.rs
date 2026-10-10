//! # folioxide-security: layer L2, the standard security handler
//!
//! Implements PDF encryption as specified in ISO 32000-2 §7.6:
//!
//! - the standard security handler, revisions R2 to R4 (RC4-40/128, AES-128) and R6 (AES-256),
//!   with R5 supported read-only
//! - crypt filters (`/Identity`, `/StdCF`, `/V2`, `/AESV2`, `/AESV3`) and `EncryptMetadata`
//! - user and owner passwords, permissions (`/P`), changing and removing passwords
//!
//! It plugs into the syntax layer through the `Decryptor` trait of `folioxide-syntax`, so
//! decryption always happens on copies and the source bytes stay ciphertext.
//! Dependency direction: `folioxide-syntax ← folioxide-security`.
//!
//! **Status:** scaffolding only (M0). The implementation lands in M5.
