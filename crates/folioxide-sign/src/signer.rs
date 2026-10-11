//! The [`Signer`] trait and [`LocalSigner`], the signer for local keys (M3 brief §3.1).
//!
//! A [`Signer`] produces the raw signature value over the DER signed attributes; the CMS
//! around it is built by [`cms`](crate::cms). Local keys come from PKCS#12 or PEM files
//! ([`LocalSigner::from_pkcs12`], [`LocalSigner::from_pem`]). HSMs, cloud KMSes and WebCrypto
//! either implement [`Signer`] or use the two-phase `prepare`/`finish` flow.
//!
//! **RSA advisory (DECISIONS D5.4).** The `rsa` crate is affected by RUSTSEC-2023-0071 (the
//! "Marvin" timing side channel), for which no patched release exists. `LocalSigner` signs RSA
//! through the blinded path, but on servers where an attacker can time many signatures, prefer
//! ECDSA keys or the external (KMS/HSM) flow.

use std::fmt;
use std::sync::{Mutex, PoisonError};

use crate::algorithms::{DigestAlgorithm, KeyKind, SignatureAlgorithm};
use crate::error::{Error, Result};
use crate::keys::private::{PrivateKey, Rng};
use crate::keys::{self, pkcs12};
use crate::x509info::cert;

/// The RNG trait that [`LocalSigner::with_rng`] takes (`rand_core` 0.10): a cryptographically
/// secure, infallible random number generator.
pub use rand_core::CryptoRng;

/// Something that can sign: a local key, an HSM, a KMS, an OS keychain.
///
/// Implementations must be `Send + Sync`, so one signer can serve several threads.
pub trait Signer: Send + Sync {
    /// The DER certificates: the signer's certificate first, then the intermediates (the root
    /// is optional). They are embedded in the CMS byte for byte and never re-encoded.
    fn certificate_chain(&self) -> &[Vec<u8>];

    /// The signature algorithm family of the key.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// The kind and size of the key.
    fn key_kind(&self) -> KeyKind;

    /// Signs `to_be_signed`, hashing it with `digest`.
    ///
    /// For RSA the result is exactly the modulus length in bytes (RFC 8017 §8.2.1). For ECDSA
    /// it is either a DER `ECDSA-Sig-Value` or IEEE P1363 `r || s`; both are accepted
    /// downstream.
    fn sign(&self, digest: DigestAlgorithm, to_be_signed: &[u8]) -> Result<Vec<u8>>;
}

/// A [`Signer`] for a private key held in memory, loaded from PKCS#12, PEM or PKCS#8.
///
/// - The key must belong to the first certificate of the chain, else
///   [`Error::KeyLoad`]. RSA keys need 2048 to 8192 bits
///   ([`Error::KeyLoad`] otherwise); curves other than P-256 and P-384
///   give [`Error::Unsupported`].
/// - Decrypted key material is wiped from memory when it is dropped. (`p12-keystore` holds its
///   own, unwiped copy of a PKCS#12 key while [`LocalSigner::from_pkcs12`] runs; that copy is
///   dropped before it returns.)
/// - `Debug` prints only the key kind and the certificate subject, never key material.
/// - RSA signatures use the blinded `RandomizedSigner` path; the RNG is the operating
///   system's (feature `sys-rng`, on by default) unless [`LocalSigner::with_rng`] sets one.
///   PKCS#1 v1.5 is deterministic, so the RNG never changes the output. ECDSA signatures are
///   deterministic (RFC 6979) and use no RNG.
///
/// **RSA advisory (DECISIONS D5.4):** see the [module documentation](self). Prefer ECDSA keys
/// or the external flow for server-side signing.
pub struct LocalSigner {
    /// DER certificates, the signer's first.
    chain: Vec<Vec<u8>>,
    /// The key's kind and size.
    kind: KeyKind,
    /// The signer certificate's subject (RFC 4514), for `Debug`.
    subject: String,
    /// The private key; RustCrypto wipes it when dropped.
    key: PrivateKey,
    /// The RNG for RSA blinding set by [`LocalSigner::with_rng`]; `None` means the default.
    rng: Option<Mutex<Box<dyn CryptoRng + Send>>>,
}

impl LocalSigner {
    /// Loads the key and certificate chain from a PKCS#12 (`.p12`/`.pfx`) file.
    ///
    /// The MAC is verified before anything is decrypted. Modern PBES2/AES files always load;
    /// RC2-40 and 3DES files need the `pkcs12-legacy` feature.
    ///
    /// # Errors
    /// [`Error::WrongPassword`] for a wrong password,
    /// [`Error::Unsupported`] for an encryption or MAC scheme that is
    /// not available, [`Error::KeyLoad`] for anything else (no key, no
    /// certificate for the key, a corrupt file).
    pub fn from_pkcs12(p12_der: &[u8], password: &str) -> Result<LocalSigner> {
        let contents = pkcs12::load(p12_der, password)?;
        LocalSigner::from_pkcs8_der(&contents.key_pkcs8, contents.chain)
    }

    /// Loads the key from PEM and the certificates from one or more `BEGIN CERTIFICATE`
    /// blocks.
    ///
    /// Accepted keys: `BEGIN PRIVATE KEY` (PKCS#8), `BEGIN ENCRYPTED PRIVATE KEY` (PKCS#8
    /// PBES2, needs `key_password`), `BEGIN RSA PRIVATE KEY` (PKCS#1) and `BEGIN EC PRIVATE KEY`
    /// (SEC1). The certificate that matches the key is moved to the front of the chain; the
    /// others keep their order.
    ///
    /// # Errors
    /// [`Error::PasswordRequired`] for an encrypted key without
    /// a password, [`Error::WrongPassword`] when it does not
    /// decrypt, [`Error::Unsupported`] for legacy OpenSSL
    /// `Proc-Type: 4,ENCRYPTED` keys and unsupported key types and curves,
    /// [`Error::Certificate`] when `certs_pem` holds no certificate
    /// or one that does not parse, [`Error::KeyLoad`] for anything else
    /// (including no certificate matching the key).
    pub fn from_pem(
        key_pem: &str,
        certs_pem: &str,
        key_password: Option<&str>,
    ) -> Result<LocalSigner> {
        let key = keys::private_key_from_pem(key_pem, key_password)?;
        let mut certs = keys::certificates_from_pem(certs_pem)?;
        let position = certs
            .iter()
            .position(|der| {
                cert::CertParts::parse(der)
                    .and_then(|parts| parts.public_key())
                    .is_ok_and(|public| key.matches(&public))
            })
            .ok_or_else(|| {
                Error::KeyLoad(
                    "no certificate in the certificate PEM matches the private key".into(),
                )
            })?;
        let leaf = certs.remove(position);
        certs.insert(0, leaf);
        LocalSigner::from_key(key, certs)
    }

    /// Loads an unencrypted PKCS#8 DER private key with a DER certificate chain, the signer's
    /// certificate first.
    ///
    /// # Errors
    /// [`Error::KeyLoad`] when the key does not parse, has an RSA size
    /// outside 2048 to 8192 bits, or does not match `chain_der[0]` (or the chain is empty),
    /// [`Error::Certificate`] when `chain_der[0]` does not parse,
    /// [`Error::Unsupported`] for unsupported key types and curves.
    pub fn from_pkcs8_der(key_der: &[u8], chain_der: Vec<Vec<u8>>) -> Result<LocalSigner> {
        let key = PrivateKey::from_pkcs8_der(key_der)?;
        LocalSigner::from_key(key, chain_der)
    }

    /// Checks that `key` belongs to `chain[0]` and builds the signer.
    fn from_key(key: PrivateKey, chain: Vec<Vec<u8>>) -> Result<LocalSigner> {
        let leaf = chain
            .first()
            .ok_or_else(|| Error::KeyLoad("the certificate chain is empty".into()))?;
        let parts = cert::CertParts::parse(leaf)?;
        let matches = parts.public_key().is_ok_and(|public| key.matches(&public));
        if !matches {
            return Err(Error::KeyLoad(
                "the private key does not belong to the first certificate of the chain".into(),
            ));
        }
        let subject = cert::decode(leaf)?.tbs_certificate().subject().to_string();
        Ok(LocalSigner {
            kind: key.kind(),
            chain,
            subject,
            key,
            rng: None,
        })
    }

    /// Uses `rng` for RSA blinding instead of the default (the operating-system RNG with the
    /// `sys-rng` feature). ECDSA signing never uses it.
    ///
    /// PKCS#1 v1.5 signatures are deterministic, so the RNG never changes the output; it only
    /// randomizes the private-key operation against timing attacks (RFC 8017 §5.1.2 note).
    #[must_use]
    pub fn with_rng(mut self, rng: Box<dyn CryptoRng + Send>) -> Self {
        self.rng = Some(Mutex::new(rng));
        self
    }
}

impl Signer for LocalSigner {
    fn certificate_chain(&self) -> &[Vec<u8>] {
        &self.chain
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.kind.algorithm()
    }

    fn key_kind(&self) -> KeyKind {
        self.kind
    }

    /// Signs with the local key: RSA PKCS#1 v1.5 through the blinded path (exactly the modulus
    /// length), ECDSA with RFC 6979 nonces (a minimal DER `ECDSA-Sig-Value`).
    ///
    /// # Errors
    /// [`Error::InvalidArgument`] for SHA-1 (never used to sign)
    /// or, without the `sys-rng` feature, an RSA key with no [`LocalSigner::with_rng`];
    /// [`Error::Crypto`] when the RNG or the primitive fails.
    fn sign(&self, digest: DigestAlgorithm, to_be_signed: &[u8]) -> Result<Vec<u8>> {
        match &self.rng {
            Some(rng) => {
                // A poisoned lock only means another thread panicked mid-signature; the RNG
                // itself is still usable.
                let mut rng = rng.lock().unwrap_or_else(PoisonError::into_inner);
                self.key.sign(digest, to_be_signed, Rng::Custom(&mut **rng))
            }
            None => self.key.sign(digest, to_be_signed, default_rng()),
        }
    }
}

/// The RNG used when [`LocalSigner::with_rng`] was not called.
fn default_rng() -> Rng<'static> {
    #[cfg(feature = "sys-rng")]
    {
        Rng::System
    }
    #[cfg(not(feature = "sys-rng"))]
    {
        Rng::None
    }
}

impl fmt::Debug for LocalSigner {
    /// Prints the key kind and the certificate subject only.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalSigner")
            .field("kind", &self.kind)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An external signer, as an HSM or KMS adapter would implement it.
    struct External {
        chain: Vec<Vec<u8>>,
    }

    impl Signer for External {
        fn certificate_chain(&self) -> &[Vec<u8>] {
            &self.chain
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::Ecdsa
        }

        fn key_kind(&self) -> KeyKind {
            KeyKind::EcP256
        }

        fn sign(&self, digest: DigestAlgorithm, to_be_signed: &[u8]) -> Result<Vec<u8>> {
            // A stand-in "signature": the P1363-sized digest twice.
            let hash = digest.digest(&[to_be_signed]);
            Ok([hash.as_slice(), hash.as_slice()].concat())
        }
    }

    #[test]
    fn external_signers_are_object_safe_and_shareable_across_threads() {
        let signer: Box<dyn Signer> = Box::new(External {
            chain: vec![vec![0x30, 0x00]],
        });
        let signer = &*signer;
        let outputs: Vec<Vec<u8>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| scope.spawn(move || signer.sign(DigestAlgorithm::Sha256, b"tbs").unwrap()))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(outputs.iter().all(|o| o.len() == 64 && *o == outputs[0]));
        assert_eq!(signer.certificate_chain(), [vec![0x30, 0x00]]);
        assert_eq!(
            Some(signer.sign(DigestAlgorithm::Sha256, b"x").unwrap().len()),
            signer.key_kind().p1363_len()
        );
        assert_eq!(signer.algorithm(), signer.key_kind().algorithm());
    }
}
