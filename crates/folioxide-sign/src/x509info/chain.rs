//! Certification path building and validation for [`build_trust`](super::build_trust)
//! (M3 brief §5 V9, decisions D-10, D-12 and D-16; RFC 5280 §6.1).
//!
//! **Building.** A depth-first search from the signer certificate: at each step the candidates
//! are the trust anchors, then the pool certificates, whose subject names the current
//! certificate's issuer (RFC 5280 §7.1 name chaining), which the current certificate's
//! `authorityKeyIdentifier` describes ([`KeyIds::mismatch`]: key identifier, issuer name and
//! serial, as OpenSSL's `X509_check_akid` and pyhanko-certvalidator check them; manager ruling
//! R-22 (a)), and whose public key verifies its signature, made with an algorithm whose
//! parameters, in the outer `signatureAlgorithm` and in `tbsCertificate.signature`, are the
//! ones it defines (absent or NULL for RSASSA-PKCS1-v1_5, as pyhanko-certvalidator requires,
//! and absent for ECDSA; manager ruling R-30 (b)). Edge checks are cached per (certificate,
//! issuer) pair, and the search is bounded: at most [`MAX_PATH_CERTIFICATES`] certificates
//! below the anchor, [`MAX_CANDIDATES`] pool certificates and as many anchors,
//! [`MAX_SIGNATURE_CHECKS`] signature verifications, [`MAX_EXPANSIONS`] search steps and
//! [`MAX_COMPLETE_PATHS`] complete paths. A hostile certificate set can therefore make the result untrusted, but never
//! slow.
//!
//! **Validation** of a complete path, as RFC 5280 §6.1.3 and §6.1.4 and pyhanko-certvalidator
//! (`validate.py`, `intl_validate_path`, `_prepare_next_step`) do it, without revocation,
//! policies or name constraints, which make the path untrusted instead:
//!
//! - every certificate below the anchor is valid at the validation time, inclusive at both
//!   ends (§6.1.3 (a)(2));
//! - its outer `signatureAlgorithm` equals the one inside `tbsCertificate` (§4.1.1.2), and it
//!   is not signed with a weak hash (MD2, MD5, SHA-1: pyHanko's `DEFAULT_WEAK_HASH_ALGOS`),
//!   which gives the problem [`ProblemCode::WeakAlgorithm`];
//! - it has no critical extension Folioxide does not process (§6.1.4 (o)) or OpenSSL 3.0 does not
//!   handle as critical (`X509_supported_extension`: a critical key identifier or
//!   authorityInfoAccess, for example; M4 closing round, findings 8 and 11); see
//!   [`KNOWN_CRITICAL_EXTENSIONS`];
//! - its names hold only valid encodings and strings OpenSSL converts to UTF-8 (no BMPString
//!   surrogate; M4 QA round 4 finding 1);
//! - every extension of a known type decodes, critical or not, and none occurs twice
//!   (pyhanko-certvalidator and OpenSSL's `ossl_x509v3_cache_extensions` refuse a certificate
//!   whose authority or subject key identifier, alternative names, CRL distribution points,
//!   name constraints or extended key usage do not; M4 QA round 4 finding 5);
//! - no issuer carries `nameConstraints`, `policyMappings` or `policyConstraints`, critical or
//!   not, and the signer no `policyConstraints`: Folioxide does not process them (§6.1.4 (a),
//!   (g)–(i), §6.1.5 (b)), and ignoring a non-critical one made paths trusted that pyHanko and
//!   OpenSSL reject (QA round 4 finding 5: a `nameConstraints` excluding the signer's name); a
//!   path that satisfies one is untrusted too, which is stricter than both (a non-critical
//!   `inhibitAnyPolicy` cannot fail a path without them and is allowed);
//! - every issuer below the anchor is a CA (`basicConstraints cA`, §6.1.4 (k)), has
//!   `keyCertSign` when it has a key usage extension (§6.1.4 (n)), and the path respects every
//!   `pathLenConstraint` (§6.1.4 (l), (m); self-issued certificates do not count);
//! - the signer's key usage, when present, contains digitalSignature **or** nonRepudiation
//!   (D-10; pyHanko requires nonRepudiation, and the fixture signers have both bits).
//!
//! The trust anchor itself contributes only its name and public key (RFC 5280 §6.1.1 (d)):
//! its own validity, extensions and self-signature are not checked, as in pyHanko with default
//! trust-anchor qualifiers. When the signer certificate is itself an anchor, the path is the
//! signer alone, and its validity, extensions and key usage are still checked.
//!
//! RSA keys of 1024 to 8192 bits verify (D-12), but a path whose signer or issuer (anchor
//! included) has an RSA key below [`MIN_RSA_TRUST_BITS`] is untrusted with
//! [`ProblemCode::WeakAlgorithm`], as pyhanko-certvalidator's default algorithm policy and
//! pyHanko's CMS validation make it.

use std::collections::HashMap;

use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

use super::cert::{self, CertParts, RawProfileCertificate};
use super::extensions::{self, KeyIds};
use super::{TrustResult, UnixTime, rfc3339};
use crate::algorithms::{DigestAlgorithm, KeyKind, SignatureAlgorithm};
use crate::cms::decode::algorithm_id;
use crate::cms::verify::{Scheme, algorithm_name, classify, null_or_absent};
use crate::cms::{AlgorithmId, tlv};
use crate::keys::public::{PublicKey, VerifyFailure};
use crate::problem::{Problem, ProblemCode};

/// The smallest RSA key, in bits, that a trusted path may use: for the signer and for every
/// issuer, the anchor included (pyhanko-certvalidator's `DisallowWeakAlgorithmsPolicy`
/// `rsa_key_size_threshold`). Smaller keys of at least
/// [`MIN_RSA_VERIFY_BITS`](crate::algorithms::MIN_RSA_VERIFY_BITS) still verify (D-12).
pub const MIN_RSA_TRUST_BITS: u32 = 2048;
/// The most certificates a path may hold below its trust anchor, the signer included.
pub const MAX_PATH_CERTIFICATES: usize = 8;
/// The most pool certificates (and, separately, the most trust anchors) path building
/// considers; the rest are ignored with a warning.
pub const MAX_CANDIDATES: usize = 64;
/// The most certificate signatures one path search verifies.
pub const MAX_SIGNATURE_CHECKS: usize = 256;
/// The most search steps (certificates taken as the current end of a partial path).
pub const MAX_EXPANSIONS: usize = 4096;
/// The most complete paths that are validated before the search gives up.
pub const MAX_COMPLETE_PATHS: usize = 16;

/// Extensions that may be critical: the ones path validation processes, and the ones that need
/// no processing for a signature (RFC 5280 §4.2; the subset of pyhanko-certvalidator's
/// `SUPPORTED_EXTENSIONS` that Folioxide handles the same way), each one OpenSSL 3.0 also
/// handles when it is critical (`X509_supported_extension`).
///
/// Not in the list, so untrusted when critical:
/// - every extension OpenSSL does not handle as critical, among them a critical
///   subjectKeyIdentifier, authorityKeyIdentifier, authorityInfoAccess, freshestCRL,
///   qcStatements, issuerAltName and every private extension. OpenSSL refuses any chain with
///   such a certificate ("unhandled critical extension"), so on a TSA certificate one also makes
///   the token invalid (M4 closing round, findings 8 and 11; stricter than pyHanko, which trusts
///   a critical key identifier or authorityInfoAccess, and equal to OpenSSL);
/// - nameConstraints, policyMappings, policyConstraints, inhibitAnyPolicy, nsCertType and the
///   RFC 3779 and proxy certificate extensions, which OpenSSL handles and Folioxide does not
///   process (stricter than pyHanko and OpenSSL). The first three make an issuer untrusted even
///   when they are not critical (M4 QA round 4 finding 5), the RFC 3779 blocks and
///   proxyCertInfo any certificate of the path.
///
/// Every extension of a type Folioxide decodes must decode, critical or not.
pub const KNOWN_CRITICAL_EXTENSIONS: [(&str, &str); 7] = [
    ("2.5.29.15", "keyUsage"),
    ("2.5.29.17", "subjectAltName"),
    ("2.5.29.19", "basicConstraints"),
    ("2.5.29.31", "cRLDistributionPoints"),
    // Any policy is acceptable: no explicit policy is required (RFC 5280 §6.1.1 (c), (e)).
    ("2.5.29.32", "certificatePolicies"),
    // Not enforced on the signer, as in pyHanko's default key usage policy.
    ("2.5.29.37", "extKeyUsage"),
    ("1.3.6.1.5.5.7.48.1.5", "ocspNoCheck"),
];

/// Signature algorithms with a hash so weak that Folioxide does not even verify them
/// (md2WithRSAEncryption, md5WithRSAEncryption).
const UNVERIFIED_WEAK_ALGORITHMS: [(&str, &str); 2] = [
    ("1.2.840.113549.1.1.2", "md2WithRSAEncryption"),
    ("1.2.840.113549.1.1.4", "md5WithRSAEncryption"),
];

/// The most notes about dead ends kept for the "no path" reasons.
const MAX_NOTES: usize = 8;

/// A certificate that may be part of a path.
struct Candidate<'a> {
    der: &'a [u8],
    parts: CertParts<'a>,
    decoded: RawProfileCertificate,
    /// Its authority and subject key identifiers, for issuer matching.
    key_ids: KeyIds,
    /// The subject as RFC 4514 text, for messages.
    name: String,
}

impl<'a> Candidate<'a> {
    fn parse(der: &'a [u8]) -> crate::error::Result<Candidate<'a>> {
        let parts = CertParts::parse(der)?;
        let decoded = cert::decode(der)?;
        let key_ids = KeyIds::of(&decoded);
        let name = decoded.tbs_certificate().subject().to_string();
        Ok(Candidate {
            der,
            parts,
            decoded,
            key_ids,
            name,
        })
    }

    /// The text that names this certificate in messages: its subject, or its fingerprint
    /// prefix when the subject is empty.
    fn label(&self) -> String {
        if self.name.is_empty() {
            let digest = DigestAlgorithm::Sha256.digest(&[self.der]);
            let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
            format!("the certificate with SHA-256 {hex}…")
        } else {
            format!("\"{}\"", self.name)
        }
    }
}

/// A certificate in the search: the signer, a pool certificate or a trust anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Node {
    Signer,
    Pool(usize),
    Anchor(usize),
}

/// The outcome of checking that `issuer` signed `child`.
#[derive(Clone, Debug)]
enum Edge {
    /// The signature verifies; `weak` names the algorithm when its hash is weak (SHA-1), and
    /// `rsa_bits` is the size of an RSA issuer key.
    Verified {
        weak: Option<String>,
        rsa_bits: Option<u32>,
    },
    /// The signature uses MD2 or MD5: weak, and not verified.
    Weak(String),
    /// The signature does not verify, or cannot be checked, or `child`'s
    /// `authorityKeyIdentifier` does not describe `issuer`; the text says why.
    Failed(String),
}

/// The depth-first path search.
struct Search<'a> {
    signer: Candidate<'a>,
    pool: Vec<Candidate<'a>>,
    anchors: Vec<Candidate<'a>>,
    at: UnixTime,
    edges: HashMap<(Node, Node), Edge>,
    signature_checks: usize,
    expansions: usize,
    complete_paths: usize,
    /// A limit stopped the search.
    gave_up: Option<&'static str>,
    /// The first complete path that failed validation.
    first_failure: Option<TrustResult>,
    /// Why partial paths ended, for the "no path" result.
    notes: Vec<String>,
    /// An issuer signature used MD2 or MD5.
    weak_edge: bool,
    warnings: Vec<String>,
}

/// See [`super::build_trust`].
pub(crate) fn build_trust(
    signer_der: &[u8],
    pool: &[Vec<u8>],
    anchors: &[Vec<u8>],
    at: UnixTime,
) -> TrustResult {
    let signer = match Candidate::parse(signer_der) {
        Ok(signer) => signer,
        Err(err) => {
            return untrusted(format!("the signer certificate is unusable: {err}"));
        }
    };
    if anchors.is_empty() {
        return untrusted("no trust anchors were given".to_owned());
    }
    let mut warnings = Vec::new();
    let anchors = parse_all(anchors, "trust anchor", &[], &mut warnings);
    if anchors.is_empty() {
        let mut result = untrusted("none of the trust anchors is a usable certificate".to_owned());
        result.warnings = warnings;
        return result;
    }
    let pool = parse_all(pool, "pool certificate", &[signer_der], &mut warnings);
    let mut search = Search {
        signer,
        pool,
        anchors,
        at,
        edges: HashMap::new(),
        signature_checks: 0,
        expansions: 0,
        complete_paths: 0,
        gave_up: None,
        first_failure: None,
        notes: Vec::new(),
        weak_edge: false,
        warnings,
    };
    search.run()
}

/// An untrusted result with one reason.
fn untrusted(reason: String) -> TrustResult {
    TrustResult {
        reasons: vec![reason],
        ..TrustResult::default()
    }
}

/// Parses up to [`MAX_CANDIDATES`] certificates, skipping duplicates, the certificates in
/// `skip` and those that do not parse (each with a warning).
fn parse_all<'a>(
    ders: &'a [Vec<u8>],
    what: &str,
    skip: &[&[u8]],
    warnings: &mut Vec<String>,
) -> Vec<Candidate<'a>> {
    let mut out: Vec<Candidate<'a>> = Vec::new();
    for (index, der) in ders.iter().enumerate() {
        if skip.contains(&der.as_slice()) || out.iter().any(|c| c.der == der.as_slice()) {
            continue;
        }
        if out.len() == MAX_CANDIDATES {
            warnings.push(format!(
                "only the first {MAX_CANDIDATES} distinct {what}s were considered"
            ));
            break;
        }
        match Candidate::parse(der) {
            Ok(candidate) => out.push(candidate),
            Err(err) => warnings.push(format!("{what} {index} was ignored: {err}")),
        }
    }
    out
}

impl<'a> Search<'a> {
    fn run(&mut self) -> TrustResult {
        // The signer may itself be a trust anchor: the same certificate, or the same name and
        // key (RFC 5280 §6.1.1 (d) describes an anchor by its name and key only).
        let signer_anchor = self.anchors.iter().position(|anchor| {
            anchor.der == self.signer.der
                || (cert::names_match(anchor.parts.subject, self.signer.parts.subject)
                    && anchor.parts.spki == self.signer.parts.spki)
        });
        let mut found = match signer_anchor {
            Some(index) => {
                let result = self.validate(&[Node::Signer], Node::Anchor(index), true);
                self.consider(result)
            }
            None => None,
        };
        if found.is_none() {
            let mut path = vec![Node::Signer];
            found = self.search(&mut path);
        }
        let mut result = match (found, self.first_failure.take()) {
            (Some(trusted), _) => trusted,
            (None, Some(failure)) => failure,
            (None, None) => {
                let mut result = self.no_path();
                if self.weak_edge {
                    // The path may exist, but only through an MD2/MD5 signature.
                    push_weak(
                        &mut result.problems,
                        "an issuer signature uses MD2 or MD5, a weak algorithm",
                    );
                }
                result
            }
        };
        let mut warnings = std::mem::take(&mut self.warnings);
        warnings.append(&mut result.warnings);
        result.warnings = dedup(warnings);
        result
    }

    /// The "no path" result: the dead ends and the limits that were hit.
    fn no_path(&mut self) -> TrustResult {
        let mut reasons = vec![format!(
            "no certification path leads from {} to a trust anchor",
            self.signer.label()
        )];
        if let Some(limit) = self.gave_up {
            reasons.push(format!("path building stopped early: {limit}"));
        }
        reasons.extend(dedup(std::mem::take(&mut self.notes)));
        TrustResult {
            reasons,
            ..TrustResult::default()
        }
    }

    /// Keeps `result` if it is trusted; otherwise remembers the first failure.
    fn consider(&mut self, result: TrustResult) -> Option<TrustResult> {
        self.complete_paths += 1;
        if result.trusted {
            return Some(result);
        }
        if self.first_failure.is_none() {
            self.first_failure = Some(result);
        }
        None
    }

    fn candidate(&self, node: Node) -> Option<&Candidate<'a>> {
        match node {
            Node::Signer => Some(&self.signer),
            Node::Pool(i) => self.pool.get(i),
            Node::Anchor(i) => self.anchors.get(i),
        }
    }

    fn note(&mut self, text: String) {
        if self.notes.len() < MAX_NOTES {
            self.notes.push(text);
        }
    }

    /// Extends `path` (whose last certificate is the current one) until a valid path is found.
    fn search(&mut self, path: &mut Vec<Node>) -> Option<TrustResult> {
        if self.gave_up.is_some() {
            return None;
        }
        self.expansions += 1;
        if self.expansions > MAX_EXPANSIONS {
            self.gave_up = Some("too many search steps");
            return None;
        }
        let current = *path.last()?;
        let issuer_name = self.candidate(current)?.parts.issuer;
        let mut named = false;

        // Anchors first: the shortest path wins.
        for index in 0..self.anchors.len() {
            let anchor = self.anchors.get(index)?;
            if !cert::names_match(anchor.parts.subject, issuer_name) {
                continue;
            }
            named = true;
            if self.edge_verified(current, Node::Anchor(index)) {
                let result = self.validate(path, Node::Anchor(index), false);
                if let Some(trusted) = self.consider(result) {
                    return Some(trusted);
                }
                if self.complete_paths >= MAX_COMPLETE_PATHS {
                    self.gave_up = Some("too many complete paths failed validation");
                    return None;
                }
            }
            if self.gave_up.is_some() {
                return None;
            }
        }

        for index in 0..self.pool.len() {
            let node = Node::Pool(index);
            let candidate = self.pool.get(index)?;
            if path.contains(&node) || !cert::names_match(candidate.parts.subject, issuer_name) {
                continue;
            }
            named = true;
            if path.len() >= MAX_PATH_CERTIFICATES {
                let text = format!(
                    "a path through {} would be longer than {MAX_PATH_CERTIFICATES} certificates",
                    candidate.label()
                );
                self.note(text);
                continue;
            }
            if self.edge_verified(current, node) {
                path.push(node);
                if let Some(trusted) = self.search(path) {
                    return Some(trusted);
                }
                path.pop();
            }
            if self.gave_up.is_some() {
                return None;
            }
        }

        if !named && let Some(current) = self.candidate(current) {
            let issuer = current.decoded.tbs_certificate().issuer().to_string();
            let text = format!(
                "no certificate among the anchors and the pool is named \"{issuer}\", the \
                 issuer of {}",
                current.label()
            );
            self.note(text);
        }
        None
    }

    /// Whether `issuer` signed `child` and is the issuer `child`'s `authorityKeyIdentifier`
    /// describes (cached); failures become notes.
    fn edge_verified(&mut self, child: Node, issuer: Node) -> bool {
        let edge = match self.edges.get(&(child, issuer)) {
            Some(edge) => edge.clone(),
            None => {
                if self.signature_checks >= MAX_SIGNATURE_CHECKS {
                    self.gave_up = Some("too many certificate signatures to check");
                    return false;
                }
                self.signature_checks += 1;
                let edge = match (self.candidate(child), self.candidate(issuer)) {
                    (Some(c), Some(i)) => check_edge(c, i),
                    _ => Edge::Failed("internal: unknown certificate".to_owned()),
                };
                self.edges.insert((child, issuer), edge.clone());
                edge
            }
        };
        match edge {
            Edge::Verified { .. } => true,
            Edge::Weak(message) => {
                self.weak_edge = true;
                self.note(message);
                false
            }
            Edge::Failed(message) => {
                self.note(message);
                false
            }
        }
    }

    /// Validates the complete path `path` (signer first) that ends at `anchor`. With
    /// `signer_is_anchor`, `path` is the signer alone and the signer is the anchor.
    fn validate(&self, path: &[Node], anchor: Node, signer_is_anchor: bool) -> TrustResult {
        let mut reasons = Vec::new();
        let mut problems = Vec::new();
        let mut max_path_length = path.len();
        // From the anchor down to the signer (RFC 5280 §6.1.3 processes certificates in
        // that order).
        for (index, &node) in path.iter().enumerate().rev() {
            let Some(certificate) = self.candidate(node) else {
                continue;
            };
            let label = certificate.label();
            let tbs = certificate.decoded.tbs_certificate();

            check_validity(certificate, self.at, &mut reasons);
            check_names(certificate, &mut reasons);
            check_extensions(certificate, index > 0, &mut reasons);

            if certificate.decoded.signature_algorithm() != tbs.signature() {
                reasons.push(format!(
                    "{label}: the signature algorithm differs from the one in tbsCertificate"
                ));
            }
            let issuer = if signer_is_anchor {
                None
            } else {
                Some(path.get(index + 1).copied().unwrap_or(anchor))
            };
            if let Some(issuer) = issuer
                && let Some(Edge::Verified { weak, rsa_bits }) = self.edges.get(&(node, issuer))
            {
                if let Some(name) = weak {
                    let text = format!("{label} is signed with {name}, a weak algorithm");
                    push_weak(&mut problems, &text);
                    reasons.push(text);
                }
                if let Some(bits) = rsa_bits
                    && *bits < MIN_RSA_TRUST_BITS
                    && let Some(issuer) = self.candidate(issuer)
                {
                    let text = format!(
                        "{} signs with an RSA key of only {bits} bits, a weak key",
                        issuer.label()
                    );
                    push_weak(&mut problems, &text);
                    reasons.push(text);
                }
            }

            if index > 0 {
                // An issuing CA (RFC 5280 §6.1.4 (k)–(n)).
                let self_issued =
                    cert::names_match(certificate.parts.subject, certificate.parts.issuer);
                match tbs.get_extension::<BasicConstraints>() {
                    Ok(Some((_, constraints))) if constraints.ca => {
                        if !self_issued {
                            if max_path_length == 0 {
                                reasons.push(format!(
                                    "the path is longer than a pathLenConstraint above {label} allows"
                                ));
                            } else {
                                max_path_length -= 1;
                            }
                        }
                        if let Some(limit) = constraints.path_len_constraint {
                            max_path_length = max_path_length.min(usize::from(limit));
                        }
                    }
                    Ok(_) => reasons.push(format!(
                        "{label} issues a certificate but is not a CA (basicConstraints cA is not set)"
                    )),
                    Err(_) => reasons.push(format!(
                        "{label} has a malformed basicConstraints extension"
                    )),
                }
                match tbs.get_extension::<KeyUsage>() {
                    Ok(Some((_, usage))) if !usage.key_cert_sign() => reasons.push(format!(
                        "{label} issues a certificate but its key usage lacks keyCertSign"
                    )),
                    Ok(_) => {}
                    Err(_) => reasons.push(format!("{label} has a malformed keyUsage extension")),
                }
            } else {
                // The signer's own key: pyHanko's CMS validation applies the same RSA threshold
                // (generic_cms `_enforce_algorithm_usage`), so its signatures are never trusted.
                match PublicKey::from_spki_der(certificate.parts.spki).map(|k| k.kind()) {
                    Ok(KeyKind::Rsa { bits }) if bits < MIN_RSA_TRUST_BITS => {
                        let text = format!(
                            "the signer {label} has an RSA key of only {bits} bits, a weak key"
                        );
                        push_weak(&mut problems, &text);
                        reasons.push(text);
                    }
                    Ok(_) => {}
                    Err(err) => {
                        reasons.push(format!("the key of the signer {label} is unusable: {err}"))
                    }
                }
                // The signer (D-10: digitalSignature or nonRepudiation).
                match tbs.get_extension::<KeyUsage>() {
                    Ok(Some((_, usage)))
                        if !(usage.digital_signature() || usage.non_repudiation()) =>
                    {
                        reasons.push(format!(
                            "the key usage of the signer {label} allows neither digitalSignature \
                             nor nonRepudiation"
                        ));
                    }
                    Ok(_) => {}
                    Err(_) => reasons.push(format!("{label} has a malformed keyUsage extension")),
                }
            }
        }

        let mut der_path: Vec<Vec<u8>> = path
            .iter()
            .filter_map(|&node| self.candidate(node))
            .map(|c| c.der.to_vec())
            .collect();
        if !signer_is_anchor && let Some(anchor) = self.candidate(anchor) {
            der_path.push(anchor.der.to_vec());
        }
        TrustResult {
            trusted: reasons.is_empty(),
            path: der_path,
            reasons,
            warnings: Vec::new(),
            problems,
        }
    }
}

/// The certificates of `pool` that issued `leaf_der`, and transitively the ones that issued
/// one of those, each link checked by name **and** signature: the candidate's subject names
/// the certificate's issuer (RFC 5280 §7.1) and the candidate's key verifies its signature
/// (MD2 and MD5 signatures never link). `leaf_der` itself and repeated certificates are left
/// out; the result is in pool order.
///
/// This is the stand-in, without trust anchors, for the verified chain that OpenSSL checks
/// later ESS certificate identifiers against (`OSSL_ESS_check_signing_certs`; M4 QA round 2
/// finding 3): a certificate that merely carries an issuer's name is never part of it. Each
/// certificate is expanded once and each (certificate, candidate) pair is checked once; after
/// [`MAX_SIGNATURE_CHECKS`] signature checks the search stops with what it found, so a caller
/// that looks for a certificate in the result fails closed.
pub(crate) fn linked_issuers<'a>(leaf_der: &[u8], pool: &'a [Vec<u8>]) -> Vec<&'a [u8]> {
    let Ok(leaf) = CertParts::parse(leaf_der) else {
        return Vec::new();
    };
    let leaf_ids = KeyIds::of_der(leaf_der);
    // The distinct pool certificates other than the leaf, with their canonical subjects and
    // key identifiers.
    let mut seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
    seen.insert(leaf_der);
    type Node<'a> = (&'a [u8], CertParts<'a>, Option<cert::CanonicalName>, KeyIds);
    let nodes: Vec<Node<'a>> = pool
        .iter()
        .filter(|der| seen.insert(der.as_slice()))
        .filter_map(|der| {
            let parts = CertParts::parse(der).ok()?;
            let subject = cert::canonical_name(parts.subject);
            Some((der.as_slice(), parts, subject, KeyIds::of_der(der)))
        })
        .collect();
    let mut linked = vec![false; nodes.len()];
    let mut checks = 0usize;
    // `None` is the leaf, `Some(i)` the node `i`; each enters the frontier once.
    let mut frontier: Vec<Option<usize>> = vec![None];
    'search: while let Some(current) = frontier.pop() {
        let (child_der, child, child_ids) = match current {
            None => (leaf_der, leaf, &leaf_ids),
            Some(index) => match nodes.get(index) {
                Some((der, parts, _, ids)) => (*der, *parts, ids),
                None => continue,
            },
        };
        let issuer = cert::canonical_name(child.issuer);
        for (index, (_, candidate, subject, candidate_ids)) in nodes.iter().enumerate() {
            if linked.get(index).copied().unwrap_or(true) {
                continue;
            }
            let named = candidate.subject == child.issuer
                || matches!((subject, &issuer), (Some(s), Some(i)) if s == i);
            // The authorityKeyIdentifier must describe the candidate, as on a path (R-22 (a)).
            if !named || child_ids.mismatch(candidate_ids, candidate).is_some() {
                continue;
            }
            if checks >= MAX_SIGNATURE_CHECKS {
                break 'search;
            }
            checks += 1;
            let edge = verify_edge(
                child_der,
                &child,
                candidate.spki,
                &String::new,
                &String::new,
            );
            if matches!(edge, Edge::Verified { .. }) {
                if let Some(slot) = linked.get_mut(index) {
                    *slot = true;
                }
                frontier.push(Some(index));
            }
        }
    }
    nodes
        .iter()
        .zip(&linked)
        .filter(|(_, linked)| **linked)
        .map(|((der, _, _, _), _)| *der)
        .collect()
}

/// Checks that `child`'s `authorityKeyIdentifier` describes `issuer` (R-22 (a)) and that
/// `issuer`'s key verifies `child`'s signature over its `tbsCertificate`.
fn check_edge(child: &Candidate<'_>, issuer: &Candidate<'_>) -> Edge {
    if let Some(why) = child.key_ids.mismatch(&issuer.key_ids, &issuer.parts) {
        return akid_failure(&child.label(), &issuer.label(), why);
    }
    verify_edge(
        child.der,
        &child.parts,
        issuer.parts.spki,
        &|| child.label(),
        &|| issuer.label(),
    )
}

/// The failed edge of a certificate (`child`) whose `authorityKeyIdentifier` does not describe
/// `issuer` (RFC 5280 §4.2.1.1).
fn akid_failure(child: &str, issuer: &str, why: &str) -> Edge {
    Edge::Failed(format!(
        "the authorityKeyIdentifier of {child} does not describe {issuer} as its issuer: {why} \
         (RFC 5280 §4.2.1.1)"
    ))
}

/// Checks that the key `issuer_spki` verifies the signature of the certificate `child_der`
/// (whose parts are `child`) over its `tbsCertificate`; the labels name the two certificates
/// in messages.
///
/// Both AlgorithmIdentifiers that name the signature algorithm, the outer `signatureAlgorithm`
/// and `tbsCertificate.signature`, must have the parameters their algorithm defines
/// ([`parameters_defect`], manager ruling R-30 (b)); otherwise the edge fails without a
/// signature check.
fn verify_edge(
    child_der: &[u8],
    child: &CertParts<'_>,
    issuer_spki: &[u8],
    child_label: &dyn Fn() -> String,
    issuer_label: &dyn Fn() -> String,
) -> Edge {
    let what = || format!("the signature of {} by {}", child_label(), issuer_label());
    let (algorithm_der, signature) = match CertParts::outer_signature(child_der) {
        Ok(parts) => parts,
        Err(err) => return Edge::Failed(format!("{}: {err}", child_label())),
    };
    let Some(algorithm) = parse_algorithm(algorithm_der) else {
        return Edge::Failed(format!(
            "{}: the signature algorithm does not parse",
            child_label()
        ));
    };
    if let Some((_, name)) = UNVERIFIED_WEAK_ALGORITHMS
        .iter()
        .find(|(dotted, _)| *dotted == algorithm.oid)
    {
        return Edge::Weak(format!(
            "{} uses {name}, a weak algorithm that is not verified",
            what()
        ));
    }
    let Some(inner) = parse_algorithm(child.signature) else {
        return Edge::Failed(format!(
            "{}: the signature algorithm in tbsCertificate does not parse",
            child_label()
        ));
    };
    for (part, algorithm) in [
        ("signatureAlgorithm", &algorithm),
        ("tbsCertificate signature", &inner),
    ] {
        if let Some(defect) = parameters_defect(algorithm) {
            return Edge::Failed(format!("{}: its {part} {defect}", what()));
        }
    }
    let scheme = match classify(&algorithm) {
        Ok(scheme) => scheme,
        Err(message) => return Edge::Failed(format!("{}: {message}", what())),
    };
    let Some(hash) = scheme.implied_hash else {
        return Edge::Failed(format!(
            "{}: the algorithm {} names no hash",
            what(),
            algorithm_name(&algorithm.oid)
        ));
    };
    let key = match PublicKey::from_spki_der(issuer_spki) {
        Ok(key) => key,
        Err(err) => return Edge::Failed(format!("{}: the issuer key is unusable: {err}", what())),
    };
    let hashed = hash.digest(&[child.tbs]);
    let verified = match scheme.scheme {
        Scheme::RsaPkcs1v15 => key
            .verify_rsa_pkcs1v15(hash, &hashed, signature)
            .map(|_| ()),
        Scheme::RsaPss { salt_len } => key.verify_rsa_pss(hash, salt_len, &hashed, signature),
        // RFC 5480 §2.2: a certificate's ECDSA signature is a DER ECDSA-Sig-Value, minimal as
        // OpenSSL requires (it re-encodes and compares).
        Scheme::Ecdsa => key.verify_ecdsa_der(&hashed, signature),
    };
    let rsa_bits = match key.kind() {
        KeyKind::Rsa { bits } => Some(bits),
        _ => None,
    };
    match verified {
        Ok(()) => Edge::Verified {
            weak: hash
                .is_weak()
                .then(|| algorithm_name_for(&algorithm.oid, hash)),
            rsa_bits,
        },
        Err(VerifyFailure::Invalid(message)) => {
            Edge::Failed(format!("{} does not verify: {message}", what()))
        }
    }
}

/// The AlgorithmIdentifier whose whole DER is `der`, or `None` when it does not parse.
fn parse_algorithm(der: &[u8]) -> Option<AlgorithmId> {
    tlv::read_exact(der, 4)
        .ok()
        .and_then(|element| algorithm_id(der, &element, 0).ok())
}

/// Why the parameters of a certificate's signature AlgorithmIdentifier (the outer
/// `signatureAlgorithm` or `tbsCertificate.signature`) are not the ones its algorithm defines,
/// if they are not (manager ruling R-30 (b)):
///
/// - the RSASSA-PKCS1-v1_5 algorithms take absent or NULL parameters (RFC 4055 §5: they "MUST
///   be NULL" and implementations "MUST accept the parameters being absent as well"; RFC 3279
///   §2.2.1 for sha1WithRSAEncryption);
/// - the ECDSA algorithms take none (RFC 5758 §3.2 and RFC 3279 §2.2.3: "the encoding MUST
///   omit the parameters field").
///
/// For the RSA algorithms with a SHA-2 hash, pyhanko-certvalidator does not trust a path
/// through a certificate with other parameters there (asn1crypto requires NULL), an INTEGER
/// for example, where Folioxide had verified the signature and ignored them (QA variant
/// `r10-samealg-int-int`). For ECDSA, pyHanko and OpenSSL accept any parameters: Folioxide is
/// stricter, as RFC 5758 says. RSASSA-PSS parameters are checked by [`classify`]
/// ([`pss_parameters`](crate::cms::verify::pss_parameters)); MD2 and MD5 signatures are never
/// verified.
fn parameters_defect(algorithm: &AlgorithmId) -> Option<String> {
    let scheme = classify(algorithm).ok()?;
    let parameters = algorithm.parameters.as_deref();
    let name = |kind: SignatureAlgorithm| {
        scheme.implied_hash.map_or_else(
            || algorithm_name(&algorithm.oid),
            |hash| kind.signature_name(hash).to_owned(),
        )
    };
    match scheme.scheme {
        Scheme::RsaPkcs1v15 if !null_or_absent(parameters) => Some(format!(
            "{} has parameters that are neither absent nor NULL (RFC 4055 §5)",
            name(SignatureAlgorithm::RsaPkcs1v15)
        )),
        Scheme::Ecdsa if parameters.is_some() => Some(format!(
            "{} has parameters, which must be absent (RFC 5758 §3.2)",
            name(SignatureAlgorithm::Ecdsa)
        )),
        _ => None,
    }
}

/// A readable name for a certificate signature algorithm with a known hash.
fn algorithm_name_for(dotted: &str, hash: DigestAlgorithm) -> String {
    match dotted {
        crate::algorithms::oid::SHA1_WITH_RSA => "sha1WithRSAEncryption".to_owned(),
        crate::algorithms::oid::ECDSA_WITH_SHA1 => "ecdsa-with-SHA1".to_owned(),
        crate::algorithms::oid::RSASSA_PSS => format!("RSASSA-PSS with {hash}"),
        other => algorithm_name(other),
    }
}

/// Validity at `at`, inclusive at both ends (RFC 5280 §4.1.2.5, §6.1.3 (a)(2)).
fn check_validity(certificate: &Candidate<'_>, at: UnixTime, reasons: &mut Vec<String>) {
    let validity = certificate.decoded.tbs_certificate().validity();
    let seconds = |time: x509_cert::time::Time| {
        i64::try_from(time.to_unix_duration().as_secs()).unwrap_or(i64::MAX)
    };
    let label = certificate.label();
    if at.secs() < seconds(validity.not_before) {
        reasons.push(format!(
            "{label} is not valid before {}",
            rfc3339(&validity.not_before)
        ));
    }
    if at.secs() > seconds(validity.not_after) {
        reasons.push(format!(
            "{label} expired on {}",
            rfc3339(&validity.not_after)
        ));
    }
}

/// The issuer and subject names of a certificate of the path: every primitive a valid encoding
/// and every string one OpenSSL converts to UTF-8 ([`tlv::check_primitives`]; no BMPString
/// surrogate, no UniversalString beyond Unicode). OpenSSL cannot decode a certificate with such
/// a name at all, and pyhanko-certvalidator fails on a lone surrogate (M4 QA round 4 finding
/// 1). The value types are not restricted here (pyHanko reads a VisibleString value).
fn check_names(certificate: &Candidate<'_>, reasons: &mut Vec<String>) {
    for (what, name) in [
        ("subject", certificate.parts.subject),
        ("issuer", certificate.parts.issuer),
    ] {
        let converts = tlv::read_exact(name, crate::cms::MAX_DEPTH).is_ok_and(|element| {
            tlv::check_primitives(name, &element, 0, crate::cms::MAX_DEPTH).is_ok()
        });
        if !converts {
            reasons.push(format!(
                "{}: its {what} name holds a string OpenSSL cannot convert to UTF-8 or an \
                 invalid encoding",
                certificate.label()
            ));
        }
    }
}

/// The extensions of a certificate of the path (RFC 5280 §4.2): none twice and every known one
/// decoding as RFC 5280 defines it, critical or not ([`extensions::integrity_defects`]), no
/// critical one outside [`KNOWN_CRITICAL_EXTENSIONS`] (one OpenSSL does not handle either is
/// named by [`extensions::unhandled_critical`]; M4 closing round, findings 8 and 11), none of
/// the constraints Folioxide does not process on a certificate that issues (`issuing`) or, for
/// `policyConstraints`, on any certificate (M4 QA round 4 finding 5), and no RFC 3779 resource
/// block or proxy certificate information on any certificate (M4 final fix round 2, finding 1;
/// see [`extensions`]).
fn check_extensions(certificate: &Candidate<'_>, issuing: bool, reasons: &mut Vec<String>) {
    let Some(extensions) = certificate.decoded.tbs_certificate().extensions() else {
        return;
    };
    let label = certificate.label();
    for defect in extensions::integrity_defects(extensions)
        .into_iter()
        .chain(extensions::unhandled_critical(extensions))
    {
        reasons.push(format!("{label} has {defect}"));
    }
    for extension in extensions {
        let dotted = extension.extn_id.to_string();
        // A critical extension OpenSSL handles and Folioxide does not process (the others are
        // named by `unhandled_critical` above).
        if extension.critical
            && extensions::openssl_handles_critical(&dotted)
            && !KNOWN_CRITICAL_EXTENSIONS
                .iter()
                .any(|(known, _)| *known == dotted)
        {
            let name = extensions::decoded_name(&dotted).unwrap_or("unknown");
            reasons.push(format!(
                "{label} has a critical {name} extension, which Folioxide does not process (RFC \
                 5280 §6.1.4 (o))"
            ));
        }
        if let Some((_, name)) = extensions::UNPROCESSED_CONSTRAINTS
            .iter()
            .find(|(known, _)| *known == dotted)
            && (issuing || dotted == extensions::POLICY_CONSTRAINTS)
        {
            reasons.push(format!(
                "{label} has a {name} extension, which Folioxide does not process (RFC 5280 \
                 §6.1.4), so the path is not trusted whether it is critical or not"
            ));
        }
        if let Some((_, name)) = extensions::UNPROCESSED_ON_ANY_CERTIFICATE
            .iter()
            .find(|(known, _)| *known == dotted)
        {
            reasons.push(format!(
                "{label} has the {name} extension, whose path processing Folioxide does not \
                 implement (OpenSSL refuses such a chain), so the path is not trusted whether it \
                 is critical or not"
            ));
        }
    }
}

/// Adds one [`ProblemCode::WeakAlgorithm`] problem (the first message wins).
fn push_weak(problems: &mut Vec<Problem>, message: &str) {
    if !problems
        .iter()
        .any(|p| p.code == ProblemCode::WeakAlgorithm)
    {
        problems.push(Problem::new(ProblemCode::WeakAlgorithm, message));
    }
}

/// `items` without repeats, in first-seen order.
fn dedup(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        if !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cms::tlv::{
        TAG_BIT_STRING, TAG_CONTEXT_0, TAG_INTEGER, TAG_NULL, TAG_OID, TAG_SEQUENCE, TAG_SET,
        TAG_UTC_TIME, tlv, tlv_parts,
    };

    /// `Name { RDN { CN = cn } }`.
    fn name(cn: &str) -> Vec<u8> {
        let atv = tlv_parts(
            TAG_SEQUENCE,
            &[
                &tlv(TAG_OID, &[0x55, 0x04, 0x03]),
                &tlv(0x0C, cn.as_bytes()),
            ],
        );
        tlv(TAG_SEQUENCE, &tlv(TAG_SET, &atv))
    }

    /// `sha256WithRSAEncryption` (1.2.840.113549.1.1.11), content octets.
    const SHA256_WITH_RSA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
    /// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2), content octets.
    const ECDSA_WITH_SHA256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

    /// The AlgorithmIdentifier of the OID content octets `oid` followed by `parameters` (the
    /// whole element; empty for none).
    fn algorithm(oid: &[u8], parameters: &[u8]) -> Vec<u8> {
        tlv_parts(TAG_SEQUENCE, &[&tlv(TAG_OID, oid), parameters])
    }

    /// A certificate-shaped DER from `issuer` for `subject` whose key and signature are junk,
    /// so no signature of it or by it ever verifies.
    fn shaped(issuer: &str, subject: &str, serial: u16) -> Vec<u8> {
        let algorithm = algorithm(&SHA256_WITH_RSA, &tlv(TAG_NULL, &[]));
        shaped_with(issuer, subject, serial, &algorithm, &algorithm)
    }

    /// [`shaped`] with the signature AlgorithmIdentifier `inner` in `tbsCertificate` and
    /// `outer` outside.
    fn shaped_with(
        issuer: &str,
        subject: &str,
        serial: u16,
        inner: &[u8],
        outer: &[u8],
    ) -> Vec<u8> {
        let time = tlv(TAG_UTC_TIME, b"250101000000Z");
        let key_algorithm = algorithm(&SHA256_WITH_RSA, &tlv(TAG_NULL, &[]));
        let tbs = tlv_parts(
            TAG_SEQUENCE,
            &[
                &tlv(TAG_CONTEXT_0, &tlv(TAG_INTEGER, &[2])),
                &tlv(
                    TAG_INTEGER,
                    &[0x01, serial.to_be_bytes()[0], serial.to_be_bytes()[1]],
                ),
                inner,
                &name(issuer),
                &tlv_parts(TAG_SEQUENCE, &[&time, &time]),
                &name(subject),
                &tlv_parts(
                    TAG_SEQUENCE,
                    &[&key_algorithm, &tlv(TAG_BIT_STRING, &[0x00, 0x30, 0x00])],
                ),
            ],
        );
        tlv_parts(
            TAG_SEQUENCE,
            &[&tbs, outer, &tlv(TAG_BIT_STRING, &[0x00, 0x01, 0x02])],
        )
    }

    #[test]
    fn signature_parameters_follow_the_algorithm() {
        // Manager ruling R-30 (b): absent or NULL for RSASSA-PKCS1-v1_5 (RFC 4055 §5), absent
        // for ECDSA (RFC 5758 §3.2).
        let null = tlv(TAG_NULL, &[]);
        let integer = tlv(TAG_INTEGER, &[1]);
        let octets = tlv(crate::cms::tlv::TAG_OCTET_STRING, &[]);
        let sequence = tlv(TAG_SEQUENCE, &[]);
        // A NULL with a non-minimal length, and one with content.
        let long_null = vec![TAG_NULL, 0x81, 0x00];
        let full_null = vec![TAG_NULL, 0x01, 0x00];
        let id = |oid: &str, parameters: Option<&[u8]>| AlgorithmId {
            oid: oid.to_owned(),
            parameters: parameters.map(<[u8]>::to_vec),
        };
        use crate::algorithms::oid;
        for rsa in [
            oid::RSA_ENCRYPTION,
            oid::SHA1_WITH_RSA,
            oid::SHA256_WITH_RSA,
            oid::SHA384_WITH_RSA,
            oid::SHA512_WITH_RSA,
        ] {
            assert_eq!(parameters_defect(&id(rsa, None)), None, "{rsa}");
            assert_eq!(parameters_defect(&id(rsa, Some(&null))), None, "{rsa}");
            for bad in [&integer, &octets, &sequence, &long_null, &full_null] {
                let defect = parameters_defect(&id(rsa, Some(bad))).unwrap();
                assert!(
                    defect.contains("neither absent nor NULL"),
                    "{rsa}: {defect}"
                );
            }
        }
        assert!(
            parameters_defect(&id(oid::SHA256_WITH_RSA, Some(&integer)))
                .unwrap()
                .starts_with("sha256WithRSAEncryption ")
        );
        for ecdsa in [
            oid::ECDSA_WITH_SHA1,
            oid::ECDSA_WITH_SHA256,
            oid::ECDSA_WITH_SHA384,
            oid::ECDSA_WITH_SHA512,
        ] {
            assert_eq!(parameters_defect(&id(ecdsa, None)), None, "{ecdsa}");
            for bad in [&null, &integer, &octets, &sequence] {
                let defect = parameters_defect(&id(ecdsa, Some(bad))).unwrap();
                assert!(defect.contains("must be absent"), "{ecdsa}: {defect}");
            }
        }
        // RSASSA-PSS parameters are classify's (pss_parameters); MD5 and unknown algorithms are
        // never verified, so this check says nothing about them.
        assert_eq!(parameters_defect(&id(oid::RSASSA_PSS, None)), None);
        assert_eq!(
            parameters_defect(&id("1.2.840.113549.1.1.4", Some(&integer))),
            None
        );
        assert_eq!(parameters_defect(&id("1.3.101.112", Some(&integer))), None);
    }

    #[test]
    fn edges_check_the_parameters_inside_and_outside() {
        // Both AlgorithmIdentifiers are checked before the signature (whose key here is junk,
        // so a well-formed edge fails later, on the key): the outer one first.
        let rsa = |parameters: &[u8]| algorithm(&SHA256_WITH_RSA, parameters);
        let ecdsa = |parameters: &[u8]| algorithm(&ECDSA_WITH_SHA256, parameters);
        let null = tlv(TAG_NULL, &[]);
        let integer = tlv(TAG_INTEGER, &[1]);
        let issuer = shaped("Test CA", "Test CA", 1);
        let issuer_spki = CertParts::parse(&issuer).unwrap().spki;
        for (inner, outer, defect) in [
            (rsa(&null), rsa(&null), None),
            (rsa(&[]), rsa(&[]), None),
            (ecdsa(&[]), ecdsa(&[]), None),
            (rsa(&integer), rsa(&integer), Some("its signatureAlgorithm")),
            (rsa(&null), rsa(&integer), Some("its signatureAlgorithm")),
            (
                rsa(&integer),
                rsa(&null),
                Some("its tbsCertificate signature"),
            ),
            (ecdsa(&null), ecdsa(&null), Some("its signatureAlgorithm")),
            (ecdsa(&[]), ecdsa(&null), Some("its signatureAlgorithm")),
            (
                ecdsa(&null),
                ecdsa(&[]),
                Some("its tbsCertificate signature"),
            ),
        ] {
            let leaf = shaped_with("Test CA", "Test Leaf", 0, &inner, &outer);
            let parts = CertParts::parse(&leaf).unwrap();
            let edge = verify_edge(
                &leaf,
                &parts,
                issuer_spki,
                &|| "the leaf".to_owned(),
                &|| "the CA".to_owned(),
            );
            let Edge::Failed(message) = edge else {
                panic!("{defect:?}: {edge:?}");
            };
            match defect {
                Some(part) => assert!(
                    message.starts_with(&format!("the signature of the leaf by the CA: {part} ")),
                    "{message}"
                ),
                None => assert!(message.contains("the issuer key is unusable"), "{message}"),
            }
        }
        // An unreadable AlgorithmIdentifier inside tbsCertificate fails the edge too.
        let leaf = shaped_with(
            "Test CA",
            "Test Leaf",
            0,
            &tlv(TAG_SEQUENCE, &[]),
            &rsa(&null),
        );
        let parts = CertParts::parse(&leaf).unwrap();
        let edge = verify_edge(&leaf, &parts, issuer_spki, &String::new, &String::new);
        assert!(
            matches!(&edge, Edge::Failed(m) if m.contains("in tbsCertificate does not parse")),
            "{edge:?}"
        );
    }

    #[test]
    fn issuers_are_linked_by_signature_not_by_name() {
        // QA round 2 finding 3: certificates named like the issuer, none of whose keys verifies
        // the leaf, are never linked; more of them than the signature budget is no problem.
        let leaf = shaped("Test CA", "Test Leaf", 0);
        let pool: Vec<Vec<u8>> = (1..=300).map(|i| shaped("Test CA", "Test CA", i)).collect();
        assert!(pool.len() > MAX_SIGNATURE_CHECKS);
        assert!(linked_issuers(&leaf, &pool).is_empty());
        // The leaf itself, garbage and repeats are skipped; garbage as the leaf links nothing.
        let odd = [
            leaf.clone(),
            b"garbage".to_vec(),
            pool[0].clone(),
            pool[0].clone(),
        ];
        assert!(linked_issuers(&leaf, &odd).is_empty());
        assert!(linked_issuers(b"garbage", &pool).is_empty());
        assert!(linked_issuers(&leaf, &[]).is_empty());
    }
}
