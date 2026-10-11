//! Certification path building and validation for [`build_trust`](super::build_trust)
//! (M3 brief §5 V9, decisions D-10, D-12 and D-16; RFC 5280 §6.1).
//!
//! **Building.** A depth-first search from the signer certificate: at each step the candidates
//! are the trust anchors, then the pool certificates, whose subject names the current
//! certificate's issuer (RFC 5280 §7.1 name chaining) and whose public key verifies its
//! signature. Signature checks are cached per (certificate, issuer) pair, and the search is
//! bounded: at most [`MAX_PATH_CERTIFICATES`] certificates below the anchor,
//! [`MAX_CANDIDATES`] pool certificates and as many anchors, [`MAX_SIGNATURE_CHECKS`]
//! signature verifications, [`MAX_EXPANSIONS`] search steps and [`MAX_COMPLETE_PATHS`]
//! complete paths. A hostile certificate set can therefore make the result untrusted, but never
//! slow.
//!
//! **Validation** of a complete path, as RFC 5280 §6.1.3 and §6.1.4 and pyhanko-certvalidator
//! (`validate.py`, `intl_validate_path`, `_prepare_next_step`) do it, without revocation,
//! policies or name constraints:
//!
//! - every certificate below the anchor is valid at the validation time, inclusive at both
//!   ends (§6.1.3 (a)(2));
//! - its outer `signatureAlgorithm` equals the one inside `tbsCertificate` (§4.1.1.2), and it
//!   is not signed with a weak hash (MD2, MD5, SHA-1: pyHanko's `DEFAULT_WEAK_HASH_ALGOS`),
//!   which gives the problem [`ProblemCode::WeakAlgorithm`];
//! - it has no critical extension Folioxide does not process (§6.1.4 (o)); see
//!   [`KNOWN_CRITICAL_EXTENSIONS`];
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

use der::oid::ObjectIdentifier;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};

use super::cert::{self, CertParts, RawProfileCertificate};
use super::{TrustResult, UnixTime, rfc3339};
use crate::algorithms::{DigestAlgorithm, KeyKind};
use crate::cms::decode::algorithm_id;
use crate::cms::tlv;
use crate::cms::verify::{Scheme, algorithm_name, classify};
use crate::keys::public::{PublicKey, VerifyFailure, ecdsa_der_to_fixed};
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
/// `SUPPORTED_EXTENSIONS` that Folioxide handles the same way).
///
/// Not in the list, so untrusted when critical (stricter than pyHanko, which processes them):
/// nameConstraints, policyMappings, policyConstraints, inhibitAnyPolicy; also issuerAltName and
/// every private extension.
pub const KNOWN_CRITICAL_EXTENSIONS: [(&str, &str); 12] = [
    ("2.5.29.14", "subjectKeyIdentifier"),
    ("2.5.29.15", "keyUsage"),
    ("2.5.29.17", "subjectAltName"),
    ("2.5.29.19", "basicConstraints"),
    ("2.5.29.31", "cRLDistributionPoints"),
    // Any policy is acceptable: no explicit policy is required (RFC 5280 §6.1.1 (c), (e)).
    ("2.5.29.32", "certificatePolicies"),
    ("2.5.29.35", "authorityKeyIdentifier"),
    // Not enforced on the signer, as in pyHanko's default key usage policy.
    ("2.5.29.37", "extKeyUsage"),
    ("2.5.29.46", "freshestCRL"),
    ("1.3.6.1.5.5.7.1.1", "authorityInfoAccess"),
    ("1.3.6.1.5.5.7.1.3", "qcStatements"),
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
    /// The subject as RFC 4514 text, for messages.
    name: String,
}

impl<'a> Candidate<'a> {
    fn parse(der: &'a [u8]) -> crate::error::Result<Candidate<'a>> {
        let parts = CertParts::parse(der)?;
        let decoded = cert::decode(der)?;
        let name = decoded.tbs_certificate().subject().to_string();
        Ok(Candidate {
            der,
            parts,
            decoded,
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
    /// The signature does not verify, or cannot be checked; the text says why.
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

    /// Whether `issuer` signed `child` (cached); failures become notes.
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
            check_extensions(certificate, &mut reasons);

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

/// Checks that `issuer`'s key verifies `child`'s signature over its `tbsCertificate`.
fn check_edge(child: &Candidate<'_>, issuer: &Candidate<'_>) -> Edge {
    let what = || format!("the signature of {} by {}", child.label(), issuer.label());
    let (algorithm_der, signature) = match CertParts::outer_signature(child.der) {
        Ok(parts) => parts,
        Err(err) => return Edge::Failed(format!("{}: {err}", child.label())),
    };
    let algorithm = match tlv::read_exact(algorithm_der, 4)
        .ok()
        .and_then(|element| algorithm_id(algorithm_der, &element, 0).ok())
    {
        Some(algorithm) => algorithm,
        None => {
            return Edge::Failed(format!(
                "{}: the signature algorithm does not parse",
                child.label()
            ));
        }
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
    let key = match PublicKey::from_spki_der(issuer.parts.spki) {
        Ok(key) => key,
        Err(err) => return Edge::Failed(format!("{}: the issuer key is unusable: {err}", what())),
    };
    let hashed = hash.digest(&[child.parts.tbs]);
    let verified = match scheme.scheme {
        Scheme::RsaPkcs1v15 => key
            .verify_rsa_pkcs1v15(hash, &hashed, signature)
            .map(|_| ()),
        Scheme::RsaPss { salt_len } => key.verify_rsa_pss(hash, salt_len, &hashed, signature),
        // RFC 5480 §2.2: a certificate's ECDSA signature is a DER ECDSA-Sig-Value; the fixed
        // form is passed on so that only that reading is tried.
        Scheme::Ecdsa => match key
            .ecdsa_field_len()
            .and_then(|field| ecdsa_der_to_fixed(signature, field))
        {
            Some(fixed) => key.verify_ecdsa(&hashed, &fixed).map(|_| ()),
            None => Err(VerifyFailure::Invalid(
                "the ECDSA signature is not a DER ECDSA-Sig-Value for the issuer's curve".into(),
            )),
        },
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

/// Unknown critical extensions, and extensions that occur twice (RFC 5280 §4.2).
fn check_extensions(certificate: &Candidate<'_>, reasons: &mut Vec<String>) {
    let Some(extensions) = certificate.decoded.tbs_certificate().extensions() else {
        return;
    };
    let label = certificate.label();
    let mut seen: Vec<&ObjectIdentifier> = Vec::new();
    for extension in extensions {
        if seen.contains(&&extension.extn_id) {
            reasons.push(format!(
                "{label} has the extension {} more than once",
                extension.extn_id
            ));
        }
        seen.push(&extension.extn_id);
        let dotted = extension.extn_id.to_string();
        if extension.critical
            && !KNOWN_CRITICAL_EXTENSIONS
                .iter()
                .any(|(known, _)| *known == dotted)
        {
            reasons.push(format!(
                "{label} has an unknown critical extension {dotted}"
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
