//! Crate-private certificate access: raw slices for CMS identifiers, and typed fields read with
//! the lenient `Raw` profile of `x509-cert`.
//!
//! Raw slices matter because Folioxide never re-encodes a certificate: the CMS `sid` and the ESS
//! `issuerSerial` copy the issuer `Name` and serial `INTEGER` exactly as the certificate encodes
//! them (M3 brief §4.3), and a verifier compares them byte for byte first.

use der::Decode as _;
use x509_cert::certificate::{CertificateInner, Raw};

use crate::cms::tlv::{self, TAG_BIT_STRING, TAG_CONTEXT_0, TAG_INTEGER, TAG_SEQUENCE};
use crate::error::{Error, Result};
use crate::keys::public::PublicKey;

/// The deepest nesting followed when locating the parts of a certificate.
const CERT_DEPTH: usize = 8;

/// A certificate parsed with the lenient `Raw` profile.
pub(crate) type RawProfileCertificate = CertificateInner<Raw>;

/// The raw parts of a DER certificate (RFC 5280 §4.1).
#[derive(Clone, Copy, Debug)]
pub(crate) struct CertParts<'a> {
    /// `tbsCertificate.serialNumber`: the whole `INTEGER` TLV.
    pub serial: &'a [u8],
    /// The content octets of the serial number `INTEGER`.
    pub serial_content: &'a [u8],
    /// `tbsCertificate.issuer`: the whole `Name` TLV.
    pub issuer: &'a [u8],
    /// `tbsCertificate.subject`: the whole `Name` TLV.
    pub subject: &'a [u8],
    /// `tbsCertificate.subjectPublicKeyInfo`: the whole TLV.
    pub spki: &'a [u8],
    /// The whole `tbsCertificate` TLV, exactly as encoded: the bytes the issuer signed.
    pub tbs: &'a [u8],
}

impl<'a> CertParts<'a> {
    /// Locates the parts of `der` without decoding them.
    ///
    /// # Errors
    /// [`Error::Certificate`] when the bytes are not shaped like a certificate.
    pub(crate) fn parse(der: &'a [u8]) -> Result<CertParts<'a>> {
        let malformed =
            |what: &str| Error::Certificate(format!("the certificate does not parse: {what}"));
        let cert = tlv::read_exact(der, CERT_DEPTH).map_err(|e| malformed(&e.to_string()))?;
        if cert.tag != TAG_SEQUENCE {
            return Err(malformed("not a SEQUENCE"));
        }
        let tbs = tlv::children(der, &cert, 0, CERT_DEPTH)
            .next()
            .ok_or_else(|| malformed("no tbsCertificate"))?
            .map_err(|e| malformed(&e.to_string()))?;
        if tbs.tag != TAG_SEQUENCE {
            return Err(malformed("tbsCertificate is not a SEQUENCE"));
        }
        let mut fields = tlv::children(der, &tbs, 1, CERT_DEPTH);
        let mut next = || -> Result<tlv::Element> {
            fields
                .next()
                .ok_or_else(|| malformed("tbsCertificate is too short"))?
                .map_err(|e| malformed(&e.to_string()))
        };
        let mut serial = next()?;
        if serial.tag == TAG_CONTEXT_0 {
            // version [0] EXPLICIT Version DEFAULT v1
            serial = next()?;
        }
        if serial.tag != TAG_INTEGER {
            return Err(malformed("serialNumber is not an INTEGER"));
        }
        let _signature = next()?;
        let issuer = next()?;
        let _validity = next()?;
        let subject = next()?;
        let spki = next()?;
        for (name, element) in [
            ("issuer", &issuer),
            ("subject", &subject),
            ("subjectPublicKeyInfo", &spki),
        ] {
            if element.tag != TAG_SEQUENCE {
                return Err(malformed(&format!("{name} is not a SEQUENCE")));
            }
        }
        Ok(CertParts {
            serial: serial.raw(der),
            serial_content: serial.content(der),
            issuer: issuer.raw(der),
            subject: subject.raw(der),
            spki: spki.raw(der),
            tbs: tbs.raw(der),
        })
    }

    /// The certificate's outer `signatureAlgorithm` (the whole `AlgorithmIdentifier` TLV) and
    /// the contents of its `signatureValue` BIT STRING without the unused-bits octet
    /// (RFC 5280 §4.1.1.2, §4.1.1.3).
    ///
    /// # Errors
    /// [`Error::Certificate`] when the certificate has no such fields, or the BIT STRING has
    /// unused bits.
    pub(crate) fn outer_signature(der: &'a [u8]) -> Result<(&'a [u8], &'a [u8])> {
        let malformed = |what: &str| {
            Error::Certificate(format!("the certificate signature does not parse: {what}"))
        };
        let cert = tlv::read_exact(der, CERT_DEPTH).map_err(|e| malformed(&e.to_string()))?;
        let fields = tlv::children_vec(der, &cert, 0, CERT_DEPTH, 3)
            .map_err(|e| malformed(&e.to_string()))?;
        let [_tbs, algorithm, value] = fields.as_slice() else {
            return Err(malformed(
                "expected tbsCertificate, signatureAlgorithm, signatureValue",
            ));
        };
        if algorithm.tag != TAG_SEQUENCE {
            return Err(malformed("signatureAlgorithm is not a SEQUENCE"));
        }
        if value.tag != TAG_BIT_STRING {
            return Err(malformed("signatureValue is not a BIT STRING"));
        }
        match value.content(der).split_first() {
            Some((0, bits)) => Ok((algorithm.raw(der), bits)),
            _ => Err(malformed("signatureValue has unused bits")),
        }
    }

    /// The certificate's public key.
    ///
    /// # Errors
    /// As [`PublicKey::from_spki_der`].
    pub(crate) fn public_key(&self) -> Result<PublicKey> {
        PublicKey::from_spki_der(self.spki)
    }
}

/// Decodes a certificate with the lenient `Raw` profile (serial numbers of any length, any time
/// encoding).
///
/// # Errors
/// [`Error::Certificate`] when it does not decode.
pub(crate) fn decode(der: &[u8]) -> Result<RawProfileCertificate> {
    RawProfileCertificate::from_der(der)
        .map_err(|e| Error::Certificate(format!("the certificate does not parse: {e}")))
}

/// The subjectKeyIdentifier extension value (RFC 5280 §4.2.1.2), when present and decodable.
pub(crate) fn subject_key_identifier(der: &[u8]) -> Option<Vec<u8>> {
    let cert = decode(der).ok()?;
    let (_, ski) = cert
        .tbs_certificate()
        .get_extension::<x509_cert::ext::pkix::SubjectKeyIdentifier>()
        .ok()??;
    Some(ski.0.as_bytes().to_vec())
}

/// Whether two DER `Name`s denote the same name: byte-identical, or equal once decoded (so a
/// re-encoded issuer still matches, as asn1crypto's comparison allows).
pub(crate) fn names_match(a: &[u8], b: &[u8]) -> bool {
    if a == b {
        return true;
    }
    match (
        x509_cert::name::Name::from_der(a),
        x509_cert::name::Name::from_der(b),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Whether two serial number `INTEGER` contents denote the same value.
pub(crate) fn serials_match(a: &[u8], b: &[u8]) -> bool {
    tlv::integer_canonical(a) == tlv::integer_canonical(b)
}
