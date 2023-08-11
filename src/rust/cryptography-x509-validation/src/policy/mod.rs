// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

pub mod profile;

use std::collections::HashSet;
use std::marker::PhantomData;

use asn1::ObjectIdentifier;
use cryptography_x509::certificate::Certificate;
use cryptography_x509::extensions::{
    BasicConstraints, DuplicateExtensionsError, ExtendedKeyUsage, Extension, SubjectAlternativeName,
};
use cryptography_x509::name::GeneralName;
use cryptography_x509::oid::{
    BASIC_CONSTRAINTS_OID, EKU_SERVER_AUTH_OID, EXTENDED_KEY_USAGE_OID,
    SUBJECT_ALTERNATIVE_NAME_OID,
};

use crate::certificate::cert_is_self_issued;
use crate::ops::CryptoOps;
use crate::types::{DNSName, DNSPattern, IPAddress, IPRange};

pub use self::profile::rfc5280::RFC5280;
pub use self::profile::Profile;

#[derive(Debug, PartialEq)]
pub enum PolicyError {
    Malformed(asn1::ParseError),
    DuplicateExtension(DuplicateExtensionsError),
    Other(&'static str),
}

impl From<asn1::ParseError> for PolicyError {
    fn from(value: asn1::ParseError) -> Self {
        Self::Malformed(value)
    }
}

impl From<DuplicateExtensionsError> for PolicyError {
    fn from(value: DuplicateExtensionsError) -> Self {
        Self::DuplicateExtension(value)
    }
}

impl From<&'static str> for PolicyError {
    fn from(value: &'static str) -> Self {
        Self::Other(value)
    }
}

/// Represents a logical certificate "subject," i.e. a principal matching
/// one of the names listed in a certificate's `subjectAltNames` extension.
pub enum Subject<'a> {
    DNS(DNSName<'a>),
    IP(IPAddress),
}

impl Subject<'_> {
    fn general_name_matches(&self, general_name: &GeneralName) -> bool {
        match (general_name, self) {
            (GeneralName::DNSName(pattern), Self::DNS(name)) => {
                if let Some(pattern) = DNSPattern::new(pattern.0) {
                    pattern.matches(name)
                } else {
                    false
                }
            }
            (GeneralName::IPAddress(pattern), Self::IP(name)) => {
                if let Some(pattern) = IPRange::from_bytes(pattern) {
                    pattern.matches(name)
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Returns true if any of the names in the given `SubjectAlternativeName`
    /// match this `Subject`.
    pub fn matches(&self, san: SubjectAlternativeName) -> bool {
        let mut san = san;
        san.any(|gn| self.general_name_matches(&gn))
    }
}

impl<'a> From<DNSName<'a>> for Subject<'a> {
    fn from(value: DNSName<'a>) -> Self {
        Self::DNS(value)
    }
}

impl From<IPAddress> for Subject<'_> {
    fn from(value: IPAddress) -> Self {
        Self::IP(value)
    }
}

/// A `Policy` describes user-configurable aspects of X.509 path validation.
///
/// A policy contains multiple moving parts:
///
/// 1. An inner `Profile`, which specifies the valid "shape" of certificates
///    in this policy (e.g., certificates that must conform to RFC 5280);
/// 2. Additional user-specified constraints, such as restrictions on
///    signature and algorithm types.
pub struct Policy<'a, B: CryptoOps, P: Profile<B>> {
    ops: B,

    /// The X.509 profile to use in this policy.
    pub profile: P,

    /// A top-level constraint on the length of paths constructed under
    /// this policy.
    ///
    /// Note that this has different semantics from `pathLenConstraint`:
    /// it controls the *overall* non-self-issued chain length, not the number
    /// of non-self-issued intermediates in the chain.
    pub max_chain_depth: u8,

    /// A subject (i.e. DNS name or other name format) that any EE certificates
    /// validated by this policy must match.
    /// If `None`, the EE certificate must not contain a SAN.
    // TODO: Make this an enum with supported SAN variants.
    pub subject: Option<Subject<'a>>,

    // NOTE: Conceptually this belongs in the underlying profile instead,
    // but doing so introduces another configuration point when virtually
    // every profile should have the same validation time semantics.
    // So we raise it to the profile instead.
    pub validation_time: asn1::DateTime,

    // NOTE: Like the validation time, this conceptually belongs
    // in the underlying profile.
    /// An extended key usage that must appear in EEs validated by this policy.
    pub extended_key_usage: ObjectIdentifier,

    // TODO: Real types here, as these get filled in.
    pub algorithms: (),

    critical_ca_extensions: HashSet<ObjectIdentifier>,
    critical_ee_extensions: HashSet<ObjectIdentifier>,

    _backend: PhantomData<B>,
}

impl<'a, B: CryptoOps, P: Profile<B> + Default> Policy<'a, B, P> {
    /// Create a new profile.
    ///
    /// `subject` is an optional subject that must match any EE certificates
    /// validated under this policy. If `None`, the EE certificate must not
    /// contain a SAN; not all underlying profiles permit this.
    ///
    /// `time` is the validation time to use when checking each certificate's
    /// liveness.
    pub fn new(ops: B, subject: Option<Subject<'a>>, time: asn1::DateTime) -> Self {
        Self {
            ops,
            profile: P::default(),
            max_chain_depth: 8,
            subject,
            validation_time: time,
            extended_key_usage: EKU_SERVER_AUTH_OID.clone(),
            algorithms: (),
            critical_ca_extensions: P::CRITICAL_CA_EXTENSIONS.iter().cloned().collect(),
            critical_ee_extensions: P::CRITICAL_EE_EXTENSIONS.iter().cloned().collect(),
            _backend: PhantomData,
        }
    }
}

impl<'a, B: CryptoOps, P: Profile<B>> Policy<'a, B, P> {
    /// Inform this policy of an expected critical extension in CA certificates.
    ///
    /// This allows the policy to accept critical extensions that the underlying
    /// profile does not cover. The user is responsible for separately validating
    /// these extensions.
    pub fn assert_critical_ca_extension(mut self, oid: ObjectIdentifier) -> Self {
        self.critical_ca_extensions.insert(oid);
        self
    }

    /// Inform this policy of an expected critical extension in EE certificates.
    ///
    /// This allows the policy to accept critical extensions that the underlying
    /// profile does not cover. The user is responsible for separately validating
    /// these extensions.
    pub fn assert_critical_ee_extension(mut self, oid: ObjectIdentifier) -> Self {
        self.critical_ee_extensions.insert(oid);
        self
    }

    /// Configure this policy's validation time, i.e. the time referenced
    /// for certificate validity period checks.
    pub fn with_validation_time(mut self, time: asn1::DateTime) -> Self {
        self.validation_time = time;
        self
    }

    /// Configure this policy's maximum chain building depth, i.e. the
    /// longest chain that path construction will attempt before giving up.
    pub fn with_max_chain_depth(mut self, depth: u8) -> Self {
        self.max_chain_depth = depth;
        self
    }

    fn permits_basic(&self, cert: &Certificate) -> Result<(), PolicyError> {
        self.profile.permits_basic(&self.ops, cert)?;

        // NOTE: Per NOTE on `validation_time` above: checking the validity
        // notionally belongs in the profile rather than the surrounding
        // policy, but it's universal enough that we do it here.
        if &self.validation_time < cert.tbs_cert.validity.not_before.as_datetime()
            || &self.validation_time > cert.tbs_cert.validity.not_after.as_datetime()
        {
            return Err(PolicyError::Other("cert is not valid at validation time"));
        }

        Ok(())
    }

    fn permits_san(&self, san_ext: Option<Extension<'_>>) -> Result<(), PolicyError> {
        // TODO: Check if the underlying profile requires a SAN here;
        // if it does and `name` is `None`, then fail.

        match (&self.subject, san_ext) {
            // If we're given both an expected name and the cert has a SAN,
            // then we attempt to match them.
            (Some(sub), Some(san)) => {
                let san: SubjectAlternativeName = san.value()?;
                match sub.matches(san) {
                    true => Ok(()),
                    false => Err(PolicyError::Other("EE cert has no matching SAN")),
                }
            }
            // If we aren't given a name but the cert contains a SAN,
            // we complain loudly (under the theory that the user has misused
            // our API and actually intended to match against the SAN).
            (None, Some(_)) => Err(PolicyError::Other(
                "EE cert has subjectAltName but no expected name given to match against",
            )),
            // If we're given an expected name but the cert doesn't contain a
            // SAN, we error.
            (Some(_), None) => Err(PolicyError::Other(
                "EE cert has no subjectAltName but expected name given",
            )),
            // No expected name and no SAN, no problem.
            (None, None) => Ok(()),
        }
    }

    fn permits_eku(&self, eku_ext: Option<Extension<'_>>) -> Result<(), PolicyError> {
        if let Some(ext) = eku_ext {
            let mut ekus: ExtendedKeyUsage = ext.value()?;

            if ekus.any(|eku| eku == self.extended_key_usage) {
                Ok(())
            } else {
                Err(PolicyError::Other("required EKU not found"))
            }
        } else {
            // If our cert doesn't specify an EKU, then we have nothing to check.
            // This is consistent with the CA/B BRs: a root CA MUST NOT contain
            // an EKU extension.
            // See: CA/B Baseline Requirements v2.0.0: 7.1.2.1.2
            Ok(())
        }
    }

    /// Checks whether the given CA certificate is compatible with this policy.
    pub(crate) fn permits_ca(&self, cert: &Certificate) -> Result<(), PolicyError> {
        self.permits_basic(cert)?;
        self.profile.permits_ca(&self.ops, cert)?;

        let extensions = cert.extensions()?;

        // CA certificates must also adhere to the expected EKU.
        self.permits_eku(extensions.get_extension(&EXTENDED_KEY_USAGE_OID))?;

        // TODO: Policy-level checks for EKUs, algorthms, etc.

        // Finally, check whether every critical extension in this CA
        // certificate is accounted for.
        for ext in extensions.iter() {
            if ext.critical && !self.critical_ca_extensions.contains(&ext.extn_id) {
                return Err(PolicyError::Other(
                    "CA certificate contains unaccounted critical extension",
                ));
            }
        }

        Ok(())
    }

    /// Checks whether the given EE certificate is compatible with this policy.
    pub(crate) fn permits_ee(&self, cert: &Certificate) -> Result<(), PolicyError> {
        // An end entity cert is considered "permitted" under a policy if:
        // 1. It satisfies the basic (both EE and CA) requirements of the underlying profile;
        // 2. It satisfies the EE-specific requirements of the profile;
        // 3. It satisfies the policy's own requirements (e.g. the cert's SANs
        //    match the policy's name).
        self.permits_basic(cert)?;
        self.profile.permits_ee(&self.ops, cert)?;

        let extensions = cert.extensions()?;

        self.permits_san(extensions.get_extension(&SUBJECT_ALTERNATIVE_NAME_OID))?;
        self.permits_eku(extensions.get_extension(&EXTENDED_KEY_USAGE_OID))?;

        // TODO: Policy-level checks here for KUs, algorithms, etc.

        // Finally, check whether every critical extension in this EE certificate
        // is accounted for.
        for ext in extensions.iter() {
            if ext.critical && !self.critical_ee_extensions.contains(&ext.extn_id) {
                return Err(PolicyError::Other(
                    "EE certificate contains unaccounted critical extensions",
                ));
            }
        }

        Ok(())
    }

    /// Checks whether `issuer` is a valid issuing CA for `child` at a
    /// path-building depth of `current_depth`.
    ///
    /// This checks that `issuer` is permitted under this policy and that
    /// it was used to sign for `child`.
    ///
    /// On success, this function returns the new path-building depth. This
    /// may or may not be a higher number than the original depth, depending
    /// on the kind of validation performed (e.g., whether the issuer was
    /// self-issued).
    pub(crate) fn valid_issuer(
        &self,
        issuer: &Certificate,
        child: &Certificate,
        current_depth: u8,
    ) -> Result<u8, PolicyError> {
        // The issuer needs to be a valid CA.
        self.permits_ca(issuer)?;

        let issuer_extensions = issuer.extensions()?;

        if let Some(bc) = issuer_extensions.get_extension(&BASIC_CONSTRAINTS_OID) {
            let bc: BasicConstraints = bc
                .value()
                .map_err(|_| PolicyError::Other("issuer has malformed basicConstraints"))?;

            // NOTE: `current_depth` starts at 1, indicating the EE cert in the chain.
            // Path length constraints only concern the intermediate portion of a chain,
            // so we have to adjust by 1.
            if bc
                .path_length
                .map_or(false, |len| (current_depth as u64) - 1 > len)
            {
                return Err(PolicyError::Other("path length constraint violated"));
            }
        }

        let pk = self
            .ops
            .public_key(issuer)
            .ok_or_else(|| PolicyError::Other("issuer has malformed public key"))?;
        if !self.ops.is_signed_by(child, pk) {
            return Err(PolicyError::Other("signature does not match"));
        }

        // Self-issued issuers don't increase the working depth.
        // NOTE: This is technically part of the profile's semantics.
        match cert_is_self_issued(issuer) {
            true => Ok(current_depth),
            false => Ok(current_depth + 1),
        }
    }
}

#[cfg(test)]
mod tests {}
