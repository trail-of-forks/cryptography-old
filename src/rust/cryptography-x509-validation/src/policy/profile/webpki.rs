// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Support for the Web PKI profile(s) specified by the CA/B Forum's
//! [Basic Requirements].
//!
//! Internally, this is implemented as an augmentation of the
//! [`RFC5280`] profile. This is possible because the CABF BRs are
//! specified as a superset of RFC 5280, per section 7.1.2.
//!
//! [Basic Requirements]: https://cabforum.org/wp-content/uploads/CA-Browser-Forum-BR-v2.0.0.pdf

use cryptography_x509::{
    certificate::Certificate,
    extensions::BasicConstraints,
    oid::{
        AUTHORITY_INFORMATION_ACCESS_OID, BASIC_CONSTRAINTS_OID, CERTIFICATE_POLICIES_OID,
        EXTENDED_KEY_USAGE_OID,
    },
};

use crate::{
    ops::CryptoOps,
    policy::{PolicyError, RFC5280},
};

use super::Profile;

/// The Web PKI certificate profile.
#[derive(Default)]
pub struct WebPKI {
    pub(crate) subprofile: RFC5280,
}

impl<B: CryptoOps> Profile<B> for WebPKI {
    const CRITICAL_CA_EXTENSIONS: &'static [asn1::ObjectIdentifier] =
        <RFC5280 as Profile<B>>::CRITICAL_CA_EXTENSIONS;

    const CRITICAL_EE_EXTENSIONS: &'static [asn1::ObjectIdentifier] =
        <RFC5280 as Profile<B>>::CRITICAL_EE_EXTENSIONS;

    fn permits_basic(&self, ops: &B, cert: &Certificate) -> Result<(), PolicyError> {
        self.subprofile.permits_basic(ops, cert)?;

        // TODO

        Ok(())
    }

    fn permits_ca(&self, ops: &B, cert: &Certificate) -> Result<(), PolicyError> {
        self.subprofile.permits_ca(ops, cert)?;

        // TODO

        Ok(())
    }

    fn permits_ee(&self, ops: &B, cert: &Certificate) -> Result<(), PolicyError> {
        self.subprofile.permits_ee(ops, cert)?;

        let extensions = cert.extensions()?;

        // The CA/B Forum BRs call EE certificates "subscriber" (or "server")
        // certificates, and describe their constraints in 7.1.2.7.

        // 7.1.2.7.1-5 Subscriber Certificate Types
        // TODO: Handle different subscriber certificate types?

        // 7.1.2.7.6 Subscriber Certificate Extensions
        // RFC 5280 enforces AKI and SAN (and the absence of Name Constraints);
        // CA/B additionally requires AIA, Certificate Policies, and EKU.

        // TODO: AIA must contain one or more access descriptions.
        // See: 7.1.2.7.7 Subscriber Certificate Authority Information Access
        if extensions
            .get_extension(&AUTHORITY_INFORMATION_ACCESS_OID)
            .is_none()
        {
            return Err(PolicyError::Other(
                "EE certificates must have an AIA extension",
            ));
        }

        // TODO: Certificate Policies must contain one or more PolicyInformations.
        // See: 7.1.2.7.9 Subscriber Certificate Certificate Policies
        if extensions
            .get_extension(&CERTIFICATE_POLICIES_OID)
            .is_none()
        {
            return Err(PolicyError::Other(
                "EE certificates must have a CertificatePolicies extension",
            ));
        }

        // TODO: MUST be serverAuth, MAY be clientAuth, MUST NOT be anything else
        // except non-standard EKUs (which are NOT RECOMMENDED).
        // See: 7.1.2.7.10 Subscriber Certificate Extended Key Usage
        if extensions.get_extension(&EXTENDED_KEY_USAGE_OID).is_none() {
            return Err(PolicyError::Other(
                "EE certificates must have an EKU extension",
            ));
        }

        // 7.1.2.7.8 Subscriber Certificate Basic Constraints
        // RFC 5280 enforces criticality; CA/B additionally requires that
        // cA MUST be false and pathLenConstraint MUST NOT be present.
        if let Some(basic_constraints) = extensions
            .get_extension(&BASIC_CONSTRAINTS_OID)
            .map(|e| e.value::<BasicConstraints>())
            .transpose()?
        {
            if basic_constraints.ca || basic_constraints.path_length.is_some() {
                return Err(PolicyError::Other(
                    "EE certificates must not have cA asserted or a pathlen constraint",
                ));
            }
        }

        // TODO: 7.1.2.7.11 Subscriber Certificate Key Usage

        // TODO: 7.1.2.7.12 Subscriber Certificate Subject Alternative Name

        Ok(())
    }
}
