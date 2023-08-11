// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

pub mod rfc5280;
pub mod webpki;

use asn1::ObjectIdentifier;
use cryptography_x509::certificate::Certificate;

use crate::ops::CryptoOps;

use super::PolicyError;

pub trait Profile<B: CryptoOps> {
    /// Critical CA certificate extensions that this profile is aware of.
    ///
    /// These are checked by the surrounding policy, in addition to any
    /// other extensions that the user asserts as critical.
    ///
    /// NOTE: Inclusion in this list doesn't mean that the extension is
    /// *required* to be critical, or that it must appear in a CA certificate,
    /// only that a CA certificate that contains such a critical extension
    /// will be considered accounted for.
    const CRITICAL_CA_EXTENSIONS: &'static [ObjectIdentifier];

    /// Critical EE certificate extensions that this profile is aware of.
    ///
    /// These are checked by the surrounding policy, in addition to any
    /// other extensions that the user asserts as critical.
    ///
    /// NOTE: Inclusion in this list doesn't mean that the extension is
    /// *required* to be critical, or that it must appear in an EE certificate,
    /// only that an EE certificate that contains such a critical extension
    /// will be considered accounted for.
    const CRITICAL_EE_EXTENSIONS: &'static [ObjectIdentifier];

    /// Returns a `Result` indicating whether the given certificate
    /// meet the "basic" (i.e., both CA and EE) requirements of this profile.
    fn permits_basic(&self, ops: &B, cert: &Certificate) -> Result<(), PolicyError>;

    /// Returns a `Result` indicating whether the given certificate is
    /// considered a valid CA certificate under this profile.
    fn permits_ca(&self, ops: &B, cert: &Certificate) -> Result<(), PolicyError>;

    /// Returns a `Result` indicating whether the given certificate is
    /// considered a valid end entity certificate under this profile.
    fn permits_ee(&self, ops: &B, cert: &Certificate) -> Result<(), PolicyError>;
}
