// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Support for the Internet PKI profile specified in [RFC 5280].
//!
//! [RFC 5280]: https://datatracker.ietf.org/doc/html/rfc5280

use cryptography_x509::{
    certificate::Certificate,
    extensions::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage},
    oid::{
        AUTHORITY_KEY_IDENTIFIER_OID, BASIC_CONSTRAINTS_OID, KEY_USAGE_OID,
        SUBJECT_ALTERNATIVE_NAME_OID, SUBJECT_DIRECTORY_ATTRIBUTES_OID, SUBJECT_KEY_IDENTIFIER_OID,
    },
};

use crate::{certificate::cert_is_self_signed, ops::CryptoOps, policy::PolicyError};

use super::Profile;

/// The RFC 5280 certificate profile.
#[derive(Default)]
pub struct RFC5280 {}

impl<B: CryptoOps> Profile<B> for RFC5280 {
    const CRITICAL_CA_EXTENSIONS: &'static [asn1::ObjectIdentifier] =
        &[BASIC_CONSTRAINTS_OID, KEY_USAGE_OID];
    const CRITICAL_EE_EXTENSIONS: &'static [asn1::ObjectIdentifier] =
        &[BASIC_CONSTRAINTS_OID, SUBJECT_ALTERNATIVE_NAME_OID];

    fn permits_basic(&self, ops: &B, cert: &Certificate) -> Result<(), PolicyError> {
        let extensions = cert.extensions()?;

        // 4.1.1.1: tbsCertificate
        // No checks required.

        // 4.1.1.2 / 4.1.2.3: signatureAlgorithm / TBS Certificate Signature
        // The top-level signatureAlgorithm and TBSCert signature algorithm
        // MUST match.
        if cert.signature_alg != cert.tbs_cert.signature_alg {
            return Err("mismatch between signatureAlgorithm and SPKI algorithm".into());
        }

        // 4.1.1.3: signatureValue
        // No checks required.

        // 4.1.2.1: Version
        // No checks required; implementations SHOULD be prepared to accept
        // any version certificate.

        // 4.1.2.2: Serial Number
        // Conforming CAs MUST NOT use serial numbers longer than 20 octets.
        // NOTE: In practice, this requires us to check for an encoding of
        // 21 octets, since some CAs generate 20 bytes of randomness and
        // then forget to check whether that number would be negative, resulting
        // in a 21-byte encoding.
        if !(1..=21).contains(&cert.tbs_cert.serial.as_bytes().len()) {
            return Err("certificate must have a serial between 1 and 20 octets".into());
        }

        // 4.1.2.3: Signature
        // See check under 4.1.1.2.

        // 4.1.2.4: Issuer
        // The issuer MUST be a non-empty distinguished name.
        if cert.issuer().is_empty() {
            return Err("certificate must have a non-empty Issuer".into());
        }

        // 4.1.2.5: Validity
        // Validity dates before 2050 MUST be encoded as UTCTime;
        // dates in or after 2050 MUST be encoded as GeneralizedTime.
        // TODO: The existing `tbs_cert.validity` types don't expose this
        // underlying detail. This check has no practical effect on the
        // correctness of the certificate, so it's pretty low priority.

        // 4.1.2.6: Subject
        // Devolved to `permits_ca` and `permits_ee`.

        // 4.1.2.7: Subject Public Key Info
        // No checks required.

        // 4.1.2.8: Unique Identifiers
        // These fields MUST only appear if the certificate version is 2 or 3.
        // TODO: Check this.

        // 4.1.2.9: Extensions
        // This field must MUST only appear if the certificate version is 3,
        // and it MUST be non-empty if present.
        // TODO: Check this.

        // 4.2.1.1: Authority Key Identifier
        // Certificates MUST have an AuthorityKeyIdentifier, it MUST contain
        // the keyIdentifier field, and it MUST NOT be critical.
        // The exception to this is self-signed certificates, which MAY
        // omit the AuthorityKeyIdentifier.
        if let Some(aki) = extensions.get_extension(&AUTHORITY_KEY_IDENTIFIER_OID) {
            if aki.critical {
                return Err("AuthorityKeyIdentifier must not be marked critical".into());
            }

            let aki: AuthorityKeyIdentifier = aki.value()?;
            if aki.key_identifier.is_none() {
                return Err("AuthorityKeyIdentifier.keyIdentifier must be present".into());
            }
        } else if !cert_is_self_signed(cert, ops) {
            return Err(
                "certificates must have a AuthorityKeyIdentifier unless self-signed".into(),
            );
        }

        // 4.2.1.2: Subject Key Identifier
        // Developed to `permits_ca`.

        // 4.2.1.3: Key Usage
        if let Some(key_usage) = extensions.get_extension(&KEY_USAGE_OID) {
            // KeyUsage must have at least one bit asserted, if present.
            let key_usage: KeyUsage = key_usage.value()?;
            if key_usage.is_zeroed() {
                return Err("KeyUsage must have at least one usage asserted, when present".into());
            }

            // encipherOnly or decipherOnly without keyAgreement is not well defined.
            // TODO: Check on a policy basis instead?
            if !key_usage.key_agreement()
                && (key_usage.encipher_only() || key_usage.decipher_only())
            {
                return Err(
                    "KeyUsage encipherOnly and decipherOnly can only be true when keyAgreement is true"
                        .into(),
                );
            }
        }

        // 4.2.1.4: Certificate Policies
        // No checks required.

        // 4.2.1.5: Policy Mappings
        // No checks required.

        // 4.2.1.8: Subject Directory Attributes
        // Conforming CAs MUST mark this extension as non-critical.
        if extensions
            .get_extension(&SUBJECT_DIRECTORY_ATTRIBUTES_OID)
            .map_or(false, |e| e.critical)
        {
            return Err("SubjectDirectoryAttributes must not be marked critical".into());
        }

        Ok(())
    }

    fn permits_ca(&self, _ops: &B, cert: &Certificate) -> Result<(), PolicyError> {
        let extensions = cert.extensions()?;

        // 4.1.2.6: Subject
        // CA certificates MUST have a subject populated with a non-empty distinguished name.
        if cert.subject().is_empty() {
            return Err("CA certificate must have a non-empty Subject".into());
        }

        // 4.2:
        // CA certificates must contain a few core extensions. This implies
        // that the CA certificate must be a v3 certificate, since earlier
        // versions lack extensions entirely.
        if cert.tbs_cert.version != 2 {
            return Err("CA certificate must be an X509v3 certificate".into());
        }

        // 4.2.1.2:
        // CA certificates MUST have a SubjectKeyIdentifier and it MUST NOT be
        // critical.
        if let Some(ski) = extensions.get_extension(&SUBJECT_KEY_IDENTIFIER_OID) {
            if ski.critical {
                return Err(
                    "SubjectKeyIdentifier must not be marked critical in a CA Certificate".into(),
                );
            }
        } else {
            return Err("store certificates must have a SubjectKeyIdentifier extension".into());
        }

        // 4.2.1.3:
        // CA certificates MUST have a KeyUsage, it SHOULD be critical,
        // and it MUST have `keyCertSign` asserted.
        if let Some(key_usage) = extensions.get_extension(&KEY_USAGE_OID) {
            // TODO: Check `key_usage.critical` on a policy basis here?

            let key_usage: KeyUsage = key_usage.value()?;

            if !key_usage.key_cert_sign() {
                return Err("KeyUsage.keyCertSign must be asserted in a CA certificate".into());
            }
        } else {
            return Err("CA certificates must have a KeyUsage extension".into());
        }

        // 4.2.1.9: Basic Constraints
        // CA certificates MUST have a BasicConstraints, it MUST be critical,
        // and it MUST have `cA` asserted.
        if let Some(basic_constraints) = extensions.get_extension(&BASIC_CONSTRAINTS_OID) {
            if !basic_constraints.critical {
                return Err("BasicConstraints must be marked critical in a CA certificate".into());
            }

            let basic_constraints: BasicConstraints = basic_constraints.value()?;
            if !basic_constraints.ca {
                return Err("BasicConstraints.cA must be asserted in a CA certificate".into());
            }
        } else {
            return Err("CA certificates must have a BasicConstraints extension".into());
        }

        // 4.2.1.10: Name Constraints
        // If present, NameConstraints MUST be critical.

        // 4.2.1.11: Policy Constraints
        // If present, PolicyConstraints MUST be critical.

        Ok(())
    }

    fn permits_ee(&self, _ops: &B, cert: &Certificate) -> Result<(), PolicyError> {
        let extensions = cert.extensions()?;

        // 4.1.2.6 / 4.2.1.6: Subject / Subject Alternative Name
        // EE certificates MAY have their subject in either the subject or subjectAltName.
        // If the subject is empty, then the subjectAltName MUST be marked critical.
        if cert.subject().is_empty() {
            match extensions.get_extension(&SUBJECT_ALTERNATIVE_NAME_OID) {
                Some(san) => {
                    if !san.critical {
                        return Err(
                            "EE without a subject must have a critical subjectAltName".into()
                        );
                    }

                    // TODO: There must be at least one SAN, and no SAN may be empty.
                }
                None => return Err("EE without a subject must have a subjectAltName".into()),
            }
        }

        // TODO: Pedantic: When the subject is non-empty, subjectAltName SHOULD
        // be marked as non-critical.

        // 4.2.1.5: Policy Mappings
        // The RFC is not clear on whether these may appear in EE certificates.

        // 4.2.1.10: Name Constraints
        // NameConstraints MUST NOT appear in EE certificates.

        // 4.2.1.11: Policy Constraints
        // The RFC is not clear on whether these may appear in EE certificates.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cert, tests::NullBackend};

    #[test]
    fn permits_basic_rejects_empty_issuer() {
        let root = cert!(
            "
-----BEGIN CERTIFICATE-----
MIIE5jCCAs6gAwIBAgIUbO+fY6YBZ8bJC/0fV6JbAdFJju8wDQYJKoZIhvcNAQEL
BQAwADAgFw02OTEyMzExOTAwMDBaGA8yOTY5MDUwMjE5MDAwMFowFzEVMBMGA1UE
AwwMZW1wdHktaXNzdWVyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
j3B3iwsFI2hmimdpQzxmr/rjZrDvgpyQ0jjaJkpGm0evuH++4xwixjhGr6tCA8+N
vV8bCFHBS2RsnPa6d1RYOQIkkZXgseiPYMnKdL6z4ZYFb+tu+9/aylk7215/5Zi0
JUTvunMhVA4ZzESqaxH4A74Yhd3vyyFy+7rd2/4l+XTkNHduf5PVV8gmM+8QeeWY
VsFzSpkk1dBHoJQk/V2wwbQLvWtFezRKGJwkBj+Ea8d9f01myngwDUca+CFguVx3
o+R2+xW88lAIha3luc4QozrGYPky6RkjJNmcgmXDW3HnieI92RETEQ5GICjN8xSa
/GN6QUmRK2A7USH2nFP8gb5tu5Yhi3c1tO0PoYHEUr8ooTx82XzfnwUxTAn1VmRf
TWnq+3bFD/hrsjR8FgWHT6cVlfoohv8wGz/LkrTjdHT709H6WLZ5ORS+ets4Lpvh
Ct986f2pI+zsn+WjwkHLhE4DZwymNhqwjYMYCbScIfQ05h4bDzgCyrY+kcTwU63s
b3/hrjvUlnLXd4IPX3KCfr+e5SLx4X9PbjNNp3IKUAAEvnX9n25vjbX300TG1LCi
lvNVP49klsqFImsQgmC0fCBQ8ZCR8SOchiJmVgOoxgtWKJyIztVcplU3T1dUSEPp
V2OS/1oZraMFzJ/w36TkwW3vAQ9zC+Wvw5m9geR+ZtECAwEAAaM/MD0wDwYDVR0T
AQH/BAUwAwEB/zALBgNVHQ8EBAMCAgQwHQYDVR0OBBYEFPMJDbpssGq1QLqy+5h2
Hg1rfSykMA0GCSqGSIb3DQEBCwUAA4ICAQB5Hw1K9zzjUci8j7D6aifFnChKw5cF
1aalgM37l3gj9/dUczR9v0iRqRJieeeWQUGvEMjpasMkWpMMzrV5Fhgn9bMPkK3J
ROAud+ny+djvgv0sLeh4la7Rfy5ejzLMTaVPffXIK6q3/DuVDiVCdQEOg+g4I72L
DYTqq6KqsC5zgWX6M76d5u6NJHp4SoPLCnGuWw8Ahd1w1UioEGf/+HER2rWABQLQ
sC3coxCISvvYdqmr4Q9uVW7/qVvijbslrVPMqYnoG51Je1idOnNpl/BFuGHESjll
iEqGkrtDjSp4J4SaMSK75oIbE6pS/0j+iGFF2yNp85P4jp9rc2w8/FUcCbA0kM/5
fPoNYhN379wxDS45IjgWYKiHH0y+j78gSZhUlTK+EW9xdxJCkTGxu/gmcPwea9c6
OP2F766kCpSI2cT8IB3oqHS4jeHtCJYNZLuHm0zjHTORaWcm5uTw4tUUT1XJL8Cr
Ru/tHox6+itTHwSeWCnT2GFHzzJTwAtvlFsSQaGBpIKuknL03+nKBH+iGIY/leow
1WaAoGc1Qc3s3B48ffeIN9QFP/FbIRz4jgxv8TKwdMsxI/eUmVEc9ne7U93wLU+d
7ZQ7uRwI/RUYLSoYkf+Nn9Ns64OjhcFfy028OwKginE/GRef66C8Brdh2lCRoCKm
QlkBGKnJujn8yg==
-----END CERTIFICATE-----
            "
        );

        let profile = RFC5280::default();
        let ops = NullBackend {};

        assert_eq!(
            profile.permits_basic(&ops, &root),
            Err(PolicyError::Other(
                "certificate must have a non-empty Issuer"
            ))
        );
    }
}
