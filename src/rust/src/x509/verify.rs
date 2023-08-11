// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::certificate::Certificate;
use cryptography_x509_validation::{
    ops::CryptoOps,
    policy::{profile::webpki::WebPKI, Policy, Subject, RFC5280},
    trust_store::Store,
    types::{DNSName, IPAddress},
};

use crate::error::CryptographyResult;

use super::{
    certificate::{Certificate as PyCertificate, OwnedCertificate},
    common::datetime_now,
    py_to_datetime, sign,
};

pub(crate) struct PyCryptoOps {}

impl CryptoOps for PyCryptoOps {
    // NOTE: This "key" type also carries any error that might happen
    // during key serialization/loading. This isn't ideal but also is
    // not a significant issue, since its only use is in checking
    // another certificate's signature (where an error means that the
    // signature check fails trivially).
    type Key = pyo3::Py<pyo3::PyAny>;

    fn public_key(&self, cert: &Certificate<'_>) -> Option<Self::Key> {
        pyo3::Python::with_gil(|py| -> Option<Self::Key> {
            // This makes an unnecessary copy. It'd be nice to get rid of it.
            let spki_der =
                pyo3::types::PyBytes::new(py, &asn1::write_single(&cert.tbs_cert.spki).ok()?);
            Some(
                py.import(pyo3::intern!(
                    py,
                    "cryptography.hazmat.primitives.serialization"
                ))
                .ok()?
                .getattr(pyo3::intern!(py, "load_der_public_key"))
                .ok()?
                .call1((spki_der,))
                .ok()?
                .into(),
            )
        })
    }

    fn is_signed_by(&self, cert: &Certificate<'_>, key: Self::Key) -> bool {
        pyo3::Python::with_gil(|py| -> CryptographyResult<()> {
            sign::verify_signature_with_signature_algorithm(
                py,
                key.as_ref(py),
                &cert.signature_alg,
                cert.signature.as_bytes(),
                &asn1::write_single(&cert.tbs_cert)?,
            )
        })
        .is_ok()
    }
}

// NOTE: pyO3 classes can't be generic over a trait, which our profile API requires.
// Our workaround is to unfold each profile variant in this enum, which produces
// a small amount of (internal) duplication in exchange for the monomorphism that
// pyO3 needs.
enum FixedPolicy<'a> {
    RFC5280(Policy<'a, PyCryptoOps, RFC5280>),
    WebPKI(Policy<'a, PyCryptoOps, WebPKI>),
}

/// This enum exists solely to provide heterogeneously typed ownership for `OwnedPolicy`.
enum SubjectOwner {
    // NOTE: This is ugly, but is effectively the easiest way to use a uniform
    // `OwnedPolicy` API when policies aren't strictly required to contain a subject.
    None,
    // TODO: Switch this to `Py<PyString>` once Pyo3's `to_str()` preserves a
    // lifetime relationship between an a `PyString` and its borrowed `&str`
    // reference in all limited API builds. PyO3 can't currently do that in
    // older limited API builds because it needs `PyUnicode_AsUTF8AndSize` to do
    // so, which was only stabilized with 3.10.
    DNSName(String),
    IPAddress(pyo3::Py<pyo3::types::PyBytes>),
}

self_cell::self_cell!(
    struct OwnedPolicy {
        owner: SubjectOwner,

        #[covariant]
        dependent: FixedPolicy,
    }
);

#[pyo3::pyclass(name = "Policy", module = "cryptography.hazmat.bindings._rust.x509")]
struct PyPolicy(OwnedPolicy);

impl PyPolicy {
    fn as_policy(&self) -> &FixedPolicy<'_> {
        self.0.borrow_dependent()
    }
}

fn build_subject_owner<'p>(
    py: pyo3::Python<'p>,
    subject: pyo3::Py<pyo3::PyAny>,
) -> pyo3::PyResult<SubjectOwner> {
    let subject = subject.as_ref(py);

    if subject.is_none() {
        return Ok(SubjectOwner::None);
    }

    let x509_general_name_module =
        py.import(pyo3::intern!(py, "cryptography.x509.general_name"))?;
    let dns_name_class = x509_general_name_module.getattr(pyo3::intern!(py, "DNSName"))?;
    let ip_address_class = x509_general_name_module.getattr(pyo3::intern!(py, "IPAddress"))?;

    if subject.is_instance(dns_name_class)? {
        let value = subject
            .getattr(pyo3::intern!(py, "value"))?
            .downcast::<pyo3::types::PyString>()?;

        Ok(SubjectOwner::DNSName(value.to_str()?.to_owned()))
    } else if subject.is_instance(ip_address_class)? {
        let value = subject
            .getattr(pyo3::intern!(py, "packed"))?
            .downcast::<pyo3::types::PyBytes>()?;

        Ok(SubjectOwner::IPAddress(value.into()))
    } else {
        Err(pyo3::exceptions::PyTypeError::new_err(
            "unsupported subject type",
        ))
    }
}

fn build_subject<'a, 'p>(
    py: pyo3::Python<'p>,
    subject: &'a SubjectOwner,
) -> pyo3::PyResult<Option<Subject<'a>>> {
    match subject {
        SubjectOwner::None => Ok(None),
        SubjectOwner::DNSName(dns_name) => {
            let dns_name = DNSName::new(dns_name)
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("invalid domain name"))?;

            Ok(Some(Subject::DNS(dns_name)))
        }
        SubjectOwner::IPAddress(ip_addr) => {
            let ip_addr = IPAddress::from_bytes(ip_addr.as_bytes(py))
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("invalid IP address"))?;

            Ok(Some(Subject::IP(ip_addr)))
        }
    }
}

#[pyo3::prelude::pyfunction]
fn create_policy<'p>(
    py: pyo3::Python<'p>,
    profile: &pyo3::PyAny,
    subject: pyo3::Py<pyo3::PyAny>,
    time: Option<&pyo3::PyAny>,
) -> pyo3::PyResult<PyPolicy> {
    let x509_module = py.import(pyo3::intern!(py, "cryptography.x509.verification"))?;
    let rfc5280 = x509_module
        .getattr(pyo3::intern!(py, "Profile"))?
        .get_item(pyo3::intern!(py, "RFC5280"))?;
    let webpki = x509_module
        .getattr(pyo3::intern!(py, "Profile"))?
        .get_item(pyo3::intern!(py, "WebPKI"))?;

    let time = match time {
        Some(time) => py_to_datetime(py, time)?,
        None => datetime_now(py)?,
    };

    let subject_owner = build_subject_owner(py, subject)?;
    let policy = if profile.eq(rfc5280)? {
        OwnedPolicy::try_new(subject_owner, |subject_owner| {
            let subject = build_subject(py, subject_owner)?;
            Ok::<FixedPolicy<'_>, pyo3::PyErr>(FixedPolicy::RFC5280(Policy::new(
                PyCryptoOps {},
                subject,
                time,
            )))
        })?
    } else if profile.eq(webpki)? {
        OwnedPolicy::try_new(subject_owner, |subject_owner| {
            let subject = build_subject(py, subject_owner)?;
            Ok::<FixedPolicy<'_>, pyo3::PyErr>(FixedPolicy::WebPKI(Policy::new(
                PyCryptoOps {},
                subject,
                time,
            )))
        })?
    } else {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "invalid profile specified; expected a Profile variant",
        ));
    };

    Ok(PyPolicy(policy))
}

#[pyo3::prelude::pyfunction]
fn verify<'p>(
    py: pyo3::Python<'p>,
    leaf: &PyCertificate,
    policy: &PyPolicy,
    intermediates: &'p pyo3::types::PyList,
    store: &'p pyo3::PyAny,
) -> CryptographyResult<Vec<PyCertificate>> {
    let intermediates = intermediates
        .iter()
        .map(|o| o.extract::<pyo3::PyRef<'p, PyCertificate>>())
        .collect::<Result<Vec<_>, _>>()?;
    let store_certs = store
        .getattr(pyo3::intern!(py, "_certs"))?
        .downcast::<pyo3::types::PyList>()?
        .iter()
        .map(|o| o.extract::<pyo3::PyRef<'p, PyCertificate>>())
        .collect::<Result<Vec<_>, _>>()?;
    let store = Store::new(store_certs.iter().map(|t| t.raw.borrow_dependent().clone()));

    // TODO: This manual monomorphization over each policy type is pretty ugly;
    // maybe fix it.
    let chain = match &policy.as_policy() {
        FixedPolicy::RFC5280(policy) => cryptography_x509_validation::verify(
            leaf.raw.borrow_dependent(),
            intermediates
                .iter()
                .map(|i| i.raw.borrow_dependent().clone()),
            policy,
            &store,
        ),
        FixedPolicy::WebPKI(policy) => cryptography_x509_validation::verify(
            leaf.raw.borrow_dependent(),
            intermediates
                .iter()
                .map(|i| i.raw.borrow_dependent().clone()),
            policy,
            &store,
        ),
    }
    .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("validation failed: {e:?}")))?;

    // TODO: Optimize this? Turning a Certificate back into a PyCertificate
    // involves a full round-trip back through DER, which isn't ideal.
    chain
        .iter()
        .map(|c| {
            let raw = pyo3::types::PyBytes::new(py, &asn1::write_single(c)?);
            Ok(PyCertificate {
                raw: OwnedCertificate::try_new(raw.into(), |raw| {
                    asn1::parse_single(raw.as_bytes(py))
                })?,
                cached_extensions: pyo3::once_cell::GILOnceCell::new(),
            })
        })
        .collect()
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_class::<PyPolicy>()?;
    module.add_function(pyo3::wrap_pyfunction!(verify, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(create_policy, module)?)?;

    Ok(())
}
