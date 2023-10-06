// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::error::{CryptographyError, CryptographyResult};
use crate::types;
use asn1::SimpleAsn1Readable;
use cryptography_x509::certificate::Certificate;
use cryptography_x509::common::{DssSignature, SubjectPublicKeyInfo, Time};
use cryptography_x509::name::Name;
use pyo3::basic::CompareOp;
use pyo3::types::IntoPyDict;
use pyo3::ToPyObject;

pub(crate) fn py_oid_to_oid(py_oid: &pyo3::PyAny) -> pyo3::PyResult<asn1::ObjectIdentifier> {
    Ok(py_oid
        .downcast::<pyo3::PyCell<crate::oid::ObjectIdentifier>>()?
        .borrow()
        .oid
        .clone())
}

pub(crate) fn oid_to_py_oid<'p>(
    py: pyo3::Python<'p>,
    oid: &asn1::ObjectIdentifier,
) -> pyo3::PyResult<&'p pyo3::PyAny> {
    Ok(pyo3::Py::new(py, crate::oid::ObjectIdentifier { oid: oid.clone() })?.into_ref(py))
}

#[pyo3::prelude::pyfunction]
fn parse_spki_for_data(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> Result<pyo3::PyObject, CryptographyError> {
    let spki = asn1::parse_single::<SubjectPublicKeyInfo<'_>>(data)?;
    if spki.subject_public_key.padding_bits() != 0 {
        return Err(pyo3::exceptions::PyValueError::new_err("Invalid public key encoding").into());
    }

    Ok(pyo3::types::PyBytes::new(py, spki.subject_public_key.as_bytes()).to_object(py))
}

pub(crate) fn big_byte_slice_to_py_int<'p>(
    py: pyo3::Python<'p>,
    v: &'_ [u8],
) -> pyo3::PyResult<&'p pyo3::PyAny> {
    let int_type = py.get_type::<pyo3::types::PyLong>();
    let kwargs = [("signed", true)].into_py_dict(py);
    int_type.call_method(pyo3::intern!(py, "from_bytes"), (v, "big"), Some(kwargs))
}

#[pyo3::prelude::pyfunction]
fn decode_dss_signature(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> Result<pyo3::PyObject, CryptographyError> {
    let sig = asn1::parse_single::<DssSignature<'_>>(data)?;

    Ok((
        big_byte_slice_to_py_int(py, sig.r.as_bytes())?,
        big_byte_slice_to_py_int(py, sig.s.as_bytes())?,
    )
        .to_object(py))
}

pub(crate) fn py_uint_to_big_endian_bytes<'p>(
    py: pyo3::Python<'p>,
    v: &'p pyo3::types::PyLong,
) -> pyo3::PyResult<&'p [u8]> {
    let zero = (0).to_object(py);
    if v.rich_compare(zero, CompareOp::Lt)?.is_true()? {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "Negative integers are not supported",
        ));
    }

    // Round the length up so that we prefix an extra \x00. This ensures that
    // integers that'd have the high bit set in their first octet are not
    // encoded as negative in DER.
    let n = v
        .call_method0(pyo3::intern!(py, "bit_length"))?
        .extract::<usize>()?
        / 8
        + 1;
    v.call_method1(pyo3::intern!(py, "to_bytes"), (n, "big"))?
        .extract()
}

pub(crate) fn encode_der_data<'p>(
    py: pyo3::Python<'p>,
    pem_tag: String,
    data: Vec<u8>,
    encoding: &'p pyo3::PyAny,
) -> CryptographyResult<&'p pyo3::types::PyBytes> {
    if encoding.is(types::ENCODING_DER.get(py)?) {
        Ok(pyo3::types::PyBytes::new(py, &data))
    } else if encoding.is(types::ENCODING_PEM.get(py)?) {
        Ok(pyo3::types::PyBytes::new(
            py,
            &pem::encode_config(
                &pem::Pem::new(pem_tag, data),
                pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
            )
            .into_bytes(),
        ))
    } else {
        Err(
            pyo3::exceptions::PyTypeError::new_err("encoding must be Encoding.DER or Encoding.PEM")
                .into(),
        )
    }
}

#[pyo3::prelude::pyfunction]
fn encode_dss_signature(
    py: pyo3::Python<'_>,
    r: &pyo3::types::PyLong,
    s: &pyo3::types::PyLong,
) -> CryptographyResult<pyo3::PyObject> {
    let sig = DssSignature {
        r: asn1::BigUint::new(py_uint_to_big_endian_bytes(py, r)?).unwrap(),
        s: asn1::BigUint::new(py_uint_to_big_endian_bytes(py, s)?).unwrap(),
    };
    let result = asn1::write_single(&sig)?;
    Ok(pyo3::types::PyBytes::new(py, &result).to_object(py))
}

#[pyo3::prelude::pyclass(frozen, module = "cryptography.hazmat.bindings._rust.asn1")]
struct TestCertificate {
    #[pyo3(get)]
    not_before_tag: u8,
    #[pyo3(get)]
    not_after_tag: u8,
    #[pyo3(get)]
    issuer_value_tags: Vec<u8>,
    #[pyo3(get)]
    subject_value_tags: Vec<u8>,
}

fn parse_name_value_tags(rdns: &Name<'_>) -> Vec<u8> {
    let mut tags = vec![];
    for rdn in rdns.unwrap_read().clone() {
        let mut attributes = rdn.collect::<Vec<_>>();
        assert_eq!(attributes.len(), 1);

        tags.push(attributes.pop().unwrap().value.tag().as_u8().unwrap());
    }
    tags
}

fn time_tag(t: &Time) -> u8 {
    match t {
        Time::UtcTime(_) => asn1::UtcTime::TAG.as_u8().unwrap(),
        Time::GeneralizedTime(_) => asn1::GeneralizedTime::TAG.as_u8().unwrap(),
    }
}

#[pyo3::prelude::pyfunction]
fn test_parse_certificate(data: &[u8]) -> Result<TestCertificate, CryptographyError> {
    let cert = asn1::parse_single::<Certificate<'_>>(data)?;

    Ok(TestCertificate {
        not_before_tag: time_tag(&cert.tbs_cert.validity.not_before),
        not_after_tag: time_tag(&cert.tbs_cert.validity.not_after),
        issuer_value_tags: parse_name_value_tags(&cert.tbs_cert.issuer),
        subject_value_tags: parse_name_value_tags(&cert.tbs_cert.subject),
    })
}

pub(crate) fn create_submodule(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let submod = pyo3::prelude::PyModule::new(py, "asn1")?;
    submod.add_function(pyo3::wrap_pyfunction!(parse_spki_for_data, submod)?)?;

    submod.add_function(pyo3::wrap_pyfunction!(decode_dss_signature, submod)?)?;
    submod.add_function(pyo3::wrap_pyfunction!(encode_dss_signature, submod)?)?;

    submod.add_function(pyo3::wrap_pyfunction!(test_parse_certificate, submod)?)?;

    Ok(submod)
}
