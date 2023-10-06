// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::asn1::{oid_to_py_oid, py_oid_to_oid};
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types, x509};
use cryptography_x509::common::{Asn1ReadableOrWritable, AttributeTypeValue, RawTlv};
use cryptography_x509::extensions::{
    AccessDescription, DuplicateExtensionsError, Extension, Extensions, RawExtensions,
};
use cryptography_x509::name::{GeneralName, Name, NameReadable, OtherName, UnvalidatedIA5String};
use pyo3::types::IntoPyDict;
use pyo3::{IntoPy, ToPyObject};

/// Parse all sections in a PEM file and return the first matching section.
/// If no matching sections are found, return an error.
pub(crate) fn find_in_pem(
    data: &[u8],
    filter_fn: fn(&pem::Pem) -> bool,
    no_match_err: &'static str,
) -> Result<pem::Pem, CryptographyError> {
    let all_sections = pem::parse_many(data)?;
    if all_sections.is_empty() {
        return Err(CryptographyError::from(pem::PemError::MalformedFraming));
    }
    all_sections.into_iter().find(filter_fn).ok_or_else(|| {
        CryptographyError::from(pyo3::exceptions::PyValueError::new_err(no_match_err))
    })
}

pub(crate) fn encode_name<'p>(
    py: pyo3::Python<'p>,
    py_name: &'p pyo3::PyAny,
) -> pyo3::PyResult<Name<'p>> {
    let mut rdns = vec![];

    for py_rdn in py_name.getattr(pyo3::intern!(py, "rdns"))?.iter()? {
        let py_rdn = py_rdn?;
        let mut attrs = vec![];

        for py_attr in py_rdn.iter()? {
            attrs.push(encode_name_entry(py, py_attr?)?);
        }
        rdns.push(asn1::SetOfWriter::new(attrs));
    }
    Ok(Asn1ReadableOrWritable::new_write(
        asn1::SequenceOfWriter::new(rdns),
    ))
}

pub(crate) fn encode_name_entry<'p>(
    py: pyo3::Python<'p>,
    py_name_entry: &'p pyo3::PyAny,
) -> CryptographyResult<AttributeTypeValue<'p>> {
    let attr_type = py_name_entry.getattr(pyo3::intern!(py, "_type"))?;
    let tag = attr_type
        .getattr(pyo3::intern!(py, "value"))?
        .extract::<u8>()?;
    let value: &[u8] = if !attr_type.is(types::ASN1_TYPE_BIT_STRING.get(py)?) {
        let encoding = if attr_type.is(types::ASN1_TYPE_BMP_STRING.get(py)?) {
            "utf_16_be"
        } else if attr_type.is(types::ASN1_TYPE_UNIVERSAL_STRING.get(py)?) {
            "utf_32_be"
        } else {
            "utf8"
        };
        py_name_entry
            .getattr(pyo3::intern!(py, "value"))?
            .call_method1(pyo3::intern!(py, "encode"), (encoding,))?
            .extract()?
    } else {
        py_name_entry
            .getattr(pyo3::intern!(py, "value"))?
            .extract()?
    };
    let oid = py_oid_to_oid(py_name_entry.getattr(pyo3::intern!(py, "oid"))?)?;

    Ok(AttributeTypeValue {
        type_id: oid,
        value: RawTlv::new(asn1::Tag::from_bytes(&[tag])?.0, value),
    })
}

#[pyo3::prelude::pyfunction]
fn encode_name_bytes<'p>(
    py: pyo3::Python<'p>,
    py_name: &'p pyo3::PyAny,
) -> CryptographyResult<&'p pyo3::types::PyBytes> {
    let name = encode_name(py, py_name)?;
    let result = asn1::write_single(&name)?;
    Ok(pyo3::types::PyBytes::new(py, &result))
}

pub(crate) fn encode_general_names<'a>(
    py: pyo3::Python<'a>,
    py_gns: &'a pyo3::PyAny,
) -> Result<Vec<GeneralName<'a>>, CryptographyError> {
    let mut gns = vec![];
    for el in py_gns.iter()? {
        let gn = encode_general_name(py, el?)?;
        gns.push(gn)
    }
    Ok(gns)
}

pub(crate) fn encode_general_name<'a>(
    py: pyo3::Python<'a>,
    gn: &'a pyo3::PyAny,
) -> Result<GeneralName<'a>, CryptographyError> {
    let gn_type = gn.get_type().as_ref();
    let gn_value = gn.getattr(pyo3::intern!(py, "value"))?;

    if gn_type.is(types::DNS_NAME.get(py)?) {
        Ok(GeneralName::DNSName(UnvalidatedIA5String(
            gn_value.extract::<&str>()?,
        )))
    } else if gn_type.is(types::RFC822_NAME.get(py)?) {
        Ok(GeneralName::RFC822Name(UnvalidatedIA5String(
            gn_value.extract::<&str>()?,
        )))
    } else if gn_type.is(types::DIRECTORY_NAME.get(py)?) {
        let name = encode_name(py, gn_value)?;
        Ok(GeneralName::DirectoryName(name))
    } else if gn_type.is(types::OTHER_NAME.get(py)?) {
        Ok(GeneralName::OtherName(OtherName {
            type_id: py_oid_to_oid(gn.getattr(pyo3::intern!(py, "type_id"))?)?,
            value: asn1::parse_single(gn_value.extract::<&[u8]>()?).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "OtherName value must be valid DER: {:?}",
                    e
                ))
            })?,
        }))
    } else if gn_type.is(types::UNIFORM_RESOURCE_IDENTIFIER.get(py)?) {
        Ok(GeneralName::UniformResourceIdentifier(
            UnvalidatedIA5String(gn_value.extract::<&str>()?),
        ))
    } else if gn_type.is(types::IP_ADDRESS.get(py)?) {
        Ok(GeneralName::IPAddress(
            gn.call_method0(pyo3::intern!(py, "_packed"))?
                .extract::<&[u8]>()?,
        ))
    } else if gn_type.is(types::REGISTERED_ID.get(py)?) {
        let oid = py_oid_to_oid(gn_value)?;
        Ok(GeneralName::RegisteredID(oid))
    } else {
        Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Unsupported GeneralName type"),
        ))
    }
}

pub(crate) fn encode_access_descriptions<'a>(
    py: pyo3::Python<'a>,
    py_ads: &'a pyo3::PyAny,
) -> CryptographyResult<Vec<u8>> {
    let mut ads = vec![];
    for py_ad in py_ads.iter()? {
        let py_ad = py_ad?;
        let access_method = py_oid_to_oid(py_ad.getattr(pyo3::intern!(py, "access_method"))?)?;
        let access_location =
            encode_general_name(py, py_ad.getattr(pyo3::intern!(py, "access_location"))?)?;
        ads.push(AccessDescription {
            access_method,
            access_location,
        });
    }
    Ok(asn1::write_single(&asn1::SequenceOfWriter::new(ads))?)
}

pub(crate) fn parse_name<'p>(
    py: pyo3::Python<'p>,
    name: &NameReadable<'_>,
) -> Result<&'p pyo3::PyAny, CryptographyError> {
    let py_rdns = pyo3::types::PyList::empty(py);
    for rdn in name.clone() {
        let py_rdn = parse_rdn(py, &rdn)?;
        py_rdns.append(py_rdn)?;
    }
    Ok(types::NAME.get(py)?.call1((py_rdns,))?)
}

fn parse_name_attribute(
    py: pyo3::Python<'_>,
    attribute: AttributeTypeValue<'_>,
) -> Result<pyo3::PyObject, CryptographyError> {
    let oid = oid_to_py_oid(py, &attribute.type_id)?.to_object(py);
    let tag_val = attribute
        .value
        .tag()
        .as_u8()
        .ok_or_else(|| {
            CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                "Long-form tags are not supported in NameAttribute values",
            ))
        })?
        .to_object(py);
    let py_tag = types::ASN1_TYPE_TO_ENUM.get(py)?.get_item(tag_val)?;
    let py_data = match attribute.value.tag().as_u8() {
        // BitString tag value
        Some(3) => pyo3::types::PyBytes::new(py, attribute.value.data()),
        // BMPString tag value
        Some(30) => {
            let py_bytes = pyo3::types::PyBytes::new(py, attribute.value.data());
            py_bytes.call_method1(pyo3::intern!(py, "decode"), ("utf_16_be",))?
        }
        // UniversalString
        Some(28) => {
            let py_bytes = pyo3::types::PyBytes::new(py, attribute.value.data());
            py_bytes.call_method1(pyo3::intern!(py, "decode"), ("utf_32_be",))?
        }
        _ => {
            let parsed = std::str::from_utf8(attribute.value.data())
                .map_err(|_| asn1::ParseError::new(asn1::ParseErrorKind::InvalidValue))?;
            pyo3::types::PyString::new(py, parsed)
        }
    };
    let kwargs = [("_validate", false)].into_py_dict(py);
    Ok(types::NAME_ATTRIBUTE
        .get(py)?
        .call((oid, py_data, py_tag), Some(kwargs))?
        .to_object(py))
}

pub(crate) fn parse_rdn<'a>(
    py: pyo3::Python<'_>,
    rdn: &asn1::SetOf<'a, AttributeTypeValue<'a>>,
) -> Result<pyo3::PyObject, CryptographyError> {
    let py_attrs = pyo3::types::PyList::empty(py);
    for attribute in rdn.clone() {
        let na = parse_name_attribute(py, attribute)?;
        py_attrs.append(na)?;
    }
    Ok(types::RELATIVE_DISTINGUISHED_NAME
        .get(py)?
        .call1((py_attrs,))?
        .to_object(py))
}

pub(crate) fn parse_general_name(
    py: pyo3::Python<'_>,
    gn: GeneralName<'_>,
) -> Result<pyo3::PyObject, CryptographyError> {
    let py_gn = match gn {
        GeneralName::OtherName(data) => {
            let oid = oid_to_py_oid(py, &data.type_id)?.to_object(py);
            types::OTHER_NAME
                .get(py)?
                .call1((oid, data.value.full_data()))?
                .to_object(py)
        }
        GeneralName::RFC822Name(data) => types::RFC822_NAME
            .get(py)?
            .call_method1(pyo3::intern!(py, "_init_without_validation"), (data.0,))?
            .to_object(py),
        GeneralName::DNSName(data) => types::DNS_NAME
            .get(py)?
            .call_method1(pyo3::intern!(py, "_init_without_validation"), (data.0,))?
            .to_object(py),
        GeneralName::DirectoryName(data) => {
            let py_name = parse_name(py, data.unwrap_read())?;
            types::DIRECTORY_NAME
                .get(py)?
                .call1((py_name,))?
                .to_object(py)
        }
        GeneralName::UniformResourceIdentifier(data) => types::UNIFORM_RESOURCE_IDENTIFIER
            .get(py)?
            .call_method1(pyo3::intern!(py, "_init_without_validation"), (data.0,))?
            .to_object(py),
        GeneralName::IPAddress(data) => {
            if data.len() == 4 || data.len() == 16 {
                let addr = types::IPADDRESS_IPADDRESS.get(py)?.call1((data,))?;
                types::IP_ADDRESS.get(py)?.call1((addr,))?.to_object(py)
            } else {
                // if it's not an IPv4 or IPv6 we assume it's an IPNetwork and
                // verify length in this function.
                create_ip_network(py, data)?
            }
        }
        GeneralName::RegisteredID(data) => {
            let oid = oid_to_py_oid(py, &data)?.to_object(py);
            types::REGISTERED_ID.get(py)?.call1((oid,))?.to_object(py)
        }
        _ => {
            return Err(CryptographyError::from(
                exceptions::UnsupportedGeneralNameType::new_err(
                    "x400Address/EDIPartyName are not supported types",
                ),
            ))
        }
    };
    Ok(py_gn)
}

pub(crate) fn parse_general_names<'a>(
    py: pyo3::Python<'_>,
    gn_seq: &asn1::SequenceOf<'a, GeneralName<'a>>,
) -> Result<pyo3::PyObject, CryptographyError> {
    let gns = pyo3::types::PyList::empty(py);
    for gn in gn_seq.clone() {
        let py_gn = parse_general_name(py, gn)?;
        gns.append(py_gn)?;
    }
    Ok(gns.to_object(py))
}

fn create_ip_network(
    py: pyo3::Python<'_>,
    data: &[u8],
) -> Result<pyo3::PyObject, CryptographyError> {
    let prefix = match data.len() {
        8 => {
            let num = u32::from_be_bytes(data[4..].try_into().unwrap());
            ipv4_netmask(num)
        }
        32 => {
            let num = u128::from_be_bytes(data[16..].try_into().unwrap());
            ipv6_netmask(num)
        }
        _ => Err(CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
            format!("Invalid IPNetwork, must be 8 bytes for IPv4 and 32 bytes for IPv6. Found length: {}", data.len()),
        ))),
    };
    let base = types::IPADDRESS_IPADDRESS
        .get(py)?
        .call1((pyo3::types::PyBytes::new(py, &data[..data.len() / 2]),))?;
    let net = format!(
        "{}/{}",
        base.getattr(pyo3::intern!(py, "exploded"))?
            .extract::<&str>()?,
        prefix?
    );
    let addr = types::IPADDRESS_IPNETWORK.get(py)?.call1((net,))?;
    Ok(types::IP_ADDRESS.get(py)?.call1((addr,))?.to_object(py))
}

fn ipv4_netmask(num: u32) -> Result<u32, CryptographyError> {
    if num.leading_ones() + num.trailing_zeros() != 32 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Invalid netmask"),
        ));
    }
    Ok((!num).leading_zeros())
}

fn ipv6_netmask(num: u128) -> Result<u32, CryptographyError> {
    if num.leading_ones() + num.trailing_zeros() != 128 {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Invalid netmask"),
        ));
    }
    Ok((!num).leading_zeros())
}

pub(crate) fn parse_and_cache_extensions<
    'p,
    F: Fn(&Extension<'_>) -> Result<Option<&'p pyo3::PyAny>, CryptographyError>,
>(
    py: pyo3::Python<'p>,
    cached_extensions: &pyo3::once_cell::GILOnceCell<pyo3::PyObject>,
    raw_extensions: &Option<RawExtensions<'_>>,
    parse_ext: F,
) -> pyo3::PyResult<pyo3::PyObject> {
    cached_extensions
        .get_or_try_init(py, || {
            let extensions = match Extensions::from_raw_extensions(raw_extensions.as_ref()) {
                Ok(extensions) => extensions,
                Err(DuplicateExtensionsError(oid)) => {
                    let oid_obj = oid_to_py_oid(py, &oid)?;
                    return Err(exceptions::DuplicateExtension::new_err((
                        format!("Duplicate {} extension found", &oid),
                        oid_obj.into_py(py),
                    )));
                }
            };

            let exts = pyo3::types::PyList::empty(py);
            for raw_ext in extensions.iter() {
                let oid_obj = oid_to_py_oid(py, &raw_ext.extn_id)?;

                let extn_value = match parse_ext(&raw_ext)? {
                    Some(e) => e,
                    None => types::UNRECOGNIZED_EXTENSION
                        .get(py)?
                        .call1((oid_obj, raw_ext.extn_value))?,
                };
                let ext_obj =
                    types::EXTENSION
                        .get(py)?
                        .call1((oid_obj, raw_ext.critical, extn_value))?;
                exts.append(ext_obj)?;
            }
            Ok(types::EXTENSIONS.get(py)?.call1((exts,))?.to_object(py))
        })
        .map(|p| p.clone_ref(py))
}

pub(crate) fn encode_extensions<
    'p,
    F: Fn(
        pyo3::Python<'_>,
        &asn1::ObjectIdentifier,
        &pyo3::PyAny,
    ) -> CryptographyResult<Option<Vec<u8>>>,
>(
    py: pyo3::Python<'p>,
    py_exts: &'p pyo3::PyAny,
    encode_ext: F,
) -> pyo3::PyResult<Option<RawExtensions<'p>>> {
    let mut exts = vec![];
    for py_ext in py_exts.iter()? {
        let py_ext = py_ext?;
        let oid = py_oid_to_oid(py_ext.getattr(pyo3::intern!(py, "oid"))?)?;

        let ext_val = py_ext.getattr(pyo3::intern!(py, "value"))?;
        if ext_val.is_instance(types::UNRECOGNIZED_EXTENSION.get(py)?)? {
            exts.push(Extension {
                extn_id: oid,
                critical: py_ext.getattr(pyo3::intern!(py, "critical"))?.extract()?,
                extn_value: ext_val
                    .getattr(pyo3::intern!(py, "value"))?
                    .extract::<&[u8]>()?,
            });
            continue;
        }
        match encode_ext(py, &oid, ext_val)? {
            Some(data) => {
                // TODO: extra copy
                let py_data = pyo3::types::PyBytes::new(py, &data);
                exts.push(Extension {
                    extn_id: oid,
                    critical: py_ext.getattr(pyo3::intern!(py, "critical"))?.extract()?,
                    extn_value: py_data.as_bytes(),
                })
            }
            None => {
                return Err(pyo3::exceptions::PyNotImplementedError::new_err(format!(
                    "Extension not supported: {}",
                    oid
                )))
            }
        }
    }
    if exts.is_empty() {
        return Ok(None);
    }
    Ok(Some(Asn1ReadableOrWritable::new_write(
        asn1::SequenceOfWriter::new(exts),
    )))
}

#[pyo3::prelude::pyfunction]
fn encode_extension_value<'p>(
    py: pyo3::Python<'p>,
    py_ext: &'p pyo3::PyAny,
) -> pyo3::PyResult<&'p pyo3::types::PyBytes> {
    let oid = py_oid_to_oid(py_ext.getattr(pyo3::intern!(py, "oid"))?)?;

    if let Some(data) = x509::extensions::encode_extension(py, &oid, py_ext)? {
        // TODO: extra copy
        let py_data = pyo3::types::PyBytes::new(py, &data);
        return Ok(py_data);
    }

    Err(pyo3::exceptions::PyNotImplementedError::new_err(format!(
        "Extension not supported: {}",
        oid
    )))
}

pub(crate) fn datetime_to_py<'p>(
    py: pyo3::Python<'p>,
    dt: &asn1::DateTime,
) -> pyo3::PyResult<&'p pyo3::PyAny> {
    types::DATETIME_DATETIME.get(py)?.call1((
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
    ))
}

pub(crate) fn datetime_to_py_utc<'p>(
    py: pyo3::Python<'p>,
    dt: &asn1::DateTime,
) -> pyo3::PyResult<&'p pyo3::PyAny> {
    let timezone = types::DATETIME_TIMEZONE_UTC.get(py)?;
    types::DATETIME_DATETIME.get(py)?.call1((
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        0,
        timezone,
    ))
}

pub(crate) fn py_to_datetime(
    py: pyo3::Python<'_>,
    val: &pyo3::PyAny,
) -> pyo3::PyResult<asn1::DateTime> {
    Ok(asn1::DateTime::new(
        val.getattr(pyo3::intern!(py, "year"))?.extract()?,
        val.getattr(pyo3::intern!(py, "month"))?.extract()?,
        val.getattr(pyo3::intern!(py, "day"))?.extract()?,
        val.getattr(pyo3::intern!(py, "hour"))?.extract()?,
        val.getattr(pyo3::intern!(py, "minute"))?.extract()?,
        val.getattr(pyo3::intern!(py, "second"))?.extract()?,
    )
    .unwrap())
}

pub(crate) fn datetime_now(py: pyo3::Python<'_>) -> pyo3::PyResult<asn1::DateTime> {
    let utc = types::DATETIME_TIMEZONE_UTC.get(py)?;

    py_to_datetime(
        py,
        types::DATETIME_DATETIME
            .get(py)?
            .call_method1(pyo3::intern!(py, "now"), (utc,))?,
    )
}

pub(crate) fn add_to_module(module: &pyo3::prelude::PyModule) -> pyo3::PyResult<()> {
    module.add_function(pyo3::wrap_pyfunction!(encode_extension_value, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(encode_name_bytes, module)?)?;

    Ok(())
}
