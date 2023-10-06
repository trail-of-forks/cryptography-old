// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::backend::hashes::already_finalized_error;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_LIBRESSL))]
struct Poly1305Boring {
    context: cryptography_openssl::poly1305::Poly1305State,
}

#[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_LIBRESSL))]
impl Poly1305Boring {
    fn new(key: CffiBuf<'_>) -> CryptographyResult<Poly1305Boring> {
        if key.as_bytes().len() != 32 {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("A poly1305 key is 32 bytes long"),
            ));
        }
        let ctx = cryptography_openssl::poly1305::Poly1305State::new(key.as_bytes());
        Ok(Poly1305Boring { context: ctx })
    }

    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        self.context.update(data.as_bytes());
        Ok(())
    }
    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let result = pyo3::types::PyBytes::new_with(py, 16usize, |b| {
            self.context.finalize(b.as_mut());
            Ok(())
        })?;
        Ok(result)
    }
}

#[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
struct Poly1305Open {
    signer: openssl::sign::Signer<'static>,
}

#[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
impl Poly1305Open {
    fn new(key: CffiBuf<'_>) -> CryptographyResult<Poly1305Open> {
        if cryptography_openssl::fips::is_enabled() {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "poly1305 is not supported by this version of OpenSSL.",
                    exceptions::Reasons::UNSUPPORTED_MAC,
                )),
            ));
        }

        let pkey = openssl::pkey::PKey::private_key_from_raw_bytes(
            key.as_bytes(),
            openssl::pkey::Id::POLY1305,
        )
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("A poly1305 key is 32 bytes long"))?;

        Ok(Poly1305Open {
            signer: openssl::sign::Signer::new_without_digest(&pkey).map_err(|_| {
                pyo3::exceptions::PyValueError::new_err("A poly1305 key is 32 bytes long")
            })?,
        })
    }
    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        let buf = data.as_bytes();
        self.signer.update(buf)?;
        Ok(())
    }
    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let result = pyo3::types::PyBytes::new_with(py, self.signer.len()?, |b| {
            let n = self.signer.sign(b).unwrap();
            assert_eq!(n, b.len());
            Ok(())
        })?;
        Ok(result)
    }
}

#[pyo3::prelude::pyclass(module = "cryptography.hazmat.bindings._rust.openssl.poly1305")]
struct Poly1305 {
    #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_LIBRESSL))]
    inner: Option<Poly1305Boring>,
    #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
    inner: Option<Poly1305Open>,
}

#[pyo3::pymethods]
impl Poly1305 {
    #[new]
    fn new(key: CffiBuf<'_>) -> CryptographyResult<Poly1305> {
        #[cfg(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_LIBRESSL))]
        return Ok(Poly1305 {
            inner: Some(Poly1305Boring::new(key)?),
        });
        #[cfg(not(any(CRYPTOGRAPHY_IS_LIBRESSL, CRYPTOGRAPHY_IS_BORINGSSL)))]
        return Ok(Poly1305 {
            inner: Some(Poly1305Open::new(key)?),
        });
    }

    #[staticmethod]
    fn generate_tag<'p>(
        py: pyo3::Python<'p>,
        key: CffiBuf<'_>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let mut p = Poly1305::new(key)?;
        p.update(data)?;
        p.finalize(py)
    }

    #[staticmethod]
    fn verify_tag(
        py: pyo3::Python<'_>,
        key: CffiBuf<'_>,
        data: CffiBuf<'_>,
        tag: &[u8],
    ) -> CryptographyResult<()> {
        let mut p = Poly1305::new(key)?;
        p.update(data)?;
        p.verify(py, tag)
    }

    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        self.inner
            .as_mut()
            .map_or(Err(already_finalized_error()), |b| b.update(data))
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<&'p pyo3::types::PyBytes> {
        let res = self
            .inner
            .as_mut()
            .map_or(Err(already_finalized_error()), |b| b.finalize(py));
        self.inner = None;

        res
    }

    fn verify(&mut self, py: pyo3::Python<'_>, signature: &[u8]) -> CryptographyResult<()> {
        let actual = self.finalize(py)?.as_bytes();
        if actual.len() != signature.len() || !openssl::memcmp::eq(actual, signature) {
            return Err(CryptographyError::from(
                exceptions::InvalidSignature::new_err("Value did not match computed tag."),
            ));
        }

        Ok(())
    }
}

pub(crate) fn create_module(py: pyo3::Python<'_>) -> pyo3::PyResult<&pyo3::prelude::PyModule> {
    let m = pyo3::prelude::PyModule::new(py, "poly1305")?;

    m.add_class::<Poly1305>()?;

    Ok(m)
}
