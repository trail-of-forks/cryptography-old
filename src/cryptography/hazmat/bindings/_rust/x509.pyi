# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import PSS, PKCS1v15
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

def load_pem_x509_certificate(data: bytes) -> x509.Certificate: ...
def load_pem_x509_certificates(
    data: bytes,
) -> list[x509.Certificate]: ...
def load_der_x509_certificate(data: bytes) -> x509.Certificate: ...
def load_pem_x509_crl(data: bytes) -> x509.CertificateRevocationList: ...
def load_der_x509_crl(data: bytes) -> x509.CertificateRevocationList: ...
def load_pem_x509_csr(data: bytes) -> x509.CertificateSigningRequest: ...
def load_der_x509_csr(data: bytes) -> x509.CertificateSigningRequest: ...
def encode_name_bytes(name: x509.Name) -> bytes: ...
def encode_extension_value(extension: x509.ExtensionType) -> bytes: ...
def create_x509_certificate(
    builder: x509.CertificateBuilder,
    private_key: PrivateKeyTypes,
    hash_algorithm: hashes.HashAlgorithm | None,
    padding: PKCS1v15 | PSS | None,
) -> x509.Certificate: ...
def create_x509_csr(
    builder: x509.CertificateSigningRequestBuilder,
    private_key: PrivateKeyTypes,
    hash_algorithm: hashes.HashAlgorithm | None,
    padding: PKCS1v15 | PSS | None,
) -> x509.CertificateSigningRequest: ...
def create_x509_crl(
    builder: x509.CertificateRevocationListBuilder,
    private_key: PrivateKeyTypes,
    hash_algorithm: hashes.HashAlgorithm | None,
) -> x509.CertificateRevocationList: ...
def create_server_verifier(
    name: x509.verification.Subject,
    time: datetime.datetime | None,
) -> x509.verification.ServerVerifier: ...

class Sct: ...
class Certificate: ...
class RevokedCertificate: ...
class CertificateRevocationList: ...
class CertificateSigningRequest: ...

class ServerVerifier:
    @property
    def subject(self) -> x509.verification.Subject: ...
    @property
    def validation_time(self) -> datetime.datetime: ...
    def verify(
        self,
        leaf: x509.Certificate,
        intermediates: list[x509.Certificate],
        store: Store,
    ) -> list[x509.Certificate]: ...

class Store:
    def __init__(self, certs: list[x509.Certificate]) -> None: ...
