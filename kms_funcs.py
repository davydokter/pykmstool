"""
icedevml/pykmstool - Google Cloud KMS Certificate Signing Request (CSR) Generation Tool
BSD 3-Clause "New" License
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import load_pem_x509_csr
from google.cloud import kms

from kms_priv_key import create_pyca_private_key
from typing import List, Optional
import ipaddress


def kms_get_public_key(*, client: kms.KeyManagementServiceClient, key_version_name: str) -> str:
    signer_priv_key = create_pyca_private_key(client, key_version_name)
    return signer_priv_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    ).decode('ascii')


def kms_sign_csr(
        *,
        client: kms.KeyManagementServiceClient,
        key_version_name: str,
        rfc4514_name: str,
        add_ext: Optional[List[str]]
) -> str:
    signer_priv_key = create_pyca_private_key(client, key_version_name)

    name = x509.Name.from_rfc4514_string(rfc4514_name)

    builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
    )

    if add_ext:
        gen_names_all: List[x509.GeneralName] = []
        for ext_def in add_ext:
            if not ext_def:
                continue
            if '=' not in ext_def:
                continue
            key, value = ext_def.split('=', 1)
            key_norm = key.strip().lower()

            if key_norm == 'subjectaltname':
                for part in value.split(','):
                    part = part.strip()
                    if not part:
                        continue
                    if ':' not in part:
                        continue
                    typ, data = part.split(':', 1)
                    t = typ.strip().lower()
                    if '.' in t:
                        t = t.split('.', 1)[0]
                    d = data.strip().rstrip(',:;')
                    if not d:
                        continue
                    if t == 'dns':
                        gen_names_all.append(x509.DNSName(d))
                    elif t == 'ip':
                        try:
                            ip = ipaddress.ip_address(d)
                            gen_names_all.append(x509.IPAddress(ip))
                        except ValueError:
                            continue
                    elif t == 'uri':
                        gen_names_all.append(x509.UniformResourceIdentifier(d))
                    elif t in ('email', 'rfc822'):
                        gen_names_all.append(x509.RFC822Name(d))
                    else:
                        continue

        if gen_names_all:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(gen_names_all), critical=False
            )

    cert = builder.sign(signer_priv_key, signer_priv_key.hash_algorithm())
    return cert.public_bytes(serialization.Encoding.PEM).decode('ascii')


def kms_verify_csr(
        *,
        client: kms.KeyManagementServiceClient,
        key_version_name: str,
        csr_pem: str,
        expected_rfc4514_name: str
):
    signer_priv_key = create_pyca_private_key(client, key_version_name)

    csr = load_pem_x509_csr(csr_pem.encode('ascii'))

    if csr.subject != x509.Name.from_rfc4514_string(expected_rfc4514_name):
        raise RuntimeError("Mismatched RFC4514 name.")

    if not csr.is_signature_valid:
        raise RuntimeError("Produced CSR doesn\'t have valid signature.")

    if csr.public_key() != signer_priv_key.public_key():
        raise RuntimeError("Mismatched public keys in CSR and KMS.")
