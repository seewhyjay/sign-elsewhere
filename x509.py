from re import sub
from asn1crypto.x509 import Certificate, TbsCertificate
from asn1crypto.csr import CertificationRequest, CertificationRequestInfo
from asn1crypto.core import (
    OctetBitString,
    OctetString,
    ObjectIdentifier,
    ParsableOctetBitString,
)
from asn1crypto.algos import SignedDigestAlgorithmId, SignedDigestAlgorithm
from asn1crypto.keys import PublicKeyAlgorithm, PublicKeyInfo


def CertificateTbsRebuilder(certificate: bytes, public_key: bytes) -> bytes:
    """Changes the public key in the Certificate TBS

    Args:
        certificate (bytes): X509 Certificate in DER format
        public_key (bytes): Public key in DER format

    Returns:
        bytes: Certificate's TBS in DER format, sign this then use CertificateRebuilder
    """
    cert = Certificate.load(certificate)
    tbs = cert["tbs_certificate"]
    tbs = tbs["subject_public_key_info"]["public_key"] = ParsableOctetBitString(
        public_key
    )
    return tbs.dump(force=True)


def CertificateRebuilder(
    certificate_tbs: bytes,
    signature_algorithm: str,
    signature: bytes,
) -> bytes:
    """Rebuilds X509 Certificate using TBS and signature

    Args:
        certificate_tbs (bytes): The certificate TBS you got from CertificateTbsRebuilder

        signature_algorithm (str): Signature algorithm string, any of them here:
        https://github.com/wbond/asn1crypto/blob/8a4c621e34f8cbdc83b047aa617e66dcbfde0f75/asn1crypto/algos.py#L318-L343

    Returns:
        bytes: The Certificate provided with the new signature in DER format.
    """
    tbs = TbsCertificate.load(certificate_tbs)

    certificate = Certificate(
        {
            "tbs_certificate": tbs,
            "signature_algorithm": {"algorithm": signature_algorithm},
            "signature_value": OctetBitString(signature),
        }
    )

    certificate = certificate.dump(force=True)
    return certificate


def CertificationRequestTbsRebuilder(
    csr_tbs: bytes,
    public_key: bytes,
) -> bytes:
    """Rebuilds X509 CSR TBS with new public key

    Args:
        csr_tbs (bytes): CSR TBS in DER format from CertificationRequestTbsRebuilder
        public_key (bytes): Public key in DER format

    Returns:
        bytes: CSR TBS with edited public key in DER format
    """
    tbs = CertificationRequestInfo.load(csr_tbs)
    subject_pk_info = PublicKeyInfo.load(public_key)
    tbs["subject_pk_info"] = subject_pk_info

    return tbs.dump(force=True)


def CertificationRequestRebuilder(
    csr_tbs: bytes,
    signature_algorithm: str,
    signature: bytes,
) -> bytes:
    """Rebuilds X509 CSR using TBS and signature

    Args:
        csr (bytes): CSR TBS in DER format

        signature_algorithm (str): One of the Signature Algorithms from
        https://github.com/wbond/asn1crypto/blob/8a4c621e34f8cbdc83b047aa617e66dcbfde0f75/asn1crypto/algos.py#L297

        signature (bytes): The new signature in bytes

    Returns:
        bytes: The CSR provided with new signature and public key
    """
    tbs = CertificationRequestInfo.load(csr_tbs)
    csr = CertificationRequest(
        {
            "certification_request_info": tbs,
            "signature_algorithm": {
                "algorithm": signature_algorithm,
            },
            "signature": signature,
        }
    )
    return csr.dump(force=True)
