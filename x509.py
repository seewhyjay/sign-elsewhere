from asn1crypto.x509 import Certificate
from asn1crypto.csr import CertificationRequest
from asn1crypto.core import OctetBitString, OctetString, ObjectIdentifier
from asn1crypto.algos import SignedDigestAlgorithmId, SignedDigestAlgorithm
from asn1crypto.keys import PublicKeyAlgorithmId


def CertificateBuilder(
    certificate: bytes,
    signature_algorithm: str,
    signature: bytes,
    public_key: bytes = None,
) -> bytes:
    """_summary_

    Args:
        certificate (bytes): The certificate you want to replace either the signature and/or the public key
        signature_algorithm (str): One of the Signature Algorithms from
        https://github.com/wbond/asn1crypto/blob/8a4c621e34f8cbdc83b047aa617e66dcbfde0f75/asn1crypto/algos.py#L297
        signature (bytes): The new signature in bytes
        public_key (bytes, optional): The public key in DER format, if not specified, does not replace public key (Useful if you've already replaced the public key in the CSR you used to generate the Certificate). Defaults to None.

    Returns:
        bytes: The Certificate provided with the new signature and public key
    """
    signature_algo_id = SignedDigestAlgorithmId(signature_algorithm)
    if signature_algorithm.native not in signature_algorithm._map.values():
        raise Exception("Signature algorithm does not exist")
    signature_algo = SignedDigestAlgorithm(signature_algorithm)
    pass