from asn1crypto.x509 import Certificate
from asn1crypto.csr import CertificationRequest
from asn1crypto.core import OctetBitString, OctetString, ObjectIdentifier
from asn1crypto.algos import SignedDigestAlgorithmId, SignedDigestAlgorithm
from asn1crypto.keys import PublicKeyAlgorithm, PublicKeyInfo


def CertificateRebuilder(
    certificate: bytes,
    signature_algorithm: str,
    signature: bytes,
    public_key: bytes = None,
) -> bytes:
    """Rebuilds X509 Certificate with new signature and public key if required

    Args:
        certificate (bytes): The certificate you want to replace either the signature and/or the public key in DER format
        
        signature_algorithm (str): Signature algorithm string, any of them here:
        https://github.com/wbond/asn1crypto/blob/8a4c621e34f8cbdc83b047aa617e66dcbfde0f75/asn1crypto/algos.py#L318-L343
        
        public_key (bytes, optional): The public key in DER format.
        If not specified, does not replace public key
        (Useful if you've already replaced the public key in the CSR you used to generate the Certificate).
        Assumes the same key type (Algorithm & Size) as the placeholder key used to sign the original Certificate
        (rsa if the original certificate was signed with a RSA key)
        Defaults to None.

    Returns:
        bytes: The Certificate provided with the new signature and public key
    """
    cert = Certificate.load(certificate)
    
    if public_key:
        cert["tbs_certificate"]["subject_public_key_info"]["public_key"] = public_key
        
    tbs_cert = cert["tbs_certificate"]
    
    signature_algorithm = cert["signature_algorithm"]
    
    new_certificate = Certificate({
        'tbs_certificate': tbs_cert,
        'signature_algorithm': {
            'algorithm': signature_algorithm
            },
        'signature_value': OctetBitString(signature)
    })
    
    certificate = new_certificate.dump(force=True)
    return certificate


def CertificationRequestRebuilder(
    csr: bytes,
    signature_algorithm: str,
    signature: bytes,
    public_key: bytes,
) -> bytes:
    """Rebuilds X509 CSR with new signature and public key

    Args:
        csr (bytes): CSR in DER format
        
        signature_algorithm (str): One of the Signature Algorithms from
        https://github.com/wbond/asn1crypto/blob/8a4c621e34f8cbdc83b047aa617e66dcbfde0f75/asn1crypto/algos.py#L297
        
        signature (bytes): The new signature in bytes

        public_key (bytes): The public key in DER format.
        If not specified, does not replace public key
        (Useful if you've already replaced the public key in the CSR you used to generate the Certificate).
        Assumes the same key type (Algorithm & Size) as the placeholder key used to sign the original Certificate
        (rsa if the original certificate was signed with a RSA key)
        Defaults to None.

    Returns:
        bytes: The CSR provided with new signature and public key
    """
    
    return csr