import pytest
from random import randint

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import (
    CertificateBuilder,
    CertificateSigningRequestBuilder,
    load_der_x509_csr,
)
from cryptography import x509
from cryptography.x509.oid import NameOID

from x509 import (
    CertificateRebuilder,
    CertificateTbsRebuilder,
    CertificationRequestRebuilder,
    CertificationRequestTbsRebuilder,
)


def test_csr():
    # This portion is taken from https://cryptography.io/en/latest/x509/tutorial/
    rsa_key_sizes = [2048, 3084, 4096]
    hash_algorithms = [hashes.SHA1(), hashes.SHA256(), hashes.SHA384(), hashes.SHA512()]
    for key_size in rsa_key_sizes:
        hash_algo = hash_algorithms[randint(0, 3)]
        rsa_placeholder_priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        rsa_placeholder_pub = rsa_placeholder_priv.public_key()
        rsa_placeholder_pub_der = rsa_placeholder_pub.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        rsa_signing_priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
        )

        rsa_signing_pub = rsa_signing_priv.public_key()
        rsa_signing_pub_der = rsa_signing_pub.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        # Provide various details about who we are.
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                        x509.NameAttribute(
                            NameOID.STATE_OR_PROVINCE_NAME, "California"
                        ),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
                    ]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        # Describe what sites we want this certificate for.
                        x509.DNSName("mysite.com"),
                        x509.DNSName("www.mysite.com"),
                        x509.DNSName("subdomain.mysite.com"),
                    ]
                ),
                critical=False,
                # Sign the CSR with our private key.
            )
            .sign(rsa_placeholder_priv, hash_algo)
        )

        csr_tbs = csr.tbs_certrequest_bytes

        tbs = CertificationRequestTbsRebuilder(csr_tbs, rsa_signing_pub_der)

        signature = rsa_signing_priv.sign(tbs, padding.PKCS1v15(), hash_algo)
        if isinstance(hash_algo, hashes.SHA1):
            sign_algo = "sha1_rsa"
        elif isinstance(hash_algo, hashes.SHA256):
            sign_algo = "sha256_rsa"
        elif isinstance(hash_algo, hashes.SHA1):
            sign_algo = "sha384_rsa"
        elif isinstance(hash_algo, hashes.SHA1):
            sign_algo = "sha512_rsa"
        csr_bytes = CertificationRequestRebuilder(tbs, sign_algo, signature)

        csr = load_der_x509_csr(csr_bytes)

        rsa_signing_pub.verify(
            csr.signature,
            csr.tbs_certrequest_bytes,
            padding.PKCS1v15(),
            hash_algo,
        )
