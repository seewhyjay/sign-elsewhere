import pytest
import sys
import datetime
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

sys.path.append("../sign-elsewhere")
from x509 import (
    CertificateRebuilder,
    CertificateTbsRebuilder,
    CertificationRequestRebuilder,
    CertificationRequestTbsRebuilder,
)


def test_csr():
    # This portion is taken from https://cryptography.io/en/latest/x509/tutorial/
    rsa_key_sizes = [2048, 3084, 4096]
    hash_algorithms = [hashes.SHA256(), hashes.SHA384(), hashes.SHA512()]
    for key_size in rsa_key_sizes:
        hash_algo = hash_algorithms[randint(0, 2)]
        rsa_placeholder_priv = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
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
        if isinstance(hash_algo, hashes.SHA256):
            sign_algo = "sha256_rsa"
        elif isinstance(hash_algo, hashes.SHA384):
            sign_algo = "sha384_rsa"
        elif isinstance(hash_algo, hashes.SHA512):
            sign_algo = "sha512_rsa"
        csr_bytes = CertificationRequestRebuilder(tbs, sign_algo, signature)

        csr = load_der_x509_csr(csr_bytes)

        rsa_signing_pub.verify(
            csr.signature,
            csr.tbs_certrequest_bytes,
            padding.PKCS1v15(),
            hash_algo,
        )


def test_certificate():
    rsa_placeholder_priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    rsa_signing_priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    rsa_signing_pub = rsa_signing_priv.public_key()
    rsa_signing_pub_der = rsa_signing_pub.public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )

    # Lifted from here https://cryptography.io/en/latest/x509/tutorial/
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(
            # This is actually unnecessary, you can just use signing pub here
            # I'm using the placeholder to test CertificateTbsRebuilder
            rsa_placeholder_priv.public_key()
        )
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow()
            + datetime.timedelta(days=10)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
            # Sign our certificate with our private key
        )
        .sign(rsa_placeholder_priv, hashes.SHA256())
    )

    tbs = CertificateTbsRebuilder(cert.public_bytes(Encoding.DER), rsa_signing_pub_der)

    signature = rsa_signing_priv.sign(tbs, padding.PKCS1v15(), hashes.SHA256())

    cert_bytes = CertificateRebuilder(tbs, "sha256_rsa", signature)
    cert = x509.load_der_x509_certificate(cert_bytes)

    rsa_signing_pub.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
