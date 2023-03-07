# sign-elsewhere

## Use case
[pyca/cryptography](https://github.com/pyca/cryptography) doesn't support signing with HSMs. To create certificates/CRLs/OCSP responses with your HSM, first use a placeholder key, then use **sign-elsewhere** to recreate them with the signature from your HSM.


## Certificates
1. Create certificate with placeholder key
2. Use `CertificateTbsRebuilder` to generate a valid TBS with the public key of your choice
3. Hash and sign the TBS from step 2 using your HSM with the appropriate private key
4. Use `CertificateRebuilder` to rebuild your valid certificate with the correct public key and signature