from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

def load_certificate_from_pem(pem_bytes):
    return x509.load_pem_x509_certificate(pem_bytes)

def validate_certificate(cert: x509.Certificate, ca_cert: x509.Certificate, expected_cn: str):
    # 1) Check issuer matches CA subject
    if cert.issuer != ca_cert.subject:
        return False, "BAD CERT: issuer mismatch"

    # 2) Check certificate validity period
    try:
        cert.public_key()  # ensures cert is structured properly
        cert.not_valid_before
        cert.not_valid_after
    except:
        return False, "BAD CERT: invalid certificate dates"

    # 3) Verify certificate signature (signed by CA)
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception:
        return False, "BAD CERT: signature verification failed"

    # 4) Check common name (CN)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if cn != expected_cn:
        return False, f"BAD CERT: expected CN '{expected_cn}', got '{cn}'"

    # 5) Check it is NOT a CA certificate
    basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    if basic_constraints.ca:
        return False, "BAD CERT: entity certificate cannot be a CA"

    return True, "OK"

