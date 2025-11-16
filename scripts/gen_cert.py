from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import os, datetime, sys

CERTS_DIR = "certs"

def load_ca():
    with open(f"{CERTS_DIR}/ca.key", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(f"{CERTS_DIR}/ca.crt", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    return ca_key, ca_cert

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/gen_cert.py <name>")
        sys.exit(1)

    name = sys.argv[1]
    os.makedirs(CERTS_DIR, exist_ok=True)

    ca_key, ca_cert = load_ca()

    # Generate keypair
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Subject for this certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Entity"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    # Create certificate signed by CA
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    # Save private key
    with open(f"{CERTS_DIR}/{name}.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Save certificate
    with open(f"{CERTS_DIR}/{name}.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"✔ Issued certificate for: {name}")

if __name__ == "__main__":
    main()

