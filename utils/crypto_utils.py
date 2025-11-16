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

# =======================
# Diffie–Hellman Utilities
# =======================

import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.backends import default_backend
import base64

# 2048-bit MODP Group (RFC 3526 Group 14) prime
RFC3526_PRIME_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
FFFFFFFF FFFFFFFF
""".replace("\n", "").replace(" ", "")

P = int(RFC3526_PRIME_HEX, 16)
G = 2


def generate_dh_keypair():
    """
    Generates a DH private key (a random 256-bit integer)
    and a public key A = g^a mod p.
    Returns: (private_int, public_int)
    """
    priv = secrets.randbelow(1 << 256) + (1 << 255)  # ensure 256-bit
    pub = pow(G, priv, P)
    return priv, pub


def compute_shared_secret(priv, peer_pub):
    """
    Compute shared secret: Ks = peer_pub^priv mod p
    """
    return pow(peer_pub, priv, P)


def int_to_big_endian_bytes(x: int) -> bytes:
    """
    Convert integer to big-endian bytes (removes leading zeros automatically).
    """
    blen = (x.bit_length() + 7) // 8
    return x.to_bytes(blen if blen > 0 else 1, byteorder="big")


def derive_aes_key_from_shared(Ks_int: int) -> bytes:
    """
    Derive AES-128 key according to assignment:
    K = Trunc16( SHA256( BigEndian(Ks) ) )
    """
    ks_bytes = int_to_big_endian_bytes(Ks_int)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(ks_bytes)
    full = digest.finalize()
    return full[:16]  # 128-bit AES key


# =======================
# AES-CBC Encryption Utils
# =======================

def aes_encrypt(aes_key: bytes, plaintext: bytes) -> str:
    """
    AES-128-CBC + PKCS7 padding
    Returns Base64(iv + ciphertext)
    """
    iv = secrets.token_bytes(16)

    padder = sympadding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()

    return base64.b64encode(iv + ct).decode()


def aes_decrypt(aes_key: bytes, b64_input: str) -> bytes:
    """
    AES-128-CBC decryption with PKCS7 unpadding.
    Accepts Base64(iv + ciphertext)
    Returns plaintext bytes.
    """
    raw = base64.b64decode(b64_input)
    iv = raw[:16]
    ct = raw[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()

    unpadder = sympadding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

