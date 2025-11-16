import sys, os
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)



import socket
import json
import base64
from cryptography import x509
from utils.crypto_utils import load_certificate_from_pem, validate_certificate

# Fix Python module path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

HOST = "127.0.0.1"
PORT = 6000  # IMPORTANT: same as server

# Load CA + client certificate
with open("certs/ca.crt", "rb") as f:
    CA_CERT = x509.load_pem_x509_certificate(f.read())

with open("certs/client.crt", "rb") as f:
    CLIENT_CERT_PEM = f.read().decode()

with open("certs/client.key", "rb") as f:
    CLIENT_KEY_PEM = f.read().decode()   # used later for signatures


def main():
    # ---- Step 1: Connect to server ----
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print("Connected to server")

    # ---- Step 2: Send hello ----
    nonce = os.urandom(16)

    hello_msg = {
        "type": "hello",
        "client_cert": CLIENT_CERT_PEM,
        "nonce": base64.b64encode(nonce).decode()
    }

    s.send(json.dumps(hello_msg).encode())
    print("✔ Sent client hello")

    # ---- Step 3: Get server hello ----
    msg = s.recv(8192).decode()
    data = json.loads(msg)

    if data["type"] != "server_hello":
        print("BAD PROTOCOL")
        s.close()
        return

    # ---- Step 4: Validate server certificate ----
    server_cert_pem = data["server_cert"].encode()
    server_cert = load_certificate_from_pem(server_cert_pem)

    ok, reason = validate_certificate(server_cert, CA_CERT, expected_cn="server")
    if not ok:
        print(reason)
        s.close()
        return

    print("✔ Server certificate validated")

    # ---- End handshake (DH coming later) ----
    print("Handshake complete.")

   # ======================================================
    # ===============   DIFFIE–HELLMAN   ===================
    # ======================================================

    from utils.crypto_utils import (
        generate_dh_keypair,
        compute_shared_secret,
        derive_aes_key_from_shared,
    )

    # ---- Step 1: Client generates DH keypair ----
    client_priv, client_pub = generate_dh_keypair()
    A = client_pub

    # ---- Step 2: Send DH client message ----
    dh_msg = {
        "type": "dh client",
        "A": str(A)      # send public DH share as decimal string
    }
    s.send(json.dumps(dh_msg).encode())
    print("✔ Sent DH client value (A)")

    # ---- Step 3: Receive DH server message ----
    dh_raw = s.recv(65536).decode()
    dh_resp = json.loads(dh_raw)

    if dh_resp.get("type") != "dh server":
        print("BAD PROTOCOL (expected dh server)")
        s.close()
        return

    B = int(dh_resp["B"])   # server's public DH share

    # ---- Step 4: Compute shared secret ----
    Ks = compute_shared_secret(client_priv, B)
    K = derive_aes_key_from_shared(Ks)
    print(f"✔ Client derived session key: {K.hex()}")

    # ---- Step 5: Send verify message (for testing/debug) ----
    verify_msg = {
        "type": "dh verify",
        "key_hex": K.hex()
    }
    s.send(json.dumps(verify_msg).encode())
    print("✔ Sent DH key verification to server")

    print("DH complete — shared AES key established.")


    s.close()


if __name__ == "__main__":
    main()

