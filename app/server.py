



import sys, os

# Add project root to Python path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)
import socket
import json
import base64
import os
from cryptography import x509
from utils.crypto_utils import load_certificate_from_pem, validate_certificate

HOST = "127.0.0.1"
PORT = 6000

# Load CA + server certificate
with open("certs/ca.crt", "rb") as f:
    CA_CERT = x509.load_pem_x509_certificate(f.read())

with open("certs/server.crt", "rb") as f:
    SERVER_CERT_PEM = f.read().decode()

with open("certs/server.key", "rb") as f:
    SERVER_KEY_PEM = f.read().decode()   # used later for signatures


def handle_client(conn):
    """Handle a new client connection and perform certificate exchange."""
    
    # ---- Step 1: Receive client hello ----
    data_raw = conn.recv(8192).decode()
    data = json.loads(data_raw)

    if data["type"] != "hello":
        print("BAD PROTOCOL (expected hello)")
        conn.close()
        return

    client_cert_pem = data["client_cert"].encode()
    client_cert = load_certificate_from_pem(client_cert_pem)

    # ---- Step 2: Validate client certificate ----
    ok, reason = validate_certificate(client_cert, CA_CERT, expected_cn="client")
    if not ok:
        print(reason)
        conn.close()
        return

    print("✔ Client certificate validated")

    # ---- Step 3: Send server hello ----
    nonce = os.urandom(16)

    response = {
        "type": "server_hello",
        "server_cert": SERVER_CERT_PEM,
        "nonce": base64.b64encode(nonce).decode()
    }

    conn.send(json.dumps(response).encode())
    print("✔ Sent server_hello")
    
    # ---- STOP HERE (DH, login, messaging will come later) ----
   # ======================================================
    # ===============   DIFFIE–HELLMAN   ===================
    # ======================================================

    # Import DH helpers
    from utils.crypto_utils import (
        generate_dh_keypair,
        compute_shared_secret,
        derive_aes_key_from_shared,
    )

    # ---- Step 4: Receive DH client message ----
    msg = conn.recv(65536).decode()
    dh_req = json.loads(msg)

    if dh_req.get("type") != "dh client":
        print("BAD PROTOCOL (expected 'dh client')")
        conn.close()
        return

    if "A" not in dh_req:
        print("BAD DH payload: missing A")
        conn.close()
        return

    A = int(dh_req["A"])   # client's public DH key

    # ---- Step 5: Server generates its DH keypair ----
    server_priv, server_pub = generate_dh_keypair()
    B = server_pub

    # ---- Step 6: Send DH server message ----
    dh_response = {
        "type": "dh server",
        "B": str(B)
    }
    conn.send(json.dumps(dh_response).encode())

    # ---- Step 7: Compute shared secret ----
    Ks = compute_shared_secret(server_priv, A)
    K = derive_aes_key_from_shared(Ks)

    print(f"✔ Server derived session key: {K.hex()}")

    # ---- Step 8: Optional verification (client sends its key for debugging) ----
    try:
        test_raw = conn.recv(8192).decode()
        if test_raw:
            test_msg = json.loads(test_raw)
            if test_msg.get("type") == "dh verify":
                client_key_hex = test_msg.get("key_hex")
                print("Client reported key:", client_key_hex)
                print("Match?:", client_key_hex == K.hex())
    except Exception:
        pass

    # DH is complete




    conn.close()


def main():
    """Start plain TCP server and wait for connections."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)

    print(f"Server running on {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        print(f"Accepted connection from {addr}")
        handle_client(conn)


if __name__ == "__main__":
    main()

