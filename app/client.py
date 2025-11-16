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

    s.close()


if __name__ == "__main__":
    main()

