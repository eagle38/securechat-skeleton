import sys, os
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)


import socket
import json
import os
import base64
import getpass

from utils.crypto_utils import (
    load_certificate_from_pem,
    validate_certificate,
    aes_encrypt,
    aes_decrypt,
)

HOST = "127.0.0.1"
PORT = 6000

# Load CA certificate
with open("certs/ca.crt", "rb") as f:
    CA_CERT_PEM = f.read()
CA_CERT = load_certificate_from_pem(CA_CERT_PEM)

# Load client certificate
with open("certs/client.crt", "rb") as f:
    CLIENT_CERT_PEM = f.read().decode()


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print("Connected to server")

    # -----------------------------
    # 1. Send client hello
    # -----------------------------
    hello = {
        "type": "hello",
        "client_cert": CLIENT_CERT_PEM
    }
    s.send(json.dumps(hello).encode())
    print("✔ Sent client hello")

    # -----------------------------
    # 2. Receive server hello
    # -----------------------------
    data_raw = s.recv(65536).decode()
    data = json.loads(data_raw)

    if data.get("type") != "server_hello":
        print("BAD PROTOCOL (expected server_hello)")
        s.close()
        return

    server_cert_pem = data["server_cert"].encode()
    server_cert = load_certificate_from_pem(server_cert_pem)

    # Validate server certificate
    ok, reason = validate_certificate(server_cert, CA_CERT, expected_cn="server")
    if not ok:
        print(reason)
        s.close()
        return

    print("✔ Server certificate validated")

    # ======================================================
    # ===============   DIFFIE–HELLMAN   ===================
    # ======================================================
    from utils.crypto_utils import (
        generate_dh_keypair,
        compute_shared_secret,
        derive_aes_key_from_shared,
    )

    # 1) Generate DH keypair
    client_priv, client_pub = generate_dh_keypair()
    A = client_pub

    dh_msg = {"type": "dh client", "A": str(A)}
    s.send(json.dumps(dh_msg).encode())
    print("✔ Sent DH client value (A)")

    # 2) Receive server DH
    msg2 = s.recv(65536).decode()
    dh_resp = json.loads(msg2)

    if dh_resp.get("type") != "dh server":
        print("BAD PROTOCOL (expected dh server)")
        s.close()
        return

    B = int(dh_resp["B"])

    # 3) Compute shared secret
    Ks = compute_shared_secret(client_priv, B)
    K = derive_aes_key_from_shared(Ks)
    print(f"✔ Client derived session key: {K.hex()}")

    # 4) Send verify message (debug)
    verify_msg = {"type": "dh verify", "key_hex": K.hex()}
    s.send(json.dumps(verify_msg).encode())
    print("✔ Sent DH key verification to server")

    print("DH complete — encrypted channel established.")

    # ======================================================
    # ===============   SECURE REGISTRATION   ==============
    # ======================================================

    print("Enter registration details:")
    email = input("Email: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password (hidden): ").strip()

    user_obj = {
        "email": email,
        "username": username,
        "password": password
    }

    plain_payload = json.dumps(user_obj).encode()

    # AES encrypt with session key K
    enc_payload = aes_encrypt(K, plain_payload)

    reg_msg = {"type": "register", "data": enc_payload}
    s.send(json.dumps(reg_msg).encode())
    print("✔ Registration request sent (encrypted)")

    # Receive reply
    reply_raw = s.recv(65536).decode()
    reply = json.loads(reply_raw)

    if reply.get("type") != "register_reply":
        print("BAD PROTOCOL (expected register_reply)")
        s.close()
        return

    enc_resp = reply.get("data")
    try:
        plain_resp = aes_decrypt(K, enc_resp)
        resp_obj = json.loads(plain_resp.decode())
        print("Server response:", resp_obj)
    except Exception:
        print("Failed to decrypt reply")


         # ======================================================
    # ===================== LOGIN ==========================
    # ======================================================

    print("\nNow testing secure login...")

    username = input("Username: ")
    password = getpass.getpass("Password (hidden): ")

    login_obj = {
        "username": username,
        "password": password
    }

    # encrypt login payload
    login_plain = json.dumps(login_obj).encode()
    enc_login = aes_encrypt(K, login_plain)

    login_req = {
        "type": "login",
        "data": enc_login
    }

    s.send(json.dumps(login_req).encode())

    # receive reply
    reply_raw = s.recv(65536).decode()
    reply = json.loads(reply_raw)

    reply_plain = aes_decrypt(K, reply["data"])
    print("Login response:", json.loads(reply_plain.decode()))



        # ======================================================
    # =============== ENCRYPTED MESSAGING ===================
    # ======================================================

    print("\nSecure channel ready — type your messages.")
    print("Type /quit to exit.\n")

    while True:
        text = input("You: ")

        if text.strip() == "/quit":
            break

        msg_obj = {
            "type": "message",
            "body": text
        }

        plain = json.dumps(msg_obj).encode()
        enc = aes_encrypt(K, plain)

        packet = {
            "type": "msg_send",
            "data": enc
        }

        s.send(json.dumps(packet).encode())

        # receive ack
        ack_raw = s.recv(65536).decode()
        ack_msg = json.loads(ack_raw)
        ack_plain = aes_decrypt(K, ack_msg["data"]).decode()

        print("Server ACK:", ack_plain)



    s.close()


if __name__ == "__main__":
    main()

