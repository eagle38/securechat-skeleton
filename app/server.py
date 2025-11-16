
import sys, os

# Add project root to Python path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

import socket
import json
import base64
import hashlib
import mysql.connector
from cryptography import x509

from utils.crypto_utils import (
    load_certificate_from_pem,
    validate_certificate,
    aes_encrypt,
    aes_decrypt,
)

HOST = "127.0.0.1"
PORT = 6000


# ============================================================
#   Load certificates
# ============================================================
with open("certs/ca.crt", "rb") as f:
    CA_CERT = x509.load_pem_x509_certificate(f.read())

with open("certs/server.crt", "rb") as f:
    SERVER_CERT_PEM = f.read().decode()


# ============================================================
#   Create users table if missing
# ============================================================
def ensure_users_table():
    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_USER = os.getenv("DB_USER", "chatuser")
    DB_PASS = os.getenv("DB_PASS", "StrongPassword123")
    DB_NAME = os.getenv("DB_NAME", "securechat")

    conn_db = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME,
    )
    cur = conn_db.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            email VARCHAR(255),
            username VARCHAR(255) UNIQUE,
            salt VARBINARY(16),
            pwd_hash CHAR(64)
        )
        """
    )
    conn_db.commit()
    cur.close()
    conn_db.close()


# ============================================================
#   Handle client connection
# ============================================================
def handle_client(conn):
    """Certificate exchange → DH → Registration"""

    # --------------------------------------------------------
    # 1. Receive client hello
    # --------------------------------------------------------
    data_raw = conn.recv(8192).decode()
    data = json.loads(data_raw)

    if data.get("type") != "hello":
        print("BAD PROTOCOL (expected hello)")
        conn.close()
        return

    client_cert_pem = data["client_cert"].encode()
    client_cert = load_certificate_from_pem(client_cert_pem)

    # --------------------------------------------------------
    # 2. Validate client certificate
    # --------------------------------------------------------
    ok, reason = validate_certificate(client_cert, CA_CERT, expected_cn="client")
    if not ok:
        print(reason)
        conn.close()
        return

    print("✔ Client certificate validated")

    # --------------------------------------------------------
    # 3. Send server hello
    # --------------------------------------------------------
    nonce = os.urandom(16)

    response = {
        "type": "server_hello",
        "server_cert": SERVER_CERT_PEM,
        "nonce": base64.b64encode(nonce).decode(),
    }

    conn.send(json.dumps(response).encode())
    print("✔ Sent server_hello")

    # --------------------------------------------------------
    # 4. Diffie–Hellman Key Exchange
    # --------------------------------------------------------
    from utils.crypto_utils import (
        generate_dh_keypair,
        compute_shared_secret,
        derive_aes_key_from_shared,
    )

    msg = conn.recv(65536).decode()
    dh_req = json.loads(msg)

    if dh_req.get("type") != "dh client":
        print("BAD PROTOCOL (expected dh client)")
        conn.close()
        return

    A = int(dh_req["A"])

    # Generate DH keypair
    server_priv, server_pub = generate_dh_keypair()
    B = server_pub

    dh_response = {"type": "dh server", "B": str(B)}
    conn.send(json.dumps(dh_response).encode())

    # Shared secret
    Ks = compute_shared_secret(server_priv, A)
    K = derive_aes_key_from_shared(Ks)

    print(f"✔ Server derived session key: {K.hex()}")

    # Optional verify msg
    try:
        verify_raw = conn.recv(8192).decode()
        if verify_raw:
            verify_msg = json.loads(verify_raw)
            if verify_msg.get("type") == "dh verify":
                print("Client key:", verify_msg["key_hex"])
                print("Match?:", verify_msg["key_hex"] == K.hex())
    except:
        pass

    # --------------------------------------------------------
    # 5. Encrypted Registration
    # --------------------------------------------------------
    ensure_users_table()

    reg_raw = conn.recv(65536).decode()
    if not reg_raw:
        conn.close()
        return

    reg_msg = json.loads(reg_raw)

    if reg_msg.get("type") != "register":
        conn.close()
        return

    enc_b64 = reg_msg.get("data")
    if not enc_b64:
        error_plain = json.dumps({"status": "error", "msg": "bad_payload"}).encode()
        enc = aes_encrypt(K, error_plain)
        conn.send(json.dumps({"type": "register_reply", "data": enc}).encode())
        conn.close()
        return

    # decrypt registration data
    try:
        reg_plain = aes_decrypt(K, enc_b64)
        reg_obj = json.loads(reg_plain.decode())

        email = reg_obj["email"]
        username = reg_obj["username"]
        password = reg_obj["password"]
    except:
        error_plain = json.dumps({"status": "error", "msg": "invalid_data"}).encode()
        enc = aes_encrypt(K, error_plain)
        conn.send(json.dumps({"type": "register_reply", "data": enc}).encode())
        conn.close()
        return

    # Salt + Hash password
    salt = os.urandom(16)
    h = hashlib.sha256()
    h.update(salt + password.encode())
    pwd_hash_hex = h.hexdigest()

    # Write to MySQL
    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_USER = os.getenv("DB_USER", "chatuser")
    DB_PASS = os.getenv("DB_PASS", "StrongPassword123")
    DB_NAME = os.getenv("DB_NAME", "securechat")

    try:
        conn_db = mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASS, database=DB_NAME
        )
        cur = conn_db.cursor()
        sql = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
        cur.execute(sql, (email, username, salt, pwd_hash_hex))
        conn_db.commit()
        cur.close()
        conn_db.close()

        reply_plain = json.dumps({"status": "ok"}).encode()
        enc = aes_encrypt(K, reply_plain)
        conn.send(json.dumps({"type": "register_reply", "data": enc}).encode())

    except mysql.connector.IntegrityError:
        reply_plain = json.dumps({"status": "error", "msg": "username_taken"}).encode()
        enc = aes_encrypt(K, reply_plain)
        conn.send(json.dumps({"type": "register_reply", "data": enc}).encode())

    except:
        reply_plain = json.dumps({"status": "error", "msg": "server_error"}).encode()
        enc = aes_encrypt(K, reply_plain)
        conn.send(json.dumps({"type": "register_reply", "data": enc}).encode())

         # ======================================================
    # =================== SECURE LOGIN =====================
    # ======================================================
    try:
        login_raw = conn.recv(65536).decode()
        if login_raw:
            login_msg = json.loads(login_raw)

            if login_msg.get("type") == "login":
                enc_b64 = login_msg.get("data")

                # decrypt login payload
                login_plain = aes_decrypt(K, enc_b64)
                login_obj = json.loads(login_plain.decode())

                username = login_obj.get("username")
                password = login_obj.get("password")

                if username and password:
                    # lookup user in DB
                    conn_db = mysql.connector.connect(
                        host=DB_HOST,
                        user=DB_USER,
                        password=DB_PASS,
                        database=DB_NAME,
                    )
                    cur = conn_db.cursor()
                    cur.execute("SELECT salt, pwd_hash FROM users WHERE username=%s", (username,))
                    row = cur.fetchone()
                    cur.close()
                    conn_db.close()

                    if not row:
                        reply_plain = json.dumps(
                            {"status": "error", "msg": "invalid_credentials"}
                        ).encode()
                    else:
                        db_salt, db_hash_hex = row

                        # recompute hash
                        h = hashlib.sha256()
                        h.update(db_salt + password.encode())
                        attempt_hash_hex = h.hexdigest()

                        if attempt_hash_hex == db_hash_hex:
                            reply_plain = json.dumps({"status": "ok"}).encode()
                        else:
                            reply_plain = json.dumps(
                                {"status": "error", "msg": "invalid_credentials"}
                            ).encode()

                    # encrypt reply
                    enc = aes_encrypt(K, reply_plain)
                    conn.send(json.dumps({"type": "login_reply", "data": enc}).encode())

    except Exception as e:
        print("Login error:", e)










    conn.close()


# ============================================================
#   Main
# ============================================================
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)

    print(f"Server running on {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        print(f"Accepted connection from {addr}")
        handle_client(conn)


if __name__ == "__main__":
    main()




