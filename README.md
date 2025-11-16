SecureChat – Encrypted Chat System (Mutual Auth + DH + AES + DB Login)

This project implements a secure client–server chat system using:

X.509 Certificates (CA-signed, mutual authentication)

Diffie–Hellman (DH) Key Exchange

AES-256 Encryption for all messages

MySQL database for user registration & login

Encrypted messaging with ACKs

Replay/tamper protection validated during testing

📌 Project Structure
securechat/
│
├── app/
│   ├── client.py
│   ├── server.py
│   ├── storage/
│   │     ├── db.py
│   │     └── transcript.py
│
├── utils/
│   ├── crypto_utils.py
│
├── certs/
│   ├── ca.key
│   ├── ca.crt
│   ├── client.key
│   ├── client.crt
│   ├── server.key
│   ├── server.crt
│
├── requirements.txt
└── README.md

1. ⚙️ Requirements & Setup
1.1 Install dependencies
pip install -r requirements.txt

1.2 MySQL Configuration
Create MySQL User & Database

Log in as root:

mysql -u root -p


Run:

DROP USER IF EXISTS 'chatuser'@'localhost';
CREATE USER 'chatuser'@'localhost' IDENTIFIED BY 'StrongPassword123';
CREATE DATABASE IF NOT EXISTS securechat;
GRANT ALL PRIVILEGES ON securechat.* TO 'chatuser'@'localhost';
FLUSH PRIVILEGES;

Environment Variables (Optional)

Defaults are already in server.py:

DB_HOST = 127.0.0.1
DB_USER = chatuser
DB_PASS = StrongPassword123
DB_NAME = securechat

2. 🔐 Certificate Setup

Ensure that the following files exist in certs/:

File	Purpose
ca.key	CA private key
ca.crt	CA certificate
server.key	Server private key
server.csr	Server CSR
server.crt	Server certificate (signed by CA)
client.key	Client private key
client.csr	Client CSR
client.crt	Client certificate (signed by CA)

If you need to regenerate certificates:

Create CA
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 \
  -out ca.crt -subj "/C=PK/ST=Lahore/L=Lahore/O=SecureChat/OU=CA/CN=ca"

Create Server Certificate
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/C=PK/ST=Lahore/L=Lahore/O=SecureChat/OU=Server/CN=server"

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 -sha256

Create Client Certificate
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "/C=PK/ST=Lahore/L=Lahore/O=SecureChat/OU=Client/CN=client"

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 365 -sha256

3. ▶️ Execution Steps
3.1 Run Server
python3 -m app.server


Server output example:

Server running on 127.0.0.1:6000
Accepted connection from ('127.0.0.1', 53281)
✔ Client certificate validated
✔ Server derived session key: <hex>
Match?: True

3.2 Run Client
python3 -m app.client

Sample Client Flow
Connected to server
✔ Server certificate validated
✔ Client derived session key: <hex>
DH complete — encrypted channel established.

Enter registration details:
Email: taha@test.com
Username: taha1
Password (hidden): ******
✔ Registration request sent (encrypted)
Server response: {'status': 'ok'}

Now testing secure login...
Username: taha1
Password (hidden):
Login response: {'status': 'ok'}

Secure channel ready — type your messages.
Type /quit to exit.

You: hello server
Server delivered: ✔

4. 🧪 Sample Inputs & Outputs
Registration (client → server, encrypted)

Input JSON:

{
  "type": "register",
  "data": "<base64 encrypted blob>"
}


Server plaintext payload after decryption:

{
  "email": "taha@test.com",
  "username": "taha1",
  "password": "<raw password>"
}


Server reply (encrypted):

{
  "status": "ok"
}

Login (client → server, encrypted)

Input JSON:

{
  "type": "login",
  "data": "<encrypted blob>"
}


Decrypted server view:

{
  "username": "taha1",
  "password": "12345"
}


Server reply:

{
  "status": "ok"
}

Encrypted Messaging

Client → Server:

{
  "type": "msg_send",
  "data": "<AES encrypted message>"
}


Server decrypts to:

{
  "body": "hey"
}


Server ACK (encrypted):

{
  "type": "msg_ack",
  "data": "<AES encrypted: {'status':'delivered'}>"
}

5. 📁 Transcript Storage (Phase 7)

Messages are stored in:

app/storage/transcript.py


Sample saved transcript line:

[SERVER] hey

6. 🧪 Testing Evidence

The following tests were performed:

✔ Mutual certificate validation (invalid cert rejected)
✔ Replay & tamper tests (server rejects malformed payloads)
✔ PCAP inspected — encrypted AES payload visible
✔ DH key mismatch attempt fails
✔ Incorrect login prevented
✔ Username uniqueness enforced

(Full testing documentation included in the assignment report.)

7. 📝 Final Notes for TA

Code supports full mutual authentication.

All traffic is encrypted using AES-256 derived from DH.

Database registration/login implemented securely with salt+hash.

Transcript logging works for every message.

Easy to run in any environment with MySQL + Python 3.10+.
