SecureChat – Encrypted Chat System (Mutual Auth + DH + AES + DB Login)

This project implements a secure client–server chat system using:

X.509 Certificates (CA-signed, mutual authentication)

Diffie–Hellman (DH) Key Exchange

AES-256 Encryption for all messages

MySQL database for user registration & login

Encrypted messaging with ACKs

Replay/tamper protection validated during testing


SQL SCHEMA
ast login: Sun Nov 16 15:55:11 on ttys004
taha@Tahas-Mac-mini ~ % /usr/local/mysql/bin/mysql -u root -p

Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 9
Server version: 8.0.30 MySQL Community Server - GPL

Copyright (c) 2000, 2022, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| securechat         |
| sys                |
+--------------------+
5 rows in set (0.01 sec)

mysql> ALTER USER 'chatuser'@'localhost'
    -> IDENTIFIED WITH mysql_native_password BY 'StrongPassword123';
Query OK, 0 rows affected (0.01 sec)

mysql> FLUSH PRIVILEGES
    -> FLUSH PRIVILEGES;
ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'FLUSH PRIVILEGES' at line 2
mysql> FLUSH PRIVILEGES;
Query OK, 0 rows affected (0.00 sec)

mysql> SELECT user, host, plugin FROM mysql.user;
+------------------+-----------+-----------------------+
| user             | host      | plugin                |
+------------------+-----------+-----------------------+
| chatuser         | localhost | mysql_native_password |
| mysql.infoschema | localhost | caching_sha2_password |
| mysql.session    | localhost | caching_sha2_password |
| mysql.sys        | localhost | caching_sha2_password |
| root             | localhost | caching_sha2_password |
+------------------+-----------+-----------------------+
5 rows in set (0.00 sec)

mysql> USE securechat;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> SELECT id, email, username, salt, pwd_hash FROM users;
ERROR 1054 (42S22): Unknown column 'id' in 'field list'
mysql> DESCRIBE users;
+----------+---------------+------+-----+---------+-------+
| Field    | Type          | Null | Key | Default | Extra |
+----------+---------------+------+-----+---------+-------+
| email    | varchar(255)  | YES  |     | NULL    |       |
| username | varchar(255)  | YES  | UNI | NULL    |       |
| salt     | varbinary(16) | YES  |     | NULL    |       |
| pwd_hash | char(64)      | YES  |     | NULL    |       |
+----------+---------------+------+-----+---------+-------+
4 rows in set (0.00 sec)

mysql> ALTER TABLE users
    -> ADD COLUMN id INT PRIMARY KEY AUTO_INCREMENT FIRST;
Query OK, 0 rows affected (0.02 sec)
Records: 0  Duplicates: 0  Warnings: 0

mysql> DESCRIBE users;
+----------+---------------+------+-----+---------+----------------+
| Field    | Type          | Null | Key | Default | Extra          |
+----------+---------------+------+-----+---------+----------------+
| id       | int           | NO   | PRI | NULL    | auto_increment |
| email    | varchar(255)  | YES  |     | NULL    |                |
| username | varchar(255)  | YES  | UNI | NULL    |                |
| salt     | varbinary(16) | YES  |     | NULL    |                |
| pwd_hash | char(64)      | YES  |     | NULL    |                |
+----------+---------------+------+-----+---------+----------------+
5 rows in set (0.01 sec)

mysql> SELECT * FROM users;
+----+---------------+----------+------------------------------------+------------------------------------------------------------------+
| id | email         | username | salt                               | pwd_hash                                                         |
+----+---------------+----------+------------------------------------+------------------------------------------------------------------+
|  1 | taha@test.com | taha1    | 0xF829B1D284E76B24186AFECFBE7E5C68 | 3f31432fa11f5f5c09eae1d900a3e90a84a5d05f8d6a5893caf78b3434c3576c |
+----+---------------+----------+------------------------------------+------------------------------------------------------------------+
1 row in set (0.00 sec)

mysql> mysqldump -u chatuser -p --databases securechat > securechat_dump.sql
    -> 
    -> 


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
