# existing_server.py

# Import necessary libraries
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime

# Define database file name
DB_FILE = "totally_not_my_privateKeys.db"

# Function to create/open SQLite DB and initialize schema
def initialize_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Function to store private keys in the database
def store_private_key_to_db(key_bytes, exp_timestamp):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key_bytes, exp_timestamp))
    conn.commit()
    conn.close()

# Function to retrieve private key from the database
def get_private_key_from_db(expired=False):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    if expired:
        cursor.execute("SELECT key FROM keys WHERE exp < ?", (datetime.datetime.utcnow().timestamp(),))
    else:
        cursor.execute("SELECT key FROM keys WHERE exp >= ?", (datetime.datetime.utcnow().timestamp(),))
    key_row = cursor.fetchone()
    conn.close()
    return key_row[0] if key_row else None

# Function to convert integer to Base64URL-encoded string
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Create/open SQLite DB and initialize schema
initialize_database()

# Generate private keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Serialize private keys to PEM format
pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
expired_pem = expired_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())

# Store private keys in the database
store_private_key_to_db(pem, (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())
store_private_key_to_db(expired_pem, (datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp())

# Define HTTP server parameters
hostName = "localhost"
serverPort = 8080

# Define BaseHTTPRequestHandler class
class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {"kid": "goodKID"}
            key_bytes = get_private_key_from_db(expired='expired' in params)
            if key_bytes:
                encoded_jwt = jwt.encode({"user": "username", "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, key_bytes, algorithm="RS256", headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
                return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {"keys": []}
            key_bytes = get_private_key_from_db()
            if key_bytes:
                public_key = private_key.public_key()
                numbers = public_key.public_numbers()
                keys["keys"].append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(numbers.n),
                    "e": int_to_base64(numbers.e),
                })
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
