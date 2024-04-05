# enhanced_server.py

import sqlite3
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import os
import uuid
import argon2
from http.server import BaseHTTPRequestHandler, HTTPServer

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
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP      
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,  
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

# Function to store private keys in the database
def store_private_key_to_db(key_bytes, exp_timestamp):
    # Encrypt key using AES
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(key_bytes, AES.block_size))
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (ct_bytes, exp_timestamp))
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

    if key_row:
        # Decrypt key using AES
        cipher = AES.new(AES_KEY, AES.MODE_CBC)
        pt_bytes = cipher.decrypt(key_row[0]).rstrip(b"\0") # Remove padding
        return pt_bytes
    else:
        return None

# Function to convert integer to Base64URL-encoded string
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

# Function to handle user registration
def register_user(username, email):
    password = str(uuid.uuid4())
    hashed_password = argon2.hash_password(password)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, hashed_password, email))
    conn.commit()
    conn.close()

    return password

# Function to log authentication requests
def log_authentication_request(request_ip, user_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (request_ip, user_id))
    conn.commit()
    conn.close()

# Define HTTP server parameters
hostName = "localhost"
serverPort = 8080

# Define AES key from environment variable
AES_KEY = os.getenv('NOT_MY_KEY')

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
                # Log authentication request
                log_authentication_request(self.client_address[0])

# Create/open SQLite DB and initialize schema
initialize_database()

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
