"""
JWKS Server Implementation
This server provides JWT authentication with the following features:
- User registration with UUID-based password generation
- Password hashing using Argon2
- AES encryption for private keys
- Authentication logging
- Rate limiting
"""
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import sqlite3
import os
import uuid
from argon2 import PasswordHasher
from datetime import datetime
from dotenv import load_dotenv
import time
from collections import defaultdict
from contextlib import contextmanager

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Environment variable for encryption
NOT_MY_KEY = os.getenv('NOT_MY_KEY')
if not NOT_MY_KEY:
    raise ValueError("NOT_MY_KEY environment variable is not set!")

# Initialize Fernet for encryption
fernet = Fernet(NOT_MY_KEY.encode())

# Initialize Password Hasher
ph = PasswordHasher()

# Database configuration
DATABASE = 'totally_not_my_privateKeys.db'

def encrypt_key(key_data):
    if isinstance(key_data, str):
        key_data = key_data.encode()
    return fernet.encrypt(key_data)

def decrypt_key(encrypted_key):
    if isinstance(encrypted_key, str):
        encrypted_key = encrypted_key.encode()
    decrypted = fernet.decrypt(encrypted_key)
    return decrypted.decode()

@contextmanager
def get_db():
    conn = None
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        yield conn
        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        raise e
    finally:
        if conn:
            conn.close()

def init_db():
    with get_db() as conn:
        c = conn.cursor()
        
        # Drop existing tables if they exist
        c.execute('DROP TABLE IF EXISTS keys')
        c.execute('DROP TABLE IF EXISTS auth_logs')
        c.execute('DROP TABLE IF EXISTS users')
        
        # Create users table
        c.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP      
        )
        ''')
        
        # Create auth_logs table
        c.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        ''')
        
        # Create keys table
        c.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        ''')

        # Add sample keys
        sample_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6helU/xewSE=" 
        encrypted_key = encrypt_key(sample_key)
        
        # Insert a valid key
        c.execute(
            'INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)',
            (1, encrypted_key, int(time.time()) + 3600)
        )
        
        # Insert an expired key
        c.execute(
            'INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)',
            (2, encrypted_key, int(time.time()) - 3600)
        )

# Rate limiting
request_counts = {}
def is_rate_limited(ip):
    now = time.time()
    if ip not in request_counts:
        request_counts[ip] = []
    
    # Remove timestamps older than 1 second
    request_counts[ip] = [t for t in request_counts[ip] if t > now - 1]
    
    # Check if over limit (10 requests per second)
    if len(request_counts[ip]) >= 10:
        return True
        
    # Add new timestamp
    request_counts[ip].append(now)
    return False

def log_auth_attempt(ip, user_id=None):
    with get_db() as conn:
        c = conn.cursor()
        c.execute(
            'INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)',
            (ip, user_id)
        )

# Initialize database
init_db()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'email' not in data:
        return jsonify({"error": "Missing required fields"}), 400
    
    password = str(uuid.uuid4())
    try:
        password_hash = ph.hash(password)
        with get_db() as conn:
            c = conn.cursor()
            c.execute(
                'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                (data['username'], password_hash, data['email'])
            )
        return jsonify({"password": password}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/auth', methods=['POST'])
def auth():
    # Check rate limit first
    if is_rate_limited(request.remote_addr):
        return jsonify({"error": "Too many requests"}), 429
    
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Missing username or password"}), 400
    
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT id, password_hash FROM users WHERE username = ?', (data['username'],))
            user = c.fetchone()
            
            if not user:
                log_auth_attempt(request.remote_addr)
                return jsonify({"error": "Invalid username or password"}), 401
            
            try:
                ph.verify(user['password_hash'], data['password'])
                with get_db() as conn:
                    c = conn.cursor()
                    c.execute(
                        'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
                        (user['id'],)
                    )
                log_auth_attempt(request.remote_addr, user['id'])
                return jsonify({"message": "Authentication successful"}), 200
            except Exception:
                log_auth_attempt(request.remote_addr)
                return jsonify({"error": "Invalid username or password"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
if __name__ == '__main__':
    app.run(debug=True, port=8080)