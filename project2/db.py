"""SQLite database operations for JWKS key management.

This module handles all database interactions for storing and retrieving RSA keys.
Key features:
- SQLite connection management with global connection reuse
- Schema: keys table with kid (auto-increment), key (PEM blob), exp (timestamp)
- AES encryption/decryption of private keys using NOT_MY_KEY environment variable
- User management with users table for registration
- Authentication logging with auth_logs table
- Functions for inserting keys, retrieving valid/expired keys, and querying

The database stores private keys in encrypted PEM format along with their expiration timestamps.
Educational use only - production systems should use proper key management solutions.
"""
import hashlib
import os
import sqlite3
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DB_PATH = "totally_not_my_privateKeys.db"

# Global connection instance for thread-safe reuse
_connection = None


def _get_aes_key():
    """Get AES encryption key from environment variable.

    Returns:
        bytes: 32-byte AES key derived from NOT_MY_KEY environment variable

    Raises:
        ValueError: If NOT_MY_KEY environment variable is not set
    """
    key_material = os.environ.get("NOT_MY_KEY")
    if not key_material:
        raise ValueError("NOT_MY_KEY environment variable must be set")
    # Use SHA-256 to derive a consistent 32-byte key from the environment variable
    return hashlib.sha256(key_material.encode()).digest()


def _encrypt_key(pem_str):
    """Encrypt a PEM-encoded private key using AES-256-CBC.

    Args:
        pem_str: PEM-encoded private key as string

    Returns:
        bytes: Encrypted key data (IV + ciphertext)
    """
    aes_key = _get_aes_key()
    # Generate random IV for each encryption
    # Note: In production, store IV separately. For this project, we prepend it.
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Pad the plaintext to be a multiple of 16 bytes (AES block size)
    pem_bytes = pem_str.encode('utf-8')
    padding_length = 16 - (len(pem_bytes) % 16)
    padded_data = pem_bytes + (bytes([padding_length]) * padding_length)

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return IV + ciphertext (IV is not secret, so it can be stored with ciphertext)
    return iv + ciphertext


def _decrypt_key(encrypted_data):
    """Decrypt an AES-encrypted private key.

    Args:
        encrypted_data: Encrypted key data (IV + ciphertext) as bytes

    Returns:
        str: Decrypted PEM-encoded private key
    """
    aes_key = _get_aes_key()

    # Extract IV (first 16 bytes) and ciphertext (remaining bytes)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    padding_length = padded_data[-1]
    pem_bytes = padded_data[:-padding_length]

    return pem_bytes.decode('utf-8')


def get_connection():
    """Return global SQLite database connection.

    Creates connection on first call and reuses it for subsequent calls.
    Connection is configured with:
    - check_same_thread=False for multi-threaded Flask usage
    - Row factory for dict-like access to results

    Returns:
        sqlite3.Connection: Database connection object
    """
    global _connection
    if _connection is None:
        _connection = sqlite3.connect(DB_PATH, check_same_thread=False)
        _connection.row_factory = sqlite3.Row
    return _connection


def init_db():
    """Initialize database and create all tables if they don't exist.

    Creates three tables:
    1. keys: Stores encrypted RSA private keys with expiration timestamps
    2. users: Stores user registration info with hashed passwords
    3. auth_logs: Logs authentication requests with IP, timestamp, and user_id
    """
    conn = get_connection()
    cur = conn.cursor()

    # Create keys table for RSA private keys
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        """
    )

    # Create users table for user registration
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        """
    )

    # Create auth_logs table for logging authentication requests
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )

    conn.commit()


def insert_key(pem_str, exp_ts):
    """Insert a new RSA key into the database with AES encryption.

    Args:
        pem_str: PEM-encoded private key as string
        exp_ts: Unix timestamp when key expires

    Returns:
        int: The auto-generated kid (key ID) for the inserted key
    """
    conn = get_connection()
    cur = conn.cursor()
    # Encrypt the private key before storing
    encrypted_key = _encrypt_key(pem_str)
    cur.execute(
        "INSERT INTO keys(key, exp) VALUES(?, ?)",
        (encrypted_key, exp_ts),
    )
    conn.commit()
    return cur.lastrowid


def get_key(expired=False):
    """Retrieve a single key from database based on expiration status.

    Decrypts the key using AES before returning.

    Args:
        expired: If True, returns the most recently expired key
                 If False, returns the nearest-to-expire valid key

    Returns:
        dict: Dictionary with 'kid', 'key', and 'exp' fields if key found,
              None if no suitable key exists
    """
    conn = get_connection()
    cur = conn.cursor()
    now_ts = int(time.time())
    if expired:
        # Get most recently expired key (highest exp timestamp <= now)
        cur.execute(
            "SELECT kid, key, exp FROM keys "
            "WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (now_ts,),
        )
    else:
        # Get valid key that will expire soonest (lowest exp timestamp >= now)
        cur.execute(
            "SELECT kid, key, exp FROM keys "
            "WHERE exp >= ? ORDER BY exp ASC LIMIT 1",
            (now_ts,),
        )
    row = cur.fetchone()
    if row:
        # Decrypt the key before returning
        decrypted_key = _decrypt_key(row["key"])
        return {"kid": row["kid"], "key": decrypted_key, "exp": row["exp"]}
    return None


def get_all_valid_keys():
    """Fetch all non-expired keys from database.

    Decrypts each key using AES before returning.

    Returns:
        list[dict]: List of dictionaries, each containing 'kid', 'key', and 'exp' fields
                    Sorted by expiration time (ascending) - keys expiring soonest first
    """
    conn = get_connection()
    cur = conn.cursor()
    now_ts = int(time.time())
    cur.execute(
        "SELECT kid, key, exp FROM keys "
        "WHERE exp >= ? ORDER BY exp ASC",
        (now_ts,),
    )
    rows = cur.fetchall()
    return [
        {"kid": r["kid"], "key": _decrypt_key(r["key"]), "exp": r["exp"]}
        for r in rows
    ]


def insert_user(username, password_hash, email=None):
    """Insert a new user into the database.

    Args:
        username: Unique username for the user
        password_hash: Argon2 hashed password
        email: Optional email address

    Returns:
        int: The auto-generated user id

    Raises:
        sqlite3.IntegrityError: If username or email already exists
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users(username, password_hash, email) VALUES(?, ?, ?)",
        (username, password_hash, email),
    )
    conn.commit()
    return cur.lastrowid


def get_user_by_username(username):
    """Retrieve a user by username.

    Args:
        username: Username to look up

    Returns:
        dict: Dictionary with user fields if found, None otherwise
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, username, password_hash, email, date_registered, last_login "
        "FROM users WHERE username = ?",
        (username,),
    )
    row = cur.fetchone()
    if row:
        return {
            "id": row["id"],
            "username": row["username"],
            "password_hash": row["password_hash"],
            "email": row["email"],
            "date_registered": row["date_registered"],
            "last_login": row["last_login"],
        }
    return None


def update_last_login(user_id):
    """Update the last_login timestamp for a user.

    Args:
        user_id: ID of the user to update
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
        (user_id,),
    )
    conn.commit()


def log_auth_request(request_ip, user_id=None):
    """Log an authentication request to the auth_logs table.

    Args:
        request_ip: IP address of the request
        user_id: Optional user ID if user was identified

    Returns:
        int: The auto-generated log entry id
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO auth_logs(request_ip, user_id) VALUES(?, ?)",
        (request_ip, user_id),
    )
    conn.commit()
    return cur.lastrowid
