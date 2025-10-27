"""SQLite database operations for JWKS key management.

This module handles all database interactions for storing and retrieving RSA keys.
Key features:
- SQLite connection management with global connection reuse
- Schema: keys table with kid (auto-increment), key (PEM blob), exp (timestamp)
- Functions for inserting keys, retrieving valid/expired keys, and querying

The database stores private keys in PEM format along with their expiration timestamps.
Educational use only - production systems should use proper key management solutions.
"""
import sqlite3
import time

DB_PATH = "totally_not_my_privateKeys.db"

# Global connection instance for thread-safe reuse
_connection = None


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
    """Initialize database and create keys table if it doesn't exist.

    Table schema:
    - kid: INTEGER PRIMARY KEY AUTOINCREMENT (key identifier)
    - key: BLOB NOT NULL (PEM-encoded private key)
    - exp: INTEGER NOT NULL (Unix timestamp for expiration)
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
        """
    )
    conn.commit()


def insert_key(pem_str, exp_ts):
    """Insert a new RSA key into the database.

    Args:
        pem_str: PEM-encoded private key as string
        exp_ts: Unix timestamp when key expires

    Returns:
        int: The auto-generated kid (key ID) for the inserted key
    """
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO keys(key, exp) VALUES(?, ?)",
        (pem_str, exp_ts),
    )
    conn.commit()
    return cur.lastrowid


def get_key(expired=False):
    """Retrieve a single key from database based on expiration status.

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
        return {"kid": row["kid"], "key": row["key"], "exp": row["exp"]}
    return None


def get_all_valid_keys():
    """Fetch all non-expired keys from database.

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
        {"kid": r["kid"], "key": r["key"], "exp": r["exp"]}
        for r in rows
    ]
