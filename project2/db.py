import sqlite3
import time
import threading

DB_PATH = "totally_not_my_privateKeys.db"

_connection = None
_lock = threading.Lock()


def get_connection():
    """Return global DB connection."""
    global _connection
    if _connection is None:
        _connection = sqlite3.connect(DB_PATH, check_same_thread=False)
        _connection.row_factory = sqlite3.Row
    return _connection


def init_db():
    """Initialize database and create keys table."""
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
    """Insert key into database and return kid."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO keys(key, exp) VALUES(?, ?)",
        (pem_str, exp_ts),
    )
    conn.commit()
    return cur.lastrowid


def get_key(expired=False):
    """Get a valid or expired key from DB."""
    conn = get_connection()
    cur = conn.cursor()
    now_ts = int(time.time())
    if expired:
        cur.execute(
            "SELECT kid, key, exp FROM keys "
            "WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
            (now_ts,),
        )
    else:
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
    """Fetch all non-expired keys."""
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
