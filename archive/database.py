import sqlite3
from Crypto.PublicKey import RSA
from datetime import datetime, timedelta

def init_database():
    """Initialize the SQLite database and create the keys table"""
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    # Create table with exact schema from requirements
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

def generate_and_store_keys():
    """Generate RSA key pairs and store them in the database.
    Creates one valid key (expires in 1 hour) and one expired key.
    Uses parameterized queries to prevent SQL injection attacks.
    """
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    # Check if keys already exist
    cursor.execute('SELECT COUNT(*) FROM keys')
    if cursor.fetchone()[0] > 0:
        conn.close()
        return
    
    # Generate VALID key (expires in 1 hour)
    valid_key = RSA.generate(2048)
    valid_key_pem = valid_key.export_key('PEM')
    valid_exp = int((datetime.utcnow() + timedelta(hours=1)).timestamp())
    
    # Generate EXPIRED key (expired now)
    expired_key = RSA.generate(2048)
    expired_key_pem = expired_key.export_key('PEM')
    expired_exp = int(datetime.utcnow().timestamp())
    
    # Use parameterized queries to prevent SQL injection
    cursor.execute(
        'INSERT INTO keys (key, exp) VALUES (?, ?)',
        (valid_key_pem, valid_exp)
    )
    
    cursor.execute(
        'INSERT INTO keys (key, exp) VALUES (?, ?)',
        (expired_key_pem, expired_exp)
    )
    
    conn.commit()
    conn.close()

def get_private_key(expired=False):
    """Get a private key from the database.
    Args:
        expired: If True, get an expired key. Otherwise, get a valid key.
    Returns:
        Tuple of (kid, key_pem) or (None, None) if no key found.
    """
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    current_time = int(datetime.utcnow().timestamp())
    
    if expired:
        # Get an expired key using parameterized query
        cursor.execute(
            'SELECT kid, key FROM keys WHERE exp <= ? LIMIT 1',
            (current_time,)
        )
    else:
        # Get a valid (non-expired) key using parameterized query
        cursor.execute(
            'SELECT kid, key FROM keys WHERE exp > ? LIMIT 1',
            (current_time,)
        )
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return result[0], result[1]
    return None, None

def get_valid_keys():
    """Get all valid (non-expired) keys from the database.
    Returns:
        List of tuples (kid, key_pem)
    """
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    
    current_time = int(datetime.utcnow().timestamp())
    
    # Get all valid keys using parameterized query
    cursor.execute(
        'SELECT kid, key FROM keys WHERE exp > ?',
        (current_time,)
    )
    
    results = cursor.fetchall()
    conn.close()
    
    return results
