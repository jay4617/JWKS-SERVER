#!/usr/bin/env python3
"""Test script for new security features.

Tests:
1. AES encryption of private keys
2. User registration with Argon2 hashing
3. Authentication logging
4. Database schema verification
"""
import os
import sqlite3
import sys

# Set environment variable before importing app
os.environ["NOT_MY_KEY"] = "test-encryption-key-do-not-use-in-production"

# Now import the app modules
from app import app
from db import get_connection, get_user_by_username

def test_database_schema():
    """Verify all tables exist with correct schema."""
    print("Testing database schema...")

    conn = get_connection()
    cur = conn.cursor()

    # Check if all tables exist
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cur.fetchall()]

    required_tables = ["keys", "users", "auth_logs"]
    for table in required_tables:
        assert table in tables, f"Table '{table}' missing"
        print(f"✓ Table '{table}' exists")

    # Check users table schema
    cur.execute("PRAGMA table_info(users)")
    user_columns = {row[1]: row[2] for row in cur.fetchall()}

    expected_user_columns = {
        "id": "INTEGER",
        "username": "TEXT",
        "password_hash": "TEXT",
        "email": "TEXT",
        "date_registered": "TIMESTAMP",
        "last_login": "TIMESTAMP"
    }

    for col, type_ in expected_user_columns.items():
        assert col in user_columns, f"users.{col} missing"
        print(f"✓ users.{col} ({user_columns[col]}) exists")

    # Check auth_logs table schema
    cur.execute("PRAGMA table_info(auth_logs)")
    log_columns = {row[1]: row[2] for row in cur.fetchall()}

    expected_log_columns = {
        "id": "INTEGER",
        "request_ip": "TEXT",
        "request_timestamp": "TIMESTAMP",
        "user_id": "INTEGER"
    }

    for col, type_ in expected_log_columns.items():
        assert col in log_columns, f"auth_logs.{col} missing"
        print(f"✓ auth_logs.{col} ({log_columns[col]}) exists")


def test_user_registration():
    """Test user registration endpoint."""
    print("\nTesting user registration...")

    with app.test_client() as client:
        # Test valid registration
        response = client.post(
            "/register",
            json={"username": "testuser_pytest", "email": "test_pytest@example.com"}
        )

        assert response.status_code == 201, f"Registration failed with status {response.status_code}"
        print("✓ User registration successful (201 CREATED)")

        data = response.get_json()
        assert "password" in data, "Password not in response"
        print(f"✓ Password generated: {data['password'][:8]}...")

        # Verify user exists in database
        user = get_user_by_username("testuser_pytest")
        assert user is not None, "User not found in database"
        print(f"✓ User found in database with ID {user['id']}")
        print(f"✓ Password hash stored: {user['password_hash'][:20]}...")

        # Test duplicate registration
        response = client.post(
            "/register",
            json={"username": "testuser_pytest", "email": "test2@example.com"}
        )

        assert response.status_code == 409, f"Expected 409, got {response.status_code}"
        print("✓ Duplicate username rejected (409 CONFLICT)")


def test_auth_endpoint():
    """Test authentication endpoint with logging."""
    print("\nTesting authentication endpoint...")

    with app.test_client() as client:
        # First register a user to authenticate with
        reg_response = client.post(
            "/register",
            json={"username": "testauth_user", "email": "testauth@example.com"}
        )
        assert reg_response.status_code == 201, "Failed to register test user"
        password = reg_response.get_json()["password"]

        # Test authentication
        response = client.post(
            "/auth",
            json={"username": "testauth_user", "password": password}
        )

        assert response.status_code == 200, f"Authentication failed with status {response.status_code}"
        print("✓ Authentication successful (200 OK)")

        data = response.get_json()
        assert "token" in data, "Token not in response"
        print(f"✓ JWT token generated: {data['token'][:50]}...")

        # Verify auth log entry was created
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, request_ip, user_id FROM auth_logs ORDER BY id DESC LIMIT 1"
        )
        row = cur.fetchone()

        assert row is not None, "Auth request not logged"
        print(f"✓ Auth request logged with ID {row['id']}")
        print(f"  - IP: {row['request_ip']}")
        print(f"  - User ID: {row['user_id']}")


def test_aes_encryption():
    """Test that keys are encrypted in database."""
    print("\nTesting AES encryption of private keys...")

    conn = get_connection()
    cur = conn.cursor()

    # Get a key from database
    cur.execute("SELECT kid, key FROM keys LIMIT 1")
    row = cur.fetchone()

    assert row is not None, "No keys found in database"

    encrypted_key = row["key"]
    # Check that it's not plaintext PEM (should not start with -----BEGIN)
    assert isinstance(encrypted_key, bytes), "Key should be bytes"
    assert not encrypted_key.startswith(b"-----BEGIN"), "Private key appears to be plaintext"

    print("✓ Private keys are encrypted (not plaintext PEM)")
    print(f"  - Key ID: {row['kid']}")
    print(f"  - Encrypted data (first 32 bytes): {encrypted_key[:32].hex()}")


def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing Enhanced JWKS Server Security Features")
    print("=" * 60)

    try:
        # Test 1: Database schema
        test_database_schema()
        print("✓ Database schema test passed")

        # Test 2: AES encryption
        test_aes_encryption()
        print("✓ AES encryption test passed")

        # Test 3: User registration
        test_user_registration()
        print("✓ User registration test passed")

        # Test 4: Authentication with logging
        test_auth_endpoint()
        print("✓ Authentication test passed")

        print("\n" + "=" * 60)
        print("✓ All tests passed successfully!")
        print("=" * 60)
        return 0
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
