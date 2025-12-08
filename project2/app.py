"""Flask-based JWKS Server with SQLite Database.

This module implements a JSON Web Key Set (JWKS) server using Flask and SQLite.
Key features:
- Stores RSA private keys in SQLite database with expiration timestamps
- AES encryption of private keys using NOT_MY_KEY environment variable
- User registration with Argon2 password hashing
- Authentication request logging
- Rate limiting on /auth endpoint
- Provides /auth endpoint for JWT token generation (supports expired tokens via ?expired=1)
- Provides /.well-known/jwks.json endpoint serving public keys in JWKS format
- Provides /register endpoint for user registration
- Supports HTTP Basic Auth and JSON body authentication

Educational use only - not for production environments.
"""
import base64
import sqlite3
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import HashingError
from auth import create_jwt
from db import (
    get_key,
    get_user_by_username,
    init_db,
    insert_user,
    log_auth_request,
    update_last_login,
)
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from keys import build_jwks, ensure_keys_in_db

app = Flask(__name__)

# Initialize rate limiter for /auth endpoint
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],  # No default limits, only specific endpoint limits
    storage_uri="memory://",
)

# Initialize Argon2 password hasher
ph = PasswordHasher()

# Initialize database and ensure we have both valid and expired keys
init_db()
ensure_keys_in_db()


def _get_basic_auth_creds(req):
    """Parse HTTP Basic auth header and extract credentials.

    Args:
        req: Flask request object

    Returns:
        tuple: (username, password) if valid Basic auth header exists,
               (None, None) otherwise
    """
    auth_header = req.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        # Extract base64-encoded credentials from "Basic <credentials>"
        b64_part = auth_header.split(" ", 1)[1]
        try:
            decoded = base64.b64decode(b64_part).decode("utf-8")
            # Credentials format: "username:password"
            username, password = decoded.split(":", 1)
            return username, password
        except Exception:
            # Invalid base64 or format - return None for both
            return None, None
    return None, None


@app.route("/register", methods=["POST"])
def register_route():
    """Handle user registration.

    Accepts JSON body with:
    - username: Desired username (required)
    - email: Email address (optional)

    Generates a secure UUIDv4 password and returns it to the user.
    Stores the username, email, and Argon2-hashed password in the database.

    Returns:
        JSON response with "password" field containing the generated password
        201 CREATED status on success
        400 BAD REQUEST if username is missing or invalid
        409 CONFLICT if username or email already exists
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "request body must be JSON"}), 400

    username = body.get("username")
    email = body.get("email")

    if not username:
        return jsonify({"error": "username is required"}), 400

    # Generate secure UUIDv4 password
    password = str(uuid.uuid4())

    try:
        # Hash password using Argon2
        password_hash = ph.hash(password)

        # Insert user into database
        insert_user(username, password_hash, email)

        # Return the password to the user (only time they'll see it)
        return jsonify({"password": password}), 201

    except sqlite3.IntegrityError as e:
        # Username or email already exists
        error_msg = str(e)
        if "username" in error_msg.lower():
            return jsonify({"error": "username already exists"}), 409
        elif "email" in error_msg.lower():
            return jsonify({"error": "email already exists"}), 409
        else:
            return jsonify({"error": "user already exists"}), 409
    except HashingError as e:
        return jsonify({"error": f"password hashing failed: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"registration failed: {str(e)}"}), 500


@app.route("/auth", methods=["POST"])
@limiter.limit("10 per second")
def auth_route():
    """Handle authentication and return signed JWT.

    Rate limited to 10 requests per second.
    Logs all successful authentication requests to auth_logs table.

    Accepts credentials via:
    - HTTP Basic Authentication header
    - JSON body with username/password fields

    Query parameters:
    - expired: If present, returns JWT signed with expired key

    Returns:
        JSON response with "token" field containing the signed JWT
        200 OK on success
        429 TOO MANY REQUESTS if rate limit exceeded
        500 INTERNAL SERVER ERROR if no suitable key exists
    """
    # Get client IP address
    client_ip = get_remote_address()

    # Try Basic Auth first
    username, _password = _get_basic_auth_creds(request)

    # Fall back to JSON body if Basic Auth not provided
    if username is None:
        body = request.get_json(silent=True) or {}
        username = body.get("username")
        _password = body.get("password")

    # Look up user in database to get user_id for logging
    user_id = None
    if username:
        user = get_user_by_username(username)
        if user:
            user_id = user["id"]
            # Update last login timestamp
            update_last_login(user_id)

    # Check if client wants an expired token for testing
    expired_flag = request.args.get("expired")
    want_expired = expired_flag is not None

    # Retrieve appropriate key from database
    row = get_key(expired=want_expired)
    if row is None:
        return jsonify({"error": "no suitable key found"}), 500

    # Sign and return JWT
    token = create_jwt(
        kid=row["kid"],
        pem_str=row["key"],
        expired=want_expired,
    )

    # Log successful authentication request
    log_auth_request(client_ip, user_id)

    return jsonify({"token": token})


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks_route():
    """Return JWKS with all valid (non-expired) public keys.

    Returns:
        JSON response containing JWKS with "keys" array of public key objects.
        Each key includes: kty, kid, alg, use, n, e fields per JWK spec.
    """
    jwks = build_jwks()
    return jsonify(jwks)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)
