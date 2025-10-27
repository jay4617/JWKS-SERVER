"""Flask-based JWKS Server with SQLite Database.

This module implements a JSON Web Key Set (JWKS) server using Flask and SQLite.
Key features:
- Stores RSA private keys in SQLite database with expiration timestamps
- Provides /auth endpoint for JWT token generation (supports expired tokens via ?expired=1)
- Provides /.well-known/jwks.json endpoint serving public keys in JWKS format
- Supports HTTP Basic Auth and JSON body authentication

Educational use only - not for production environments.
"""
import base64

from auth import create_jwt
from db import get_key, init_db
from flask import Flask, jsonify, request
from keys import build_jwks, ensure_keys_in_db

app = Flask(__name__)

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


@app.route("/auth", methods=["POST"])
def auth_route():
    """Handle authentication and return signed JWT.

    Accepts credentials via:
    - HTTP Basic Authentication header
    - JSON body with username/password fields

    Query parameters:
    - expired: If present, returns JWT signed with expired key

    Returns:
        JSON response with "token" field containing the signed JWT
        or error message with 500 status if no suitable key exists
    """
    # Try Basic Auth first
    username, _password = _get_basic_auth_creds(request)

    # Fall back to JSON body if Basic Auth not provided
    if username is None:
        body = request.get_json(silent=True) or {}
        username = body.get("username")
        _password = body.get("password")

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
