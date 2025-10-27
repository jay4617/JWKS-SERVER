import base64
from flask import Flask, request, jsonify

from db import init_db, get_key
from keys import ensure_keys_in_db, build_jwks
from auth import create_jwt

app = Flask(__name__)

init_db()
ensure_keys_in_db()


def _get_basic_auth_creds(req):
    """Parse HTTP Basic auth header."""
    auth_header = req.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        b64_part = auth_header.split(" ", 1)[1]
        try:
            decoded = base64.b64decode(b64_part).decode("utf-8")
            username, password = decoded.split(":", 1)
            return username, password
        except Exception:
            return None, None
    return None, None


@app.route("/auth", methods=["POST"])
def auth_route():
    """Handle authentication and return signed JWT."""

    username, _password = _get_basic_auth_creds(request)

    if username is None:
        body = request.get_json(silent=True) or {}
        username = body.get("username")
        _password = body.get("password")
    expired_flag = request.args.get("expired")
    want_expired = expired_flag is not None

    row = get_key(expired=want_expired)
    if row is None:
        return jsonify({"error": "no suitable key found"}), 500

    token = create_jwt(
        kid=row["kid"],
        pem_str=row["key"],
        expired=want_expired,
    )

    return jsonify({"token": token})


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks_route():
    """Return JWKS with all valid public keys."""
    jwks = build_jwks()
    return jsonify(jwks)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)
