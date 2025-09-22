import json
import time

import jwt
from fastapi.testclient import TestClient
from jwt import ExpiredSignatureError
from jwt.algorithms import RSAAlgorithm

from app.main import app, store

client = TestClient(app)


def get_public_key_from_jwks(kid: str):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.json()
    for jwk in data.get("keys", []):
        if jwk.get("kid") == kid:
            return RSAAlgorithm.from_jwk(json.dumps(jwk))
    return None


def test_valid_jwt_authentication():
    # Request a valid token
    r = client.post("/auth")
    assert r.status_code == 200
    token = r.json()["token"]

    # Header contains kid
    header = jwt.get_unverified_header(token)
    assert "kid" in header
    kid = header["kid"]

    # JWKS should include this kid
    pub_key = get_public_key_from_jwks(kid)
    assert pub_key is not None

    # Token should verify and not be expired
    decoded = jwt.decode(token, key=pub_key, algorithms=["RS256"])
    assert decoded["sub"] == "fake-user-123"


def test_expired_jwt_authentication_and_jwk_not_in_jwks():
    # Request an expired token
    r = client.post("/auth?expired=1")
    assert r.status_code == 200
    token = r.json()["token"]
    header = jwt.get_unverified_header(token)
    kid = header["kid"]

    # The expired key should NOT be present in JWKS
    assert get_public_key_from_jwks(kid) is None

    # But we (as white-box unit test) can still fetch the key material from the store
    pub_key = store.get_public_key_by_kid(kid)
    assert pub_key is not None

    # Verifying with expiration should fail
    try:
        jwt.decode(token, key=pub_key, algorithms=["RS256"])
        assert False, "Expected token to be expired"
    except ExpiredSignatureError:
        pass


def test_proper_http_methods_and_status_codes():
    # JWKS: GET is allowed
    assert client.get("/.well-known/jwks.json").status_code == 200
    # JWKS: POST should be method not allowed
    assert client.post("/.well-known/jwks.json").status_code == 405
    # Auth: GET should be method not allowed
    assert client.get("/auth").status_code == 405
    # Auth: POST allowed
    assert client.post("/auth").status_code == 200


def test_expired_key_is_expired_flag():
    # Ensure the store's expired key truly has an expiry in the past
    assert store.expired.expires_at < int(time.time())
