from app import app
import base64
import json


def _decode_jwt_header(token: str):
    """Decode JWT header to dict."""
    header_b64 = token.split(".")[0]
    padding = "=" * (-len(header_b64) % 4)
    header_json = base64.urlsafe_b64decode(header_b64 + padding).decode("utf-8")
    return json.loads(header_json)


def test_auth_valid_and_expired():
    client = app.test_client()

    resp_valid = client.post("/auth")
    assert resp_valid.status_code == 200
    token_valid = resp_valid.get_json()["token"]
    hdr_valid = _decode_jwt_header(token_valid)
    assert "kid" in hdr_valid

    resp_exp = client.post("/auth?expired=true")
    assert resp_exp.status_code == 200
    token_exp = resp_exp.get_json()["token"]
    hdr_exp = _decode_jwt_header(token_exp)
    assert "kid" in hdr_exp
