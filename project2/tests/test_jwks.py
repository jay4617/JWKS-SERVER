from app import app


def test_jwks_has_keys():
    client = app.test_client()
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200

    data = resp.get_json()
    assert "keys" in data
    assert isinstance(data["keys"], list)

    for jwk in data["keys"]:
        assert "kid" in jwk
        assert "kty" in jwk and jwk["kty"] == "RSA"
        assert "n" in jwk
        assert "e" in jwk
        assert "alg" in jwk and jwk["alg"] == "RS256"
        assert "use" in jwk and jwk["use"] == "sig"
