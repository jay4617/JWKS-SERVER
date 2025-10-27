"""RSA key generation and JWKS formatting.

Handles RSA key pair generation, PEM loading, and conversion to JWK format.
"""
import base64
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from db import get_all_valid_keys, get_key, insert_key


def _generate_private_key_pem() -> str:
    """Generate 2048-bit RSA key as PEM string."""
    priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    pem_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem_bytes.decode("utf-8")


def load_private_key(pem_str: str):
    """Load private key from PEM string."""
    return serialization.load_pem_private_key(
        pem_str.encode("utf-8"),
        password=None,
    )


def ensure_keys_in_db():
    """Ensure DB has at least one expired and one valid key."""
    now_ts = int(time.time())
    expired_key = get_key(expired=True)
    valid_key = get_key(expired=False)

    # Create expired key if none exists (expired 60 seconds ago)
    if expired_key is None:
        expired_pem = _generate_private_key_pem()
        expired_exp = now_ts - 60
        insert_key(expired_pem, expired_exp)

    # Create valid key if none exists (expires in 1 hour)
    if valid_key is None:
        valid_pem = _generate_private_key_pem()
        valid_exp = now_ts + 3600
        insert_key(valid_pem, valid_exp)


def _b64url_uint(val: int) -> str:
    """Convert int to base64url without padding."""
    byte_length = (val.bit_length() + 7) // 8
    val_bytes = val.to_bytes(byte_length, "big")
    b64 = base64.urlsafe_b64encode(val_bytes).rstrip(b"=")
    return b64.decode("utf-8")


def _private_to_jwk(kid: int, pem_str: str) -> dict[str, Any]:
    """Convert private key to public JWK format."""
    priv = load_private_key(pem_str)
    pub = priv.public_key()
    numbers = pub.public_numbers()

    n_int = numbers.n
    e_int = numbers.e

    jwk = {
        "kty": "RSA",
        "kid": str(kid),
        "alg": "RS256",
        "use": "sig",
        "n": _b64url_uint(n_int),
        "e": _b64url_uint(e_int),
    }
    return jwk


def build_jwks() -> dict[str, Any]:
    """Build JWKS from all valid keys in DB."""
    valid_keys = get_all_valid_keys()
    jwks_keys = [_private_to_jwk(k["kid"], k["key"]) for k in valid_keys]
    return {"keys": jwks_keys}
