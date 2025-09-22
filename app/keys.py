"""RSA key management and JWT signing for JWKS server.

This module provides:
- RSA key pair generation with unique identifiers (kid) and expiry timestamps
- Key rotation management with active and expired keys
- JWT signing with proper kid headers
- JWKS format conversion for public key distribution

Educational use only - not for production environments.
"""
from __future__ import annotations

import base64
import time
import uuid
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _b64u(data: bytes) -> str:
    """Base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass
class KeyPair:
    kid: str
    private_pem: bytes
    public_pem: bytes
    expires_at: int  # unix epoch seconds

    def is_expired(self, now: int | None = None) -> bool:
        n = now or int(time.time())
        return n >= self.expires_at

    def public_jwk(self) -> dict[str, str]:
        """Return a public JWK dict suitable for JWKS."""
        public_key = serialization.load_pem_public_key(self.public_pem)
        numbers = public_key.public_numbers()
        e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
        n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": self.kid,
            "e": _b64u(e),
            "n": _b64u(n),
        }

    def private_key(self):
        return serialization.load_pem_private_key(self.private_pem, password=None)

    def public_key(self):
        return serialization.load_pem_public_key(self.public_pem)


class KeyStore:
    """In-memory key store holding one active and one expired key for this assignment."""

    def __init__(self, active_lifetime_s: int = 3600, expired_age_s: int = 3600):
        now = int(time.time())
        self.active = self._generate_key(expires_at=now + active_lifetime_s)
        # expired key that already expired in the past
        self.expired = self._generate_key(expires_at=now - expired_age_s)

    def _generate_key(self, *, expires_at: int) -> KeyPair:
        kid = str(uuid.uuid4())
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return KeyPair(
            kid=kid, private_pem=private_pem, public_pem=public_pem, expires_at=expires_at
        )

    # --- Helpers for app ---
    def jwks(self) -> dict[str, list[dict[str, str]]]:
        """Return JWKS dict containing only unexpired public keys."""
        keys = []
        if not self.active.is_expired():
            keys.append(self.active.public_jwk())
        # If you ever rotate and have multiple actives, you'd add them here.
        return {"keys": keys}

    def sign_jwt(self, *, use_expired: bool = False) -> str:
        """Sign a JWT with either the active or expired private key."""
        kp = self.expired if use_expired else self.active
        now = int(time.time())
        payload = {
            "sub": "fake-user-123",
            "iat": now,
            "exp": kp.expires_at,
            "iss": "jwks-server",
            "scope": "demo",
        }
        private_key = kp.private_key()
        token = jwt.encode(
            payload,
            private_key,
            algorithm="RS256",
            headers={"kid": kp.kid},
        )
        return token

    def get_public_key_by_kid(self, kid: str):
        """Return public key object for a given kid, if known (active or expired)."""
        for kp in (self.active, self.expired):
            if kp.kid == kid:
                return kp.public_key()
        return None
