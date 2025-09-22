"""Pydantic models for JWKS server API responses.

Defines the data structures for:
- JWK (JSON Web Key) representation
- JWKS (JSON Web Key Set) containing multiple keys

These models ensure proper validation and serialization of JWT-related data.
"""
from __future__ import annotations

from pydantic import BaseModel


class JWK(BaseModel):
    """JSON Web Key model representing a single public key.

    Attributes:
        kty: Key type (e.g., 'RSA')
        use: Public key use (e.g., 'sig' for signature verification)
        alg: Algorithm intended for use with the key (e.g., 'RS256')
        kid: Key ID for identifying this key
        e: RSA public exponent (base64url encoded)
        n: RSA modulus (base64url encoded)
    """
    kty: str
    use: str
    alg: str
    kid: str
    e: str
    n: str


class JWKS(BaseModel):
    """JSON Web Key Set containing multiple JWK entries.

    Attributes:
        keys: List of JWK objects representing public keys
    """
    keys: list[JWK]
