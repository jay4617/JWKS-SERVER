from __future__ import annotations
from typing import List
from pydantic import BaseModel


class JWK(BaseModel):
    kty: str
    use: str
    alg: str
    kid: str
    e: str
    n: str


class JWKS(BaseModel):
    keys: List[JWK]
