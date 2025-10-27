"""JWT creation and signing with RS256 algorithm."""
import time

import jwt  # pyjwt
from keys import load_private_key


def create_jwt(kid: int, pem_str: str, expired: bool = False) -> str:
    """Create and sign RS256 JWT with given key.

    Args:
        kid: Key identifier to include in JWT header
        pem_str: PEM-encoded private key for signing
        expired: If True, creates token that expired 10 minutes ago

    Returns:
        Signed JWT token string
    """
    now_ts = int(time.time())
    # Set expiration time: 10 minutes in past or future
    if expired:
        exp_ts = now_ts - 600
    else:
        exp_ts = now_ts + 600

    payload = {
        "sub": "userABC",
        "username": "userABC",
        "iat": now_ts,
        "exp": exp_ts,
    }

    private_key_obj = load_private_key(pem_str)

    token = jwt.encode(
        payload,
        private_key_obj,
        algorithm="RS256",
        headers={"kid": str(kid)},
    )
    return token
