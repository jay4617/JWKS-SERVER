import time
import jwt  # pyjwt

from keys import load_private_key


def create_jwt(kid: int, pem_str: str, expired: bool = False) -> str:
    """Create and sign RS256 JWT with given key."""
    now_ts = int(time.time())
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
