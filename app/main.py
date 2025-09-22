"""Educational JWKS Server.

A FastAPI-based JWKS server implementation that:
- Generates RSA key pairs with unique identifiers (kid) and expiry timestamps
- Serves a RESTful JWKS endpoint with only unexpired keys
- Issues JWTs at /auth endpoint with option to issue expired tokens
- Implements proper HTTP method handling and status codes

This is for educational purposes only. Do not use in production.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.keys import KeyStore
from app.models import JWKS

app = FastAPI(title="Educational JWKS Server", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global store used by tests as well
store = KeyStore()


@app.get("/.well-known/jwks.json", response_model=JWKS, tags=["jwks"])
@app.get("/jwks", response_model=JWKS, include_in_schema=False)
def get_jwks():
    """Return unexpired public keys only."""
    return store.jwks()


@app.post("/.well-known/jwks.json", tags=["jwks"])
def post_jwks_not_allowed():
    """JWKS endpoint does not support POST method."""
    raise HTTPException(status_code=405, detail="Method Not Allowed")


@app.post("/auth", tags=["auth"])
async def post_auth(request: Request):
    """Issue a JWT. If `?expired=1` is present, use the expired key and expired exp claim."""
    use_expired = request.query_params.get("expired") is not None
    token = store.sign_jwt(use_expired=use_expired)
    return JSONResponse({"token": token}, status_code=status.HTTP_200_OK)


@app.get("/auth", tags=["auth"])
def get_auth_not_allowed():
    """Auth endpoint does not support GET method."""
    raise HTTPException(status_code=405, detail="Method Not Allowed")
