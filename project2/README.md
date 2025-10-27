# JWKS Server - Project 2

A Flask-based JWKS server that uses SQLite for key persistence.

## Overview
This server implements two endpoints:
- `POST /auth` - Returns signed JWTs
- `GET /.well-known/jwks.json` - Returns public keys in JWKS format

## Setup
```bash
source venv/bin/activate
python3 app.py
```

Server runs on http://127.0.0.1:8080

## Testing
```bash
coverage run -m pytest
coverage report -m
```

## Linting
```bash
flake8 .
```

## Endpoints

### POST /auth
Accepts username/password via Basic auth or JSON body.
- Add `?expired=true` to get an expired JWT
- Returns: `{"token": "..."}`

### GET /.well-known/jwks.json
Returns all valid public keys.
- Expired keys are not included

## Implementation Details
- SQLite database: `totally_not_my_privateKeys.db`
- Parameterized queries prevent SQL injection
- RSA-256 key signing
