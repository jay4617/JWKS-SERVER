# JWKS Server - Project 3

A Flask-based JWKS server with SQLite persistence and enhanced security features.

## Overview
This server implements secure authentication with JWKS (JSON Web Key Set) support:
- `POST /auth` - Returns signed JWTs (rate-limited, with logging)
- `POST /register` - User registration with secure password generation
- `GET /.well-known/jwks.json` - Returns public keys in JWKS format

## 🔒 Security Features (Project 3)

- **AES-256 Encryption**: Private keys encrypted at rest using NOT_MY_KEY environment variable
- **Argon2 Password Hashing**: Industry-standard password hashing for user accounts
- **Authentication Logging**: All auth requests logged with IP, timestamp, and user ID
- **Rate Limiting**: 10 requests/second limit on /auth endpoint (returns 429 if exceeded)
- **Secure Password Generation**: UUIDv4-based passwords with 128-bit entropy

For detailed security documentation, see [SECURITY_ENHANCEMENTS.md](SECURITY_ENHANCEMENTS.md)

## Setup

### 1. Install Dependencies
```bash
pip3 install -r requirements.txt
```

### 2. Set Environment Variable
⚠️ **REQUIRED**: Set the encryption key before starting the server:
```bash
export NOT_MY_KEY="your-secret-encryption-key-here"
```

⚠️ **NEVER commit this key to version control!**

### 3. Run Server
```bash
python3 app.py
```

Server runs on http://127.0.0.1:8080

## Testing

### Run Test Suite
```bash
# Set environment variable first
export NOT_MY_KEY="test-key"

# Run tests
python3 test_new_features.py

# Or with coverage
coverage run test_new_features.py
coverage report -m
```

## Linting
```bash
flake8 .
```

## Endpoints

### POST /register
Register a new user with auto-generated password.

**Request:**
```json
{
  "username": "alice",
  "email": "alice@example.com"
}
```

**Response (201 CREATED):**
```json
{
  "password": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

### POST /auth
Authenticate and receive a signed JWT.

**Rate Limit:** 10 requests per second

**Request:**
```json
{
  "username": "alice",
  "password": "password-from-registration"
}
```

**Response (200 OK):**
```json
{
  "token": "eyJhbGc..."
}
```

### GET /.well-known/jwks.json
Returns all valid (non-expired) public keys in JWKS format.

## Database Schema

### Tables
1. **keys** - Encrypted RSA private keys
2. **users** - User accounts with Argon2-hashed passwords
3. **auth_logs** - Authentication request logs

## Educational Use Only
⚠️ This implementation is for **educational purposes only**.

## Files
- `app.py` - Flask application
- `db.py` - Database operations with encryption
- `auth.py` - JWT creation
- `keys.py` - RSA key generation
- `test_new_features.py` - Test suite
- `SECURITY_ENHANCEMENTS.md` - Security documentation
