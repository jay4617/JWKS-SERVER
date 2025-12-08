# Security Enhancements for JWKS Server

This document describes the security enhancements implemented in the JWKS server as part of Project 3.

## Overview

The following security features have been added:
1. **AES Encryption** for private keys in the database
2. **User Registration** with secure password generation and Argon2 hashing
3. **Authentication Logging** to track authentication requests
4. **Rate Limiting** to prevent abuse of the authentication endpoint

---

## 1. AES Encryption of Private Keys

### Implementation
- Private keys are encrypted using **AES-256-CBC** before being stored in the database
- Encryption key is derived from the `NOT_MY_KEY` environment variable using SHA-256
- Each encrypted key includes a random 16-byte initialization vector (IV) prepended to the ciphertext
- Keys are automatically decrypted when retrieved from the database

### Security Features
- **Algorithm**: AES-256 in CBC mode with PKCS7 padding
- **Key Derivation**: SHA-256 hash of environment variable ensures consistent 32-byte key
- **IV Management**: Random IV for each encryption operation (stored with ciphertext)
- **Automatic Handling**: Encryption/decryption is transparent to application code

### Environment Setup
```bash
export NOT_MY_KEY="your-secret-encryption-key-here"
```

⚠️ **IMPORTANT**: Never commit the `NOT_MY_KEY` value to version control!

### Code Location
- `db.py:_get_aes_key()` - Retrieves and derives AES key from environment
- `db.py:_encrypt_key()` - Encrypts PEM-encoded private keys
- `db.py:_decrypt_key()` - Decrypts encrypted private keys

---

## 2. User Registration

### Endpoint: `POST /register`

#### Request Format
```json
{
  "username": "johndoe",
  "email": "john@example.com"
}
```

- `username` (required): Desired username (must be unique)
- `email` (optional): Email address (must be unique if provided)

#### Response Format

**Success (201 CREATED):**
```json
{
  "password": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

**Error (400 BAD REQUEST):**
```json
{
  "error": "username is required"
}
```

**Error (409 CONFLICT):**
```json
{
  "error": "username already exists"
}
```

### Security Features
- **Password Generation**: Secure UUIDv4-based passwords (128-bit entropy)
- **Password Hashing**: Argon2id algorithm with default parameters
- **One-Time Password Display**: Password is only returned once during registration

### Database Schema
```sql
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
```

### Code Location
- `app.py:register_route()` - Registration endpoint handler
- `db.py:insert_user()` - Database insertion for new users
- `db.py:get_user_by_username()` - User lookup by username

---

## 3. Authentication Logging

### Implementation
All successful authentication requests to `POST /auth` are logged to the `auth_logs` table.

### Logged Information
- **Request IP Address**: Client IP making the request
- **Timestamp**: Automatic timestamp when request was received
- **User ID**: Foreign key reference to users table (if username exists)

### Database Schema
```sql
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
```

### Behavior
- Logs are created **only for successful requests** (status 200)
- If username exists in database, `user_id` is recorded
- If username is not registered, `user_id` is NULL
- `last_login` timestamp is updated for registered users

### Code Location
- `db.py:log_auth_request()` - Inserts log entry
- `db.py:update_last_login()` - Updates user's last login timestamp
- `app.py:auth_route()` - Calls logging functions after successful auth

---

## 4. Rate Limiting

### Implementation
The `/auth` endpoint is rate-limited to **10 requests per second** per IP address.

### Behavior
- Uses **Flask-Limiter** with in-memory storage
- Rate limit applies per IP address (identified via `get_remote_address()`)
- Requests exceeding the limit receive **429 Too Many Requests** response
- Rate limit is enforced **before** authentication logic runs
- Only successful requests (within rate limit) are logged

### Configuration
```python
@limiter.limit("10 per second")
@app.route("/auth", methods=["POST"])
def auth_route():
    # ...
```

### Code Location
- `app.py` - Flask-Limiter initialization and decorator on `/auth` endpoint

---

## Testing

### Run Test Suite
```bash
# Set environment variable
export NOT_MY_KEY="test-encryption-key-do-not-use-in-production"

# Run test suite
python3 test_new_features.py
```

### Manual Testing

#### 1. Register a User
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com"}'
```

#### 2. Authenticate
```bash
curl -X POST http://localhost:8080/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"<password-from-registration>"}'
```

#### 3. Check Auth Logs
```bash
sqlite3 totally_not_my_privateKeys.db "SELECT * FROM auth_logs;"
```

#### 4. Verify Encryption
```bash
sqlite3 totally_not_my_privateKeys.db "SELECT hex(substr(key,1,32)) FROM keys LIMIT 1;"
# Should show hex-encoded encrypted data, NOT "2d2d2d2d2d424547494e" (which is "-----BEGIN")
```

---

## Security Best Practices

### ✅ Implemented
- AES-256 encryption for sensitive data at rest
- Argon2id password hashing (industry standard, resistant to GPU attacks)
- Random IV for each encryption operation
- Rate limiting to prevent brute force attacks
- Authentication logging for security auditing
- Environment variable for encryption key (not hardcoded)
- Secure password generation with high entropy (UUIDv4)

### ⚠️ For Production Systems
This implementation is for **educational purposes only**. Production systems should include:
- Use hardware security modules (HSM) or key management services (KMS)
- Implement key rotation mechanisms
- Use TLS/HTTPS for all communications
- Add proper authentication/authorization checks
- Implement account lockout after failed login attempts
- Add session management and token revocation
- Use structured logging with security monitoring
- Implement CSRF protection
- Add input validation and sanitization
- Use prepared statements for all SQL queries (already done)
- Regular security audits and penetration testing

---

## Dependencies Added

```
argon2-cffi==23.1.0          # Argon2 password hashing
argon2-cffi-bindings==21.2.0 # C bindings for Argon2
Flask-Limiter==3.8.0          # Rate limiting for Flask
limits==3.16.1                # Rate limiting backend
```

---

## Troubleshooting

### Error: "NOT_MY_KEY environment variable must be set"
**Solution**: Set the environment variable before starting the server:
```bash
export NOT_MY_KEY="your-secret-key"
```

### Error: "username already exists"
**Solution**: Choose a different username or check existing users:
```bash
sqlite3 totally_not_my_privateKeys.db "SELECT username FROM users;"
```

### 429 Too Many Requests
**Solution**: This is expected when exceeding 10 requests/second. Wait a second and retry.

---

## References

- [AES-256 Encryption](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
- [Argon2 Password Hashing](https://github.com/P-H-C/phc-winner-argon2)
- [Flask-Limiter Documentation](https://flask-limiter.readthedocs.io/)
- [RFC 6585 - HTTP Status Code 429](https://tools.ietf.org/html/rfc6585)
- [UUID Version 4](https://en.wikipedia.org/wiki/Universally_unique_identifier#Version_4_(random))
