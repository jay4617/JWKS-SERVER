from flask import Flask, request, jsonify
import jwt
import base64
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from database import init_database, generate_and_store_keys, get_private_key, get_valid_keys

app = Flask(__name__)

def rsa_to_jwk(key_pem, kid):
    """Convert RSA private key PEM to JWK format for public key.
    Args:
        key_pem: RSA private key in PEM format
        kid: Key ID
    Returns:
        Dictionary containing JWK formatted public key
    """
    # Import the private key and get public key
    private_key = RSA.import_key(key_pem)
    public_key = private_key.publickey()
    
    # Get modulus and exponent
    n = public_key.n
    e = public_key.e
    
    # Convert to base64url encoding
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')
    
    n_b64 = base64.urlsafe_b64encode(n_bytes).rstrip(b'=').decode('utf-8')
    e_b64 = base64.urlsafe_b64encode(e_bytes).rstrip(b'=').decode('utf-8')
    
    return {
        'kty': 'RSA',
        'use': 'sig',
        'kid': str(kid),
        'alg': 'RS256',
        'n': n_b64,
        'e': e_b64
    }

@app.route('/auth', methods=['POST'])
def auth():
    """Authenticate user and return JWT.
    Query parameters:
        expired: If present, sign JWT with expired key
    Returns:
        JSON containing JWT token
    """
    # Check for expired query parameter
    expired = request.args.get('expired', None) is not None
    
    # Get appropriate key from database
    kid, key_pem = get_private_key(expired=expired)
    
    if not key_pem:
        return jsonify({'error': 'No suitable key found'}), 500
    
    # Deserialize the key from PEM format
    private_key = RSA.import_key(key_pem)
    
    # Create JWT payload
    payload = {
        'user': 'userABC',
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    
    # Sign JWT with the private key
    token = jwt.encode(
        payload,
        private_key.export_key('PEM'),
        algorithm='RS256',
        headers={'kid': str(kid)}
    )
    
    return jsonify({'token': token})

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """Serve JWKS containing all valid public keys.
    Returns:
        JSON containing JWKS with all non-expired public keys
    """
    # Get all valid keys from database
    valid_keys = get_valid_keys()
    
    # Convert to JWK format
    keys = []
    for kid, key_pem in valid_keys:
        jwk = rsa_to_jwk(key_pem, kid)
        keys.append(jwk)
    
    return jsonify({'keys': keys})

if __name__ == '__main__':
    # Initialize database and generate keys on startup
    init_database()
    generate_and_store_keys()
    
    # Run server
    app.run(host='0.0.0.0', port=8080, debug=True)
