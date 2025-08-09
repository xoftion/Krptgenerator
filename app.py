import os
import logging
from flask import Flask, render_template, request, jsonify, session
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import secrets
import base64
import uuid

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

@app.route('/')
def index():
    """Main page with key generator interface"""
    return render_template('index.html')

@app.route('/generate_key', methods=['POST'])
def generate_key():
    """Generate cryptographic keys based on type and parameters"""
    try:
        key_type = request.json.get('type', 'fernet')
        key_format = request.json.get('format', 'base64')
        key_size = request.json.get('size', 256)
        
        generated_key = None
        key_info = {}
        
        if key_type == 'fernet':
            # Generate Fernet key
            fernet_key = Fernet.generate_key()
            generated_key = fernet_key
            key_info = {
                'type': 'Fernet',
                'size': '256 bits',
                'description': 'Symmetric encryption key for Fernet (AES 128 in CBC mode with HMAC-SHA256)'
            }
            
        elif key_type == 'aes':
            # Generate AES key
            key_size = int(key_size)
            if key_size not in [128, 192, 256]:
                return jsonify({'error': 'AES key size must be 128, 192, or 256 bits'}), 400
            
            aes_key = secrets.token_bytes(key_size // 8)
            generated_key = aes_key
            key_info = {
                'type': 'AES',
                'size': f'{key_size} bits',
                'description': f'Advanced Encryption Standard key ({key_size}-bit)'
            }
            
        elif key_type == 'rsa':
            # Generate RSA key pair
            key_size = int(key_size)
            if key_size not in [2048, 3072, 4096]:
                return jsonify({'error': 'RSA key size must be 2048, 3072, or 4096 bits'}), 400
            
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )
            
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key
            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return jsonify({
                'success': True,
                'private_key': {
                    'value': private_pem.decode('utf-8'),
                    'format': 'PEM'
                },
                'public_key': {
                    'value': public_pem.decode('utf-8'),
                    'format': 'PEM'
                },
                'info': {
                    'type': 'RSA',
                    'size': f'{key_size} bits',
                    'description': f'RSA asymmetric key pair ({key_size}-bit)'
                }
            })
            
        elif key_type == 'random':
            # Generate random bytes
            key_size = int(key_size)
            if key_size < 8 or key_size > 4096:
                return jsonify({'error': 'Random key size must be between 8 and 4096 bits'}), 400
            
            random_key = secrets.token_bytes(key_size // 8)
            generated_key = random_key
            key_info = {
                'type': 'Random',
                'size': f'{key_size} bits',
                'description': f'Cryptographically secure random bytes ({key_size}-bit)'
            }
            
        else:
            return jsonify({'error': 'Invalid key type'}), 400
        
        # Format the key based on requested format
        if generated_key is not None:
            formatted_key = format_key(generated_key, key_format)
            
            # Store in session history
            if 'key_history' not in session:
                session['key_history'] = []
            
            history_entry = {
                'id': str(uuid.uuid4()),
                'type': key_info['type'],
                'size': key_info['size'],
                'format': key_format,
                'value': formatted_key,
                'timestamp': str(int(secrets.token_hex(4), 16))  # Simple timestamp replacement
            }
            
            session['key_history'].insert(0, history_entry)
            # Keep only last 10 keys
            session['key_history'] = session['key_history'][:10]
            session.modified = True
            
            return jsonify({
                'success': True,
                'key': {
                    'value': formatted_key,
                    'format': key_format
                },
                'info': key_info
            })
    
    except Exception as e:
        logging.error(f"Error generating key: {str(e)}")
        return jsonify({'error': f'Key generation failed: {str(e)}'}), 500

def format_key(key_bytes, format_type):
    """Format key bytes in the requested format"""
    if format_type == 'base64':
        return base64.b64encode(key_bytes).decode('utf-8')
    elif format_type == 'hex':
        return key_bytes.hex()
    elif format_type == 'raw':
        return key_bytes.decode('latin-1')  # Preserve all bytes
    else:
        return base64.b64encode(key_bytes).decode('utf-8')

@app.route('/get_history')
def get_history():
    """Get key generation history from session"""
    history = session.get('key_history', [])
    return jsonify({'history': history})

@app.route('/clear_history', methods=['POST'])
def clear_history():
    """Clear key generation history"""
    session['key_history'] = []
    session.modified = True
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
