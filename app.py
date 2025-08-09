import os
import logging
import datetime
import hashlib
import hmac
from flask import Flask, render_template, request, jsonify, session
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets
import base64
import uuid
import json
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging for production
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('app.log') if not os.environ.get('RENDER') else logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create Flask app with production settings
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Security headers middleware
@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.replit.com https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com"
    return response

@app.route('/')
def index():
    """Main page with key generator interface"""
    return render_template('index.html')

@app.route('/generate_key', methods=['POST'])
def generate_key():
    """Generate cryptographic keys based on type and parameters"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
            
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
            
        key_type = data.get('type', 'fernet')
        key_format = data.get('format', 'base64')
        key_size = data.get('size', 256)
        
        generated_key = None
        key_info = {}
        
        # Validate input parameters
        if key_type not in ['fernet', 'aes', 'rsa', 'ed25519', 'ecdsa', 'random', 'pbkdf2', 'scrypt', 'hkdf', 'hmac']:
            return jsonify({'error': 'Invalid key type'}), 400
            
        if key_format not in ['base64', 'hex', 'raw', 'pem', 'der', 'jwt']:
            return jsonify({'error': 'Invalid output format'}), 400
        
        if key_type == 'fernet':
            # Generate Fernet key
            fernet_key = Fernet.generate_key()
            generated_key = fernet_key
            key_info = {
                'type': 'Fernet',
                'size': '256 bits',
                'description': 'Symmetric encryption key for Fernet (AES 128 in CBC mode with HMAC-SHA256)',
                'use_cases': ['File encryption', 'Database encryption', 'Token encryption']
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
                'description': f'Advanced Encryption Standard key ({key_size}-bit)',
                'use_cases': ['Bulk data encryption', 'File encryption', 'Database encryption']
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
            
            # Serialize keys based on format
            if key_format in ['pem', 'base64']:
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
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
                        'description': f'RSA asymmetric key pair ({key_size}-bit)',
                        'use_cases': ['Digital signatures', 'Key exchange', 'Certificate generation']
                    }
                })
            
        elif key_type == 'ed25519':
            # Generate Ed25519 key pair (modern elliptic curve signature)
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
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
                    'type': 'Ed25519',
                    'size': '256 bits',
                    'description': 'Modern elliptic curve signature algorithm (EdDSA)',
                    'use_cases': ['Digital signatures', 'Authentication', 'Certificate signing']
                }
            })
            
        elif key_type == 'ecdsa':
            # Generate ECDSA key pair
            curve_map = {
                256: ec.SECP256R1(),
                384: ec.SECP384R1(),
                521: ec.SECP521R1()
            }
            key_size = int(key_size) if int(key_size) in curve_map else 256
            
            private_key = ec.generate_private_key(curve_map[key_size])
            public_key = private_key.public_key()
            
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
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
                    'type': 'ECDSA',
                    'size': f'{key_size} bits',
                    'description': f'Elliptic Curve Digital Signature Algorithm (P-{key_size})',
                    'use_cases': ['Digital signatures', 'SSL/TLS certificates', 'Blockchain transactions']
                }
            })
            
        elif key_type == 'pbkdf2':
            # Generate PBKDF2 derived key
            password = data.get('password', 'default_password').encode()
            salt = secrets.token_bytes(16)
            key_size = int(key_size) if int(key_size) >= 128 else 256
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=key_size // 8,
                salt=salt,
                iterations=100000
            )
            derived_key = kdf.derive(password)
            
            return jsonify({
                'success': True,
                'key': {
                    'value': format_key(derived_key, key_format),
                    'format': key_format
                },
                'salt': {
                    'value': format_key(salt, key_format),
                    'format': key_format
                },
                'info': {
                    'type': 'PBKDF2',
                    'size': f'{key_size} bits',
                    'description': 'Password-Based Key Derivation Function 2 with SHA-256',
                    'use_cases': ['Password hashing', 'Key stretching', 'Secure storage'],
                    'iterations': 100000
                }
            })
            
        elif key_type == 'scrypt':
            # Generate Scrypt derived key
            password = data.get('password', 'default_password').encode()
            salt = secrets.token_bytes(16)
            key_size = int(key_size) if int(key_size) >= 128 else 256
            
            kdf = Scrypt(
                length=key_size // 8,
                salt=salt,
                n=2**14,  # CPU/memory cost
                r=8,      # block size
                p=1       # parallelization
            )
            derived_key = kdf.derive(password)
            
            return jsonify({
                'success': True,
                'key': {
                    'value': format_key(derived_key, key_format),
                    'format': key_format
                },
                'salt': {
                    'value': format_key(salt, key_format),
                    'format': key_format
                },
                'info': {
                    'type': 'Scrypt',
                    'size': f'{key_size} bits',
                    'description': 'Scrypt key derivation function (memory-hard)',
                    'use_cases': ['Password hashing', 'Cryptocurrency mining', 'Secure storage'],
                    'parameters': 'N=16384, r=8, p=1'
                }
            })
            
        elif key_type == 'hkdf':
            # Generate HKDF derived key
            input_key_material = data.get('ikm', secrets.token_bytes(32))
            if isinstance(input_key_material, str):
                input_key_material = input_key_material.encode()
            salt = secrets.token_bytes(16)
            info = data.get('info', b'key derivation')
            if isinstance(info, str):
                info = info.encode()
            key_size = int(key_size) if int(key_size) >= 128 else 256
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=key_size // 8,
                salt=salt,
                info=info
            )
            derived_key = hkdf.derive(input_key_material)
            
            return jsonify({
                'success': True,
                'key': {
                    'value': format_key(derived_key, key_format),
                    'format': key_format
                },
                'salt': {
                    'value': format_key(salt, key_format),
                    'format': key_format
                },
                'info': {
                    'type': 'HKDF',
                    'size': f'{key_size} bits',
                    'description': 'HMAC-based Key Derivation Function with SHA-256',
                    'use_cases': ['Key derivation', 'Key expansion', 'Secure key generation']
                }
            })
            
        elif key_type == 'hmac':
            # Generate HMAC key
            key_size = int(key_size) if int(key_size) >= 128 else 256
            hmac_key = secrets.token_bytes(key_size // 8)
            generated_key = hmac_key
            key_info = {
                'type': 'HMAC',
                'size': f'{key_size} bits',
                'description': 'Hash-based Message Authentication Code key',
                'use_cases': ['Message authentication', 'Data integrity', 'API authentication']
            }
            
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
                'description': f'Cryptographically secure random bytes ({key_size}-bit)',
                'use_cases': ['Nonces', 'Salts', 'Initialization vectors', 'Session tokens']
            }
        
        # Format the key based on requested format
        if generated_key is not None:
            formatted_key = format_key(generated_key, key_format)
            
            # Validate key strength
            security_level, recommendations = validate_key_strength(key_info['type'].lower(), int(key_size) if isinstance(key_size, (str, int)) else 256)
            key_info['security_level'] = security_level
            key_info['recommendations'] = recommendations
            
            # Store in session history
            if 'key_history' not in session:
                session['key_history'] = []
            
            history_entry = {
                'id': str(uuid.uuid4()),
                'type': key_info['type'],
                'size': key_info['size'],
                'format': key_format,
                'value': formatted_key,
                'timestamp': datetime.datetime.now().isoformat(),
                'security_level': security_level
            }
            
            session['key_history'].insert(0, history_entry)
            # Keep only last 20 keys
            session['key_history'] = session['key_history'][:20]
            session.modified = True
            
            # Log key generation for security audit
            logger.info(f"Key generated: type={key_info['type']}, size={key_info['size']}, format={key_format}, security_level={security_level}")
            
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
    elif format_type == 'pem':
        # For PEM format, return base64 with proper line breaks
        b64_key = base64.b64encode(key_bytes).decode('utf-8')
        # Split into 64-character lines
        lines = [b64_key[i:i+64] for i in range(0, len(b64_key), 64)]
        return '-----BEGIN KEY-----\n' + '\n'.join(lines) + '\n-----END KEY-----'
    elif format_type == 'der':
        # DER is binary format, return as base64
        return base64.b64encode(key_bytes).decode('utf-8')
    elif format_type == 'jwt':
        # JWT-style base64url encoding (no padding)
        return base64.urlsafe_b64encode(key_bytes).decode('utf-8').rstrip('=')
    else:
        return base64.b64encode(key_bytes).decode('utf-8')

def validate_key_strength(key_type, key_size):
    """Validate key strength and provide security recommendations"""
    recommendations = []
    security_level = "High"
    
    if key_type == 'rsa':
        if key_size < 2048:
            security_level = "Low"
            recommendations.append("Use at least 2048-bit RSA keys")
        elif key_size < 3072:
            security_level = "Medium"
            recommendations.append("Consider 3072-bit or 4096-bit keys for long-term security")
    elif key_type == 'aes':
        if key_size < 256:
            security_level = "Medium"
            recommendations.append("Use 256-bit AES keys for maximum security")
    elif key_type in ['random', 'hmac']:
        if key_size < 256:
            security_level = "Medium"
            recommendations.append("Use at least 256 bits for cryptographic keys")
    
    return security_level, recommendations

@app.route('/get_history')
def get_history():
    """Get key generation history from session"""
    history = session.get('key_history', [])
    return jsonify({'history': history})

@app.route('/clear_history', methods=['POST'])
def clear_history():
    """Clear key generation history"""
    try:
        session['key_history'] = []
        session.modified = True
        logger.info("Key generation history cleared")
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error clearing history: {str(e)}")
        return jsonify({'error': 'Failed to clear history'}), 500

@app.route('/api/key_types')
def get_key_types():
    """Get available key types and their configurations"""
    key_types = {
        'fernet': {
            'name': 'Fernet',
            'description': 'Symmetric encryption with AES-128 CBC + HMAC-SHA256',
            'sizes': [256],
            'formats': ['base64', 'hex', 'raw'],
            'use_cases': ['File encryption', 'Database encryption', 'Token encryption']
        },
        'aes': {
            'name': 'AES',
            'description': 'Advanced Encryption Standard',
            'sizes': [128, 192, 256],
            'formats': ['base64', 'hex', 'raw', 'pem'],
            'use_cases': ['Bulk data encryption', 'File encryption', 'Database encryption']
        },
        'rsa': {
            'name': 'RSA',
            'description': 'RSA asymmetric key pairs',
            'sizes': [2048, 3072, 4096],
            'formats': ['pem', 'der'],
            'use_cases': ['Digital signatures', 'Key exchange', 'Certificate generation']
        },
        'ed25519': {
            'name': 'Ed25519',
            'description': 'Modern elliptic curve signature algorithm',
            'sizes': [256],
            'formats': ['pem', 'der'],
            'use_cases': ['Digital signatures', 'Authentication', 'Certificate signing']
        },
        'ecdsa': {
            'name': 'ECDSA',
            'description': 'Elliptic Curve Digital Signature Algorithm',
            'sizes': [256, 384, 521],
            'formats': ['pem', 'der'],
            'use_cases': ['Digital signatures', 'SSL/TLS certificates', 'Blockchain transactions']
        },
        'pbkdf2': {
            'name': 'PBKDF2',
            'description': 'Password-Based Key Derivation Function 2',
            'sizes': [128, 192, 256, 512],
            'formats': ['base64', 'hex', 'raw'],
            'use_cases': ['Password hashing', 'Key stretching', 'Secure storage'],
            'requires_password': True
        },
        'scrypt': {
            'name': 'Scrypt',
            'description': 'Memory-hard key derivation function',
            'sizes': [128, 192, 256, 512],
            'formats': ['base64', 'hex', 'raw'],
            'use_cases': ['Password hashing', 'Cryptocurrency mining', 'Secure storage'],
            'requires_password': True
        },
        'hkdf': {
            'name': 'HKDF',
            'description': 'HMAC-based Key Derivation Function',
            'sizes': [128, 192, 256, 512],
            'formats': ['base64', 'hex', 'raw'],
            'use_cases': ['Key derivation', 'Key expansion', 'Secure key generation']
        },
        'hmac': {
            'name': 'HMAC',
            'description': 'Hash-based Message Authentication Code key',
            'sizes': [128, 192, 256, 512],
            'formats': ['base64', 'hex', 'raw'],
            'use_cases': ['Message authentication', 'Data integrity', 'API authentication']
        },
        'random': {
            'name': 'Random',
            'description': 'Cryptographically secure random bytes',
            'sizes': [64, 128, 256, 512, 1024, 2048],
            'formats': ['base64', 'hex', 'raw', 'jwt'],
            'use_cases': ['Nonces', 'Salts', 'Initialization vectors', 'Session tokens']
        }
    }
    return jsonify(key_types)

@app.route('/api/validate_key', methods=['POST'])
def validate_key():
    """Validate a key and provide security analysis"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
            
        data = request.get_json()
        key_value = data.get('key', '')
        key_type = data.get('type', '')
        
        if not key_value or not key_type:
            return jsonify({'error': 'Key value and type are required'}), 400
        
        # Basic validation
        analysis = {
            'valid': False,
            'length': len(key_value),
            'entropy_estimate': 0,
            'format_detected': 'unknown',
            'security_level': 'unknown',
            'recommendations': []
        }
        
        # Detect format
        try:
            if key_value.startswith('-----BEGIN'):
                analysis['format_detected'] = 'PEM'
            elif all(c in '0123456789abcdefABCDEF' for c in key_value):
                analysis['format_detected'] = 'hex'
                analysis['valid'] = True
            else:
                base64.b64decode(key_value)
                analysis['format_detected'] = 'base64'
                analysis['valid'] = True
        except:
            analysis['format_detected'] = 'raw'
        
        # Estimate entropy (simple method)
        if analysis['valid']:
            unique_chars = len(set(key_value))
            analysis['entropy_estimate'] = unique_chars * 4  # Rough estimate
        
        return jsonify(analysis)
        
    except Exception as e:
        logger.error(f"Error validating key: {str(e)}")
        return jsonify({'error': 'Validation failed'}), 500

@app.route('/health')
def health_check():
    """Health check endpoint for deployment monitoring"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.now().isoformat(),
        'version': '2.0.0'
    })

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
