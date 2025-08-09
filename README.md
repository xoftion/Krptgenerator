# 🔐 Advanced Cryptographic Key Generator

A robust, production-ready web application for generating secure cryptographic keys with comprehensive multi-format support, built with Flask and modern security practices.

## ✨ Features

### 🔑 Comprehensive Key Types
- **Symmetric Encryption**: Fernet, AES (128/192/256-bit)
- **Asymmetric Encryption**: RSA (2048/3072/4096-bit), Ed25519, ECDSA (P-256/384/521)
- **Key Derivation**: PBKDF2, Scrypt, HKDF (password-based and salt-based)
- **Message Authentication**: HMAC keys
- **Utilities**: Cryptographically secure random bytes

### 🎯 Multi-Format Output
- **Base64**: Standard and URL-safe (JWT) encoding
- **Hexadecimal**: Traditional hex format
- **PEM/DER**: Industry-standard certificate formats
- **Raw Bytes**: Direct binary output

### 🛡️ Security Features
- **Security Analysis**: Automatic key strength validation
- **Key Validation**: Built-in key format verification
- **Security Headers**: HSTS, CSP, XSS protection
- **Audit Logging**: Comprehensive security event logging
- **Session Management**: Secure session handling

### 🚀 Production Ready
- **Docker Support**: Complete containerization
- **Cloud Deployment**: Render.com ready configuration
- **Health Monitoring**: Built-in health checks
- **Performance**: Multi-worker WSGI deployment
- **Error Handling**: Comprehensive error management

## 🏗️ Architecture

### Backend (Python/Flask)
```
├── app.py              # Main application with all endpoints
├── main.py             # WSGI entry point
├── templates/          # Jinja2 templates
└── static/            # CSS/JS assets
```

### Key Endpoints
- `POST /generate_key` - Generate cryptographic keys
- `GET /api/key_types` - Get supported key types
- `POST /api/validate_key` - Validate existing keys
- `GET /health` - Health check endpoint

### Frontend (Bootstrap + Vanilla JS)
- **Dark Theme**: Professional Replit-themed UI
- **Responsive Design**: Mobile-friendly interface
- **Real-time Validation**: Client-side key validation
- **History Management**: Local key generation history
- **Copy to Clipboard**: One-click key copying

## 🚀 Quick Start

### Local Development
```bash
# Clone and setup
git clone <your-repo>
cd crypto-key-generator

# Install dependencies (using uv)
uv install

# Set environment variables
export SESSION_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")

# Run development server
python app.py
```

### Docker Deployment
```bash
# Build and run with Docker
docker build -t crypto-key-gen .
docker run -p 5000:5000 -e SESSION_SECRET=your-secret crypto-key-gen

# Or use Docker Compose
docker-compose up -d
```

### Render.com Deployment
1. Fork this repository
2. Connect to Render.com
3. Deploy using the included `render.yaml` configuration
4. Set environment variables in Render dashboard

## 🔧 Configuration

### Environment Variables
```bash
# Required
SESSION_SECRET=your-secure-session-secret-here

# Optional
FLASK_ENV=production          # Set to 'development' for debug mode
PORT=5000                    # Server port (auto-detected on most platforms)
```

### Security Configuration
The application automatically configures:
- **HTTPS Enforcement**: Strict Transport Security headers
- **Content Security Policy**: XSS and injection protection  
- **Session Security**: Secure cookie configuration
- **Input Validation**: Comprehensive request validation

## 📊 Usage Examples

### Python Integration
```python
# Example: Using generated Fernet key
from cryptography.fernet import Fernet

# Use your generated key
key = b'your-generated-fernet-key-here'
f = Fernet(key)

# Encrypt data
encrypted = f.encrypt(b"sensitive data")
decrypted = f.decrypt(encrypted)
```

### API Usage
```bash
# Generate AES-256 key
curl -X POST http://localhost:5000/generate_key \
  -H "Content-Type: application/json" \
  -d '{"type": "aes", "size": 256, "format": "hex"}'

# Validate existing key
curl -X POST http://localhost:5000/api/validate_key \
  -H "Content-Type: application/json" \
  -d '{"key": "your-key-here", "type": "aes"}'
```

## 🛡️ Security Best Practices

### Key Management
- **Never store keys in code**: Use environment variables or secure key management
- **Rotate keys regularly**: Implement key rotation policies
- **Separate key storage**: Store keys separately from encrypted data
- **Use appropriate key sizes**: Follow current cryptographic recommendations

### Application Security
- **HTTPS Only**: Always use HTTPS in production
- **Environment Isolation**: Separate development/staging/production environments
- **Regular Updates**: Keep dependencies updated
- **Audit Logging**: Monitor key generation activities

## 🔍 Key Types Guide

### Symmetric Encryption
- **Fernet**: Best for general-purpose encryption (recommended)
- **AES**: Low-level encryption for specific use cases

### Asymmetric Encryption
- **RSA**: Traditional public-key cryptography
- **Ed25519**: Modern, fast signature algorithm (recommended)
- **ECDSA**: Elliptic curve signatures for certificates

### Key Derivation
- **PBKDF2**: Password-based key derivation (widely supported)
- **Scrypt**: Memory-hard function (better against hardware attacks)
- **HKDF**: Key expansion and derivation

## 📈 Performance & Scalability

### Production Optimization
- **Multi-worker**: Gunicorn with 4+ workers
- **Caching**: Redis session storage (optional)
- **Load Balancing**: Nginx reverse proxy
- **Monitoring**: Built-in health checks

### Resource Requirements
- **Memory**: 256MB minimum, 512MB recommended
- **CPU**: 1 vCPU minimum, 2+ recommended for high load
- **Storage**: 1GB for application and logs

## 🤝 Contributing

### Development Setup
```bash
# Install development dependencies
uv install --dev

# Run tests
python -m pytest

# Code formatting
black app.py
flake8 app.py
```

### Security Guidelines
- Follow OWASP security practices
- Validate all user inputs
- Use parameterized queries
- Implement proper error handling
- Log security events appropriately

## 📜 License

MIT License - see LICENSE file for details.

## 🆘 Support

### Common Issues
1. **Key Generation Fails**: Check cryptography library installation
2. **Import Errors**: Ensure all dependencies are installed
3. **Session Issues**: Verify SESSION_SECRET is set
4. **Port Conflicts**: Change PORT environment variable

### Getting Help
- Check application logs for detailed error messages
- Verify environment variables are properly set
- Ensure all dependencies are compatible versions
- Review security headers in browser developer tools

---

**⚠️ Security Notice**: This application generates cryptographic keys locally and does not store them on the server. Always use generated keys immediately and store them securely in your own systems.