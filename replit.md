# Overview

This is a production-ready, advanced cryptographic key generator web application built with Flask. The application provides a comprehensive interface for generating multiple types of encryption keys with extensive format support, security validation, and enterprise-grade features. It supports symmetric encryption (Fernet, AES), asymmetric encryption (RSA, Ed25519, ECDSA), key derivation functions (PBKDF2, Scrypt, HKDF), and message authentication codes (HMAC). The application features a professional dark-themed Bootstrap UI, real-time key validation, security analysis, clipboard functionality, and comprehensive history management.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Template Engine**: Jinja2 templates with a single-page application structure
- **Styling Framework**: Bootstrap with dark theme and Font Awesome icons
- **JavaScript Architecture**: Class-based vanilla JavaScript with modular design pattern
- **UI Components**: Toast notifications, modal dialogs, and responsive grid layout
- **State Management**: Local browser storage for key generation history

## Backend Architecture
- **Web Framework**: Flask with a lightweight, single-module design
- **Route Structure**: RESTful API endpoints with JSON responses
- **Session Management**: Flask sessions with configurable secret keys
- **Error Handling**: Centralized error responses with appropriate HTTP status codes
- **Logging**: Python logging module with debug-level configuration

## Security Architecture
- **Key Generation**: Advanced cryptographic libraries (cryptography package v41+)
- **Supported Algorithms**: 
  - **Symmetric**: Fernet (AES-128 CBC + HMAC-SHA256), AES (128/192/256-bit)
  - **Asymmetric**: RSA (2048/3072/4096-bit), Ed25519, ECDSA (P-256/384/521)
  - **Key Derivation**: PBKDF2 (100k iterations), Scrypt (N=16384), HKDF
  - **Message Authentication**: HMAC keys, secure random bytes
- **Key Formats**: Base64, Base64URL (JWT), Hexadecimal, PEM, DER, Raw binary
- **Security Features**: 
  - Key strength validation and security recommendations
  - Comprehensive security headers (HSTS, CSP, XSS protection)
  - Input validation and sanitization
  - Audit logging for security events
- **Session Security**: Environment-based secret key with automatic generation

## Data Flow
- **Client-Side**: Form submission triggers AJAX requests to backend
- **Server-Side**: Key generation occurs in-memory without persistence
- **Response Format**: JSON with key data, metadata, and error handling
- **History Management**: Client-side storage only, no server-side persistence

# External Dependencies

## Python Packages
- **Flask**: Web framework for HTTP handling and templating
- **cryptography**: Primary cryptographic library for key generation
- **secrets**: Secure random number generation
- **base64**: Encoding/decoding utilities

## Frontend Libraries
- **Bootstrap**: CSS framework loaded from CDN
- **Font Awesome**: Icon library for UI elements
- **Vanilla JavaScript**: No external JavaScript frameworks

## Environment Dependencies
- **SESSION_SECRET**: Environment variable for Flask session encryption
- **Python Runtime**: Standard library modules (os, logging, uuid)

## Development Tools
- **Replit Environment**: Configured for web hosting and development
- **Static File Serving**: Flask's built-in static file handler