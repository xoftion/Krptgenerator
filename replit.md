# Overview

This is a cryptographic key generator web application built with Flask that provides a secure interface for generating various types of encryption keys. The application supports multiple key types including Fernet, AES, and RSA keys with different formats and sizes. It features a dark-themed Bootstrap UI with real-time key generation, clipboard functionality, and local history management for generated keys.

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
- **Key Generation**: Multiple cryptographic libraries (cryptography package)
- **Supported Algorithms**: 
  - Fernet (symmetric encryption with AES-128 CBC + HMAC-SHA256)
  - AES (128/192/256-bit keys)
  - RSA (asymmetric key pairs)
- **Key Formats**: Base64, hexadecimal, and raw binary encoding options
- **Session Security**: Environment-based secret key configuration

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