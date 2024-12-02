# JWKS Server Implementation

A secure JWKS (JSON Web Key Set) server implementation with robust user authentication, key encryption, and rate limiting.

## Features

- Secure user registration with UUID-based password generation
- AES encryption for private keys
- Password hashing using Argon2
- Authentication request logging
- Rate limiting (10 requests/second)
- 94% test coverage

## Setup

1. Create virtual environment:
```bash
python -m venv venv
.\venv\Scripts\activate  # On Windows
```

2. Install requirements:
```bash
pip install -r requirements.txt
```

3. Set environment variables in `.env`:
```
NOT_MY_KEY=your-encryption-key
FLASK_APP=app.py
FLASK_ENV=development
```

4. Run server:
```bash
python app.py
```

## Testing

Run tests with coverage:
```bash
coverage run -m pytest
coverage report --include="app.py"
```

## Project Structure
```
jwks_server/
├── .env                      # Environment variables
├── app.py                    # Main application
├── test_app.py              # Test suite
├── requirements.txt         # Project dependencies
├── README.md               # Documentation
└── totally_not_my_privateKeys.db  # Database file
```

## API Endpoints

### POST /register
Register new user with auto-generated password.

### POST /auth
Authenticate user with rate limiting.

### GET /health
Health check endpoint.

### Author
Bibekananda Pandey 
11811278
