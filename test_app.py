import pytest
import json
import uuid
import os
from app import app, init_db, encrypt_key, decrypt_key
from test_config import TEST_DB

@pytest.fixture
def client():
    """Test client fixture"""
    app.config['TESTING'] = True
    app.config['DATABASE'] = TEST_DB
    with app.test_client() as client:
        init_db()  # Initialize fresh database
        yield client
        # Cleanup
        if os.path.exists(TEST_DB):
            os.remove(TEST_DB)

def test_health_check(client):
    """Test health endpoint"""
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json["status"] == "healthy"

def test_register_flow(client):
    """Test complete registration flow"""
    username = f"test_{uuid.uuid4().hex[:8]}"
    
    # Test successful registration
    response = client.post('/register', json={
        "username": username,
        "email": f"{username}@test.com"
    })
    assert response.status_code == 201
    assert "password" in response.json
    password = response.json["password"]
    
    # Test duplicate registration
    response = client.post('/register', json={
        "username": username,
        "email": f"{username}@test.com"
    })
    assert response.status_code == 409
    
    # Test missing fields
    response = client.post('/register', json={})
    assert response.status_code == 400

def test_auth_flow(client):
    """Test authentication flow"""
    # Register a user first
    username = f"auth_{uuid.uuid4().hex[:8]}"
    reg_response = client.post('/register', json={
        "username": username,
        "email": f"{username}@test.com"
    })
    password = reg_response.json["password"]
    
    # Test successful auth
    auth_response = client.post('/auth', json={
        "username": username,
        "password": password
    })
    assert auth_response.status_code == 200
    
    # Test wrong password
    auth_response = client.post('/auth', json={
        "username": username,
        "password": "wrong_password"
    })
    assert auth_response.status_code == 401
    
    # Test non-existent user
    auth_response = client.post('/auth', json={
        "username": "nonexistent",
        "password": "test"
    })
    assert auth_response.status_code == 401
    
    # Test missing fields
    auth_response = client.post('/auth', json={})
    assert auth_response.status_code == 400

def test_rate_limiting(client):
    """Test rate limiting"""
    # Register a user
    username = f"rate_{uuid.uuid4().hex[:8]}"
    reg_response = client.post('/register', json={
        "username": username,
        "email": f"{username}@test.com"
    })
    password = reg_response.json["password"]
    
    # Make requests to trigger rate limit
    responses = []
    for _ in range(12):  # Make more than limit
        response = client.post('/auth', json={
            "username": username,
            "password": password
        })
        responses.append(response.status_code)
    
    assert 429 in responses  # Should see rate limit response

def test_encryption():
    """Test encryption functions"""
    test_data = "test_secret_data"
    encrypted = encrypt_key(test_data)
    decrypted = decrypt_key(encrypted)
    assert decrypted == test_data
    assert encrypted != test_data

# Run additional tests for edge cases
def test_edge_cases(client):
    """Test various edge cases"""
    # Invalid JSON
    response = client.post('/auth', data="invalid json")
    assert response.status_code in [400, 401]
    
    # Empty request body
    response = client.post('/auth')
    assert response.status_code in [400, 401]
    
    # Invalid content type
    response = client.post('/auth', data="test=1", content_type='application/x-www-form-urlencoded')
    assert response.status_code in [400, 401]