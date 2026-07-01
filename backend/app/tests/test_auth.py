import pytest
from unittest.mock import patch
from app.config import settings
from app.services.encryption import encrypt_token, decrypt_token
from app.services.auth import create_jwt_token, verify_jwt_token

from cryptography.fernet import Fernet

from datetime import datetime, timezone, timedelta
import time

def test_fernet_encryption_decryption():
    original_token = "gho_12345abcdefghijklmnopqrstuvwxyz"
    encrypted = encrypt_token(original_token)
    assert encrypted != original_token
    
    decrypted = decrypt_token(encrypted)
    assert decrypted == original_token

def test_fernet_empty_token():
    assert encrypt_token("") == ""
    assert decrypt_token("") == ""

def test_jwt_lifecycle():
    user_id = "550e8400-e29b-41d4-a716-446655440000"
    
    # 1. Access Token Lifecycle
    access_token = create_jwt_token(user_id, token_type="access")
    assert isinstance(access_token, str)
    access_payload = verify_jwt_token(access_token, expected_type="access")
    assert access_payload is not None
    assert access_payload["sub"] == user_id
    assert access_payload["type"] == "access"
    
    # 2. Refresh Token Lifecycle
    refresh_token = create_jwt_token(user_id, token_type="refresh")
    assert isinstance(refresh_token, str)
    refresh_payload = verify_jwt_token(refresh_token, expected_type="refresh")
    assert refresh_payload is not None
    assert refresh_payload["sub"] == user_id
    assert refresh_payload["type"] == "refresh"
    
    # 3. Cross-token type rejection
    assert verify_jwt_token(access_token, expected_type="refresh") is None
    assert verify_jwt_token(refresh_token, expected_type="access") is None

def test_jwt_invalid_token():
    assert verify_jwt_token("invalid.token.value", expected_type="access") is None
    assert verify_jwt_token("invalid.token.value", expected_type="refresh") is None

def test_jwt_expired_token():
    user_id = "550e8400-e29b-41d4-a716-446655440000"
    
    # create a token that expires in 1 second
    with patch.object(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 1/60):
        token = create_jwt_token(user_id)
    
    time.sleep(2)  # wait for it to expire
    
    assert verify_jwt_token(token, expected_type="access") is None

def test_jwt_tampered_token():
    user_id = "550e8400-e29b-41d4-a716-446655440000"
    token = create_jwt_token(user_id, token_type="access")
    
    # a JWT is three base64 segments separated by dots
    # tamper with the payload segment (middle part)
    parts = token.split(".")
    parts[1] = parts[1][:-4] + "xxxx"  # corrupt the payload
    tampered = ".".join(parts)
    
    assert verify_jwt_token(tampered, expected_type="access") is None

def test_jwt_wrong_secret():
    import jwt as pyjwt
    
    # manually create a token signed with a fake secret
    fake_payload = {
        "sub": "550e8400-e29b-41d4-a716-446655440000",
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30)
    }
    fake_token = pyjwt.encode(fake_payload, "wrong_secret_key", algorithm="HS256")
    
    assert verify_jwt_token(fake_token, expected_type="access") is None

def test_jwt_missing_sub():
    import jwt as pyjwt
    from app.config import settings
    
    payload = {
        "type": "access",
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30)
        # deliberately no "sub"
    }
    token = pyjwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    
    assert verify_jwt_token(token, expected_type="access") is None


def test_fernet_wrong_key():
    original = "gho_12345abcdefghijklmnopqrstuvwxyz"
    encrypted = encrypt_token(original)
    
    # generate a completely different key and try to decrypt with it
    different_key = Fernet.generate_key()
    different_fernet = Fernet(different_key)
    
    with pytest.raises(Exception):  # should raise InvalidToken
        different_fernet.decrypt(encrypted.encode())


def test_get_current_user_cookie():
    from unittest.mock import MagicMock
    from fastapi import HTTPException
    from app.services.auth import get_current_user
    from app.models.users import User
    from app.models.token_blocklist import TokenBlocklist

    user_id = "550e8400-e29b-41d4-a716-446655440000"
    token = create_jwt_token(user_id, token_type="access")

    mock_user = User(id=user_id, github_login="test_user")

    # Return None for blocklist (token is not blocked), mock_user for User lookup
    def query_side_effect(model):
        mock_q = MagicMock()
        if model is TokenBlocklist:
            mock_q.filter.return_value.first.return_value = None
        else:
            mock_q.filter.return_value.first.return_value = mock_user
        return mock_q

    mock_db = MagicMock()
    mock_db.query.side_effect = query_side_effect

    # Test cookie auth
    user = get_current_user(access_token=token, credentials=None, db=mock_db)
    assert user == mock_user


def test_get_current_user_header():
    from unittest.mock import MagicMock
    from fastapi.security import HTTPAuthorizationCredentials
    from app.services.auth import get_current_user
    from app.models.users import User
    from app.models.token_blocklist import TokenBlocklist

    user_id = "550e8400-e29b-41d4-a716-446655440000"
    token = create_jwt_token(user_id, token_type="access")

    mock_user = User(id=user_id, github_login="test_user")

    # Return None for blocklist (token is not blocked), mock_user for User lookup
    def query_side_effect(model):
        mock_q = MagicMock()
        if model is TokenBlocklist:
            mock_q.filter.return_value.first.return_value = None
        else:
            mock_q.filter.return_value.first.return_value = mock_user
        return mock_q

    mock_db = MagicMock()
    mock_db.query.side_effect = query_side_effect

    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    # Test header auth fallback
    user = get_current_user(access_token=None, credentials=credentials, db=mock_db)
    assert user == mock_user


def test_get_current_user_no_credentials():
    from fastapi import HTTPException
    from app.services.auth import get_current_user
    import pytest

    mock_db = MagicMock = None

    # Test raising 401 when no token is provided
    with pytest.raises(HTTPException) as exc_info:
        get_current_user(access_token=None, credentials=None, db=mock_db)
    assert exc_info.value.status_code == 401


def test_login_endpoint():
    from fastapi.testclient import TestClient
    from app.main import app
    
    client = TestClient(app)
    # Follow redirects = False so we can inspect the redirect headers and cookies
    response = client.get("/auth/login", follow_redirects=False)
    
    assert response.status_code == 307  # Redirect status code
    location = response.headers.get("location")
    assert "https://github.com/login/oauth/authorize" in location
    assert "state=" in location
    
    # Check that the oauth_state cookie is set
    assert "oauth_state" in response.cookies
    cookie_value = response.cookies.get("oauth_state")
    assert cookie_value is not None
    # Verify the state parameter in the redirect matches the cookie value
    assert f"state={cookie_value}" in location


def test_callback_endpoint_state_mismatch():
    from fastapi.testclient import TestClient
    from app.main import app
    
    client = TestClient(app)
    # Case 1: Missing state parameter entirely
    response = client.get("/auth/callback?code=mock_code")
    assert response.status_code == 400
    assert "state mismatch or expired" in response.json()["detail"].lower()
    
    # Case 2: Mismatched state value
    client.cookies.set("oauth_state", "expected_state")
    response = client.get("/auth/callback?code=mock_code&state=different_state")
    assert response.status_code == 400
    assert "state mismatch or expired" in response.json()["detail"].lower()


@patch("app.routes.auth.exchange_github_code_for_token")
@patch("app.routes.auth.fetch_github_user_info")
def test_callback_endpoint_success(mock_fetch_info, mock_exchange):
    from fastapi.testclient import TestClient
    from app.main import app
    from app.models.users import User
    from app.db.session import get_db
    from unittest.mock import MagicMock
    
    mock_exchange.return_value = "mock_github_token"
    mock_fetch_info.return_value = {
        "id": 12345,
        "login": "testuser",
        "name": "Test User",
        "avatar_url": "https://avatar.url"
    }
    
    mock_db = MagicMock()
    # Mock user exists
    mock_user = User(id="550e8400-e29b-41d4-a716-446655440000", github_login="testuser", github_id=12345)
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user
    
    # Override database dependency
    app.dependency_overrides[get_db] = lambda: mock_db
    
    try:
        client = TestClient(app)
        state_val = "secure_state_token"
        client.cookies.set("oauth_state", state_val)
        
        response = client.get(f"/auth/callback?code=mock_code&state={state_val}", follow_redirects=False)
        
        assert response.status_code == 307
        assert response.headers.get("location") == f"{settings.FRONTEND_URL}/dashboard"
        
        # Check that the access_token and refresh_token cookies are set
        assert "access_token" in response.cookies
        assert "refresh_token" in response.cookies
    finally:
        # Clean up dependency override
        app.dependency_overrides.pop(get_db, None)