import pytest
from datetime import datetime, timedelta, timezone
from jose import jwt
from unittest.mock import Mock
from main import create_access_token, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

def test_create_access_token_returns_jwt():
    data = {"sub": "testuser"}
    token = create_access_token(data)
    assert isinstance(token, str)
    assert len(token.split(".")) == 3  # JWT has 3 parts

def test_create_access_token_includes_expiration():
    data = {"sub": "testuser"}
    token = create_access_token(data)
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert "exp" in payload

def test_create_access_token_expiration_time():
    data = {"sub": "testuser"}
    token = create_access_token(data)
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)  # Convertir timestamp a datetime
    now = datetime.now(timezone.utc)
    expected_exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Permitir una diferencia de 60 segundos
    assert abs((exp - expected_exp).total_seconds()) < 60

def test_create_access_token_includes_original_data():
    data = {"sub": "testuser", "role": "admin"}
    token = create_access_token(data)
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert payload["sub"] == "testuser"
    assert payload["role"] == "admin"

def test_create_access_token_with_empty_data():
    data = {}
    token = create_access_token(data)
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    assert "exp" in payload
    assert len(payload) == 1  # Only expiration should be present

def test_create_access_token_different_users():
    token1 = create_access_token({"sub": "user1"})
    token2 = create_access_token({"sub": "user2"})
    assert token1 != token2

def test_create_access_token_verify_signature():
    data = {"sub": "testuser"}
    token = create_access_token(data)
    with pytest.raises(jwt.JWTError):
        jwt.decode(token, "wrong_secret", algorithms=[ALGORITHM])
    
    # Correct secret should not raise an exception
    jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
from main import verify_password
from unittest.mock import Mock

def test_verify_password_success():
    pwd_context = Mock()
    pwd_context.verify.return_value = True
    assert verify_password("plain_password", "hashed_password", pwd_context) == True

def test_verify_password_failure():
    pwd_context = Mock()
    pwd_context.verify.return_value = False
    assert verify_password("wrong_password", "hashed_password", pwd_context) == False

def test_verify_password_empty_strings():
    pwd_context = Mock()
    pwd_context.verify.return_value = False
    assert verify_password("", "", pwd_context) == False

def test_verify_password_none_values():
    pwd_context = Mock()
    pwd_context.verify.side_effect = TypeError
    with pytest.raises(TypeError):
        verify_password(None, None, pwd_context)

def test_verify_password_long_strings():
    pwd_context = Mock()
    pwd_context.verify.return_value = True
    long_password = "a" * 1000
    long_hash = "b" * 1000
    assert verify_password(long_password, long_hash, pwd_context) == True
import pytest
from passlib.context import CryptContext
from main import get_password_hash

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def test_get_password_hash_returns_string():
    password = "testpassword123"
    hashed = get_password_hash(password)
    assert isinstance(hashed, str)

def test_get_password_hash_different_from_input():
    password = "securepassword456"
    hashed = get_password_hash(password)
    assert hashed != password

def test_get_password_hash_consistent():
    password = "consistentpass789"
    hash1 = get_password_hash(password)
    hash2 = get_password_hash(password)
    assert pwd_context.verify(password, hash1)
    assert pwd_context.verify(password, hash2)

def test_get_password_hash_with_empty_string():
    password = ""
    hashed = get_password_hash(password)
    assert hashed != ""
    assert pwd_context.verify(password, hashed)

def test_get_password_hash_with_special_characters():
    password = "!@#$%^&*()_+"
    hashed = get_password_hash(password)
    assert pwd_context.verify(password, hashed)

@pytest.mark.parametrize("password", [
    "short",
    "averagepassword",
    "verylongpasswordwithmorethan30characters"
])
def test_get_password_hash_with_various_lengths(password):
    hashed = get_password_hash(password)
    assert pwd_context.verify(password, hashed)
