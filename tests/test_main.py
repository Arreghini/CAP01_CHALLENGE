import pytest
from fastapi.testclient import TestClient
from main import app, fake_db, create_access_token, get_password_hash, verify_password


client = TestClient(app)

@pytest.fixture
def test_user():
    return {"username": "testuser", "password": "testpassword"}

@pytest.fixture
def registered_user(test_user):
    fake_db["users"][test_user["username"]] = {
        "username": test_user["username"],
        "password": get_password_hash(test_user["password"]),
        "token": create_access_token(data={"sub": test_user["username"]}),
    }
    return test_user

def test_register_new_user():
    response = client.post("/register", json={"username": "newuser", "password": "newpassword"})
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "token_type" in response.json()
    assert response.json()["token_type"] == "bearer"

def test_register_existing_user(registered_user):
    response = client.post("/register", json=registered_user)
    assert response.status_code == 400
    assert response.json()["detail"] == "Username already registered"

def test_login_success(registered_user):
    response = client.post("/login", json=registered_user)
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "token_type" in response.json()
    assert response.json()["token_type"] == "bearer"

def test_login_failure_wrong_password(registered_user):
    wrong_password = {**registered_user, "password": "wrongpassword"}
    response = client.post("/login", json=wrong_password)
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"

def test_login_failure_nonexistent_user():
    response = client.post("/login", json={"username": "nonexistent", "password": "password"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"

def test_bubble_sort(registered_user):
    token = fake_db["users"][registered_user["username"]]["token"]
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"numbers": [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5]}
    response = client.post("/bubble-sort", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json()["numbers"] == [1, 1, 2, 3, 3, 4, 5, 5, 5, 6, 9]

def test_binary_search(registered_user):
    token = fake_db["users"][registered_user["username"]]["token"]
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"numbers": [1, 2, 3, 4, 5, 6, 7, 8, 9], "target": 5}
    response = client.post("/binary-search", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json()["index"] == 4

def test_filter_even(registered_user):
    token = fake_db["users"][registered_user["username"]]["token"]
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"numbers": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]}
    response = client.post("/filter-even", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json()["numbers"] == [2, 4, 6, 8, 10]

def test_sum_elements(registered_user):
    token = fake_db["users"][registered_user["username"]]["token"]
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"numbers": [1, 2, 3, 4, 5]}
    response = client.post("/sum-elements", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json()["sum"] == 15

def test_mean_value(registered_user):
    token = fake_db["users"][registered_user["username"]]["token"]
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"numbers": [1, 2, 3, 4, 5]}
    response = client.post("/mean-value", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json()["mean"] == 3.0

def test_median_elements_odd(registered_user):
    token = fake_db["users"][registered_user["username"]]["token"]
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"numbers": [1, 2, 3, 4, 5]}
    response = client.post("/median-elements", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json()["median"] == 3

def test_median_elements_even(registered_user):
    token = fake_db["users"][registered_user["username"]]["token"]
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"numbers": [1, 2, 3, 4, 5, 6]}
    response = client.post("/median-elements", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json()["median"] == 3.5

def test_max_value(registered_user):
    token = fake_db["users"][registered_user["username"]]["token"]
    headers = {"Authorization": f"Bearer {token}"}
    payload = {"numbers": [1, 5, 3, 9, 2, 7]}
    response = client.post("/max-value", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json()["max_value"] == 9

def test_unauthorized_access():
    payload = {"numbers": [1, 2, 3, 4, 5]}
    response = client.post("/bubble-sort", json=payload)
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

def test_verify_password():
    password = "testpassword"
    hashed_password = get_password_hash(password)
    assert verify_password(password, hashed_password)
    assert not verify_password("wrongpassword", hashed_password)
