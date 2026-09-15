from pymongo import MongoClient
from pymongo.server_api import ServerApi
import os
from dotenv import load_dotenv
load_dotenv()
mongo_uri = os.getenv("MONGO_URI", "mongodb+srv://<viswanadhkurre23083_db_user>:4dFy2Cvj0qGXzXdy@clusterv.lotgxig.mongodb.net")
client = MongoClient(mongo_uri, server_api=ServerApi('1'))
# Send a ping to confirm a successful connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
import pytest_asyncio
from bson import ObjectId

from app.main import app
from app.routers import auth

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as test_client:
        yield test_client


@pytest.fixture
def database(monkeypatch):
    users = SimpleNamespace(
        find_one=AsyncMock(),
        insert_one=AsyncMock(),
        update_one=AsyncMock(),
    )
    reset_tokens = SimpleNamespace(
        insert_one=AsyncMock(),
        find_one_and_delete=AsyncMock(),
    )
    fake_database = SimpleNamespace(users=users, password_reset_tokens=reset_tokens)
    monkeypatch.setattr(auth, "get_database", lambda: fake_database)
    return fake_database


async def test_root_returns_hello_world(client: httpx.AsyncClient):
    response = await client.get("/")

    assert response.status_code == 200
    assert response.json() == {"message": "Hello World"}


async def test_root_rejects_non_get_method(client: httpx.AsyncClient):
    response = await client.post("/")

    assert response.status_code == 405
    assert response.json() == {"detail": "Method Not Allowed"}


async def test_login_page_returns_html(client: httpx.AsyncClient):
    response = await client.get("/login")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<h1>Sign in</h1>" in response.text


async def test_login_page_not_found_at_unknown_path(client: httpx.AsyncClient):
    response = await client.get("/does-not-exist")

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


async def test_health_returns_ok(client: httpx.AsyncClient):
    response = await client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_health_rejects_post(client: httpx.AsyncClient):
    response = await client.post("/health")

    assert response.status_code == 405
    assert response.json() == {"detail": "Method Not Allowed"}


async def test_register_creates_user(client: httpx.AsyncClient, database):
    user_id = ObjectId()
    database.users.find_one.return_value = None
    database.users.insert_one.return_value = SimpleNamespace(inserted_id=user_id)

    response = await client.post(
        "/auth/register",
        json={
            "email": "  USER@example.com ",
            "password": "correct horse battery staple",
            "display_name": "Test User",
        },
    )

    assert response.status_code == 201
    assert response.json() == {
        "id": str(user_id),
        "email": "user@example.com",
        "display_name": "Test User",
    }
    inserted_document = database.users.insert_one.await_args.args[0]
    assert inserted_document["email"] == "user@example.com"
    assert inserted_document["password_hash"] != "correct horse battery staple"


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "not-an-email", "password": "correct horse battery staple", "display_name": "User"},
        {"email": "user@example.com", "password": "short", "display_name": "User"},
        {"email": "user@example.com", "password": "correct horse battery staple", "display_name": "<script>"},
        {"email": "user@example.com", "password": "correct horse battery staple", "display_name": ""},
    ],
)
async def test_register_rejects_invalid_input(client: httpx.AsyncClient, database, payload):
    response = await client.post("/auth/register", json=payload)

    assert response.status_code == 422
    assert "detail" in response.json()
    database.users.insert_one.assert_not_awaited()


async def test_register_rejects_duplicate_email(client: httpx.AsyncClient, database):
    database.users.find_one.return_value = {"_id": ObjectId()}

    response = await client.post(
        "/auth/register",
        json={
            "email": "user@example.com",
            "password": "correct horse battery staple",
            "display_name": "User",
        },
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "Email is already registered"}
    database.users.insert_one.assert_not_awaited()


async def test_login_sets_authentication_and_csrf_cookies(client: httpx.AsyncClient, database, monkeypatch):
    database.users.find_one.return_value = {
        "_id": ObjectId(),
        "email": "user@example.com",
        "password_hash": "stored-hash",
    }
    monkeypatch.setattr(auth, "verify_password", lambda password, _: password == "valid-password")
    monkeypatch.setattr(auth, "create_access_token", lambda _: "access-token")
    monkeypatch.setattr(auth, "create_password_reset_token", lambda: "csrf-token")

    response = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "valid-password"},
    )

    assert response.status_code == 200
    assert response.json() == {"message": "Login successful"}
    assert client.cookies["access_token"] == "access-token"
    assert client.cookies["csrf_token"] == "csrf-token"
    assert "HttpOnly" in response.headers["set-cookie"]


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "user@example.com", "password": "wrong-password"},
        {"email": "missing@example.com", "password": "valid-password"},
    ],
)
async def test_login_rejects_invalid_credentials(client: httpx.AsyncClient, database, payload):
    database.users.find_one.return_value = None

    response = await client.post("/auth/login", json=payload)

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}


async def test_login_rejects_invalid_payload(client: httpx.AsyncClient, database):
    response = await client.post("/auth/login", json={"email": "bad", "password": ""})

    assert response.status_code == 422
    database.users.find_one.assert_not_awaited()


async def test_forgot_password_has_same_response_for_existing_user(
    client: httpx.AsyncClient, database, monkeypatch
):
    database.users.find_one.return_value = {"_id": ObjectId()}
    monkeypatch.setattr(auth, "create_password_reset_token", lambda: "reset-token")

    response = await client.post("/auth/forgot-password", json={"email": "user@example.com"})

    assert response.status_code == 200
    assert response.json() == {
        "message": "If that email exists, password reset instructions have been sent"
    }
    database.password_reset_tokens.insert_one.assert_awaited_once()


async def test_forgot_password_does_not_reveal_missing_user(client: httpx.AsyncClient, database):
    database.users.find_one.return_value = None

    response = await client.post("/auth/forgot-password", json={"email": "missing@example.com"})

    assert response.status_code == 200
    assert response.json() == {
        "message": "If that email exists, password reset instructions have been sent"
    }
    database.password_reset_tokens.insert_one.assert_not_awaited()


async def test_forgot_password_rejects_invalid_email(client: httpx.AsyncClient, database):
    response = await client.post("/auth/forgot-password", json={"email": "invalid"})

    assert response.status_code == 422
    database.users.find_one.assert_not_awaited()


async def test_reset_password_updates_password(client: httpx.AsyncClient, database, monkeypatch):
    user_id = ObjectId()
    database.password_reset_tokens.find_one_and_delete.return_value = {
        "user_id": user_id,
        "expires_at": datetime.now(UTC) + timedelta(minutes=5),
    }
    monkeypatch.setattr(auth, "hash_password", lambda _: "new-password-hash")

    response = await client.post(
        "/auth/reset-password",
        json={"token": "a" * 20, "new_password": "new secure password"},
    )

    assert response.status_code == 200
    assert response.json() == {"message": "Password reset successful"}
    database.users.update_one.assert_awaited_once_with(
        {"_id": user_id},
        {"$set": {"password_hash": "new-password-hash"}},
    )


@pytest.mark.parametrize(
    "reset_result",
    [
        None,
        {
            "user_id": ObjectId(),
            "expires_at": datetime.now(UTC) - timedelta(seconds=1),
        },
    ],
)
async def test_reset_password_rejects_missing_or_expired_token(client: httpx.AsyncClient, database, reset_result):
    database.password_reset_tokens.find_one_and_delete.return_value = reset_result

    response = await client.post(
        "/auth/reset-password",
        json={"token": "a" * 20, "new_password": "new secure password"},
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid or expired reset token"}
    database.users.update_one.assert_not_awaited()


async def test_reset_password_rejects_short_token(client: httpx.AsyncClient, database):
    response = await client.post(
        "/auth/reset-password",
        json={"token": "too-short", "new_password": "new secure password"},
    )

    assert response.status_code == 422
    database.password_reset_tokens.find_one_and_delete.assert_not_awaited()


async def test_logout_requires_matching_csrf_cookie_and_header(client: httpx.AsyncClient):
    client.cookies.set("csrf_token", "csrf-token")

    response = await client.post("/auth/logout", headers={"X-CSRF-Token": "csrf-token"})

    assert response.status_code == 200
    assert response.json() == {"message": "Logged out"}
    assert 'access_token="";' in response.headers["set-cookie"]


@pytest.mark.parametrize(
    "cookies,headers",
    [
        ({}, {}),
        ({"csrf_token": "cookie-token"}, {"X-CSRF-Token": "header-token"}),
        ({"csrf_token": "cookie-token"}, {}),
    ],
)
async def test_logout_rejects_invalid_csrf(client: httpx.AsyncClient, cookies, headers):
    for name, value in cookies.items():
        client.cookies.set(name, value)

    response = await client.post("/auth/logout", headers=headers)

    assert response.status_code == 403
    assert response.json() == {"detail": "CSRF validation failed"}


async def test_me_returns_authenticated_user_from_bearer_token(client: httpx.AsyncClient, database, monkeypatch):
    user_id = ObjectId()
    database.users.find_one.return_value = {
        "_id": user_id,
        "email": "user@example.com",
        "display_name": "Test User",
    }
    monkeypatch.setattr(auth, "decode_access_token", lambda _: str(user_id))

    response = await client.get("/auth/me", headers={"Authorization": "Bearer access-token"})

    assert response.status_code == 200
    assert response.json() == {
        "id": str(user_id),
        "email": "user@example.com",
        "display_name": "Test User",
    }


async def test_me_accepts_access_token_from_cookie(client: httpx.AsyncClient, database, monkeypatch):
    user_id = ObjectId()
    database.users.find_one.return_value = {
        "_id": user_id,
        "email": "user@example.com",
        "display_name": "Test User",
    }
    monkeypatch.setattr(auth, "decode_access_token", lambda _: str(user_id))
    client.cookies.set("access_token", "cookie-access-token")

    response = await client.get("/auth/me")

    assert response.status_code == 200
    assert response.json()["id"] == str(user_id)


async def test_me_requires_authentication(client: httpx.AsyncClient):
    response = await client.get("/auth/me")

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


async def test_me_rejects_invalid_token(client: httpx.AsyncClient, monkeypatch):
    def reject_token(_):
        raise ValueError("Invalid or expired access token")

    monkeypatch.setattr(auth, "decode_access_token", reject_token)

    response = await client.get("/auth/me", headers={"Authorization": "Bearer invalid-token"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or expired access token"}


async def test_me_returns_401_when_token_user_does_not_exist(client: httpx.AsyncClient, database, monkeypatch):
    user_id = ObjectId()
    database.users.find_one.return_value = None
    monkeypatch.setattr(auth, "decode_access_token", lambda _: str(user_id))

    response = await client.get("/auth/me", headers={"Authorization": "Bearer access-token"})

    assert response.status_code == 401
    assert response.json() == {"detail": "User not found"}
