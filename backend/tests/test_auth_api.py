import os
import uuid
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock
import jwt
from dotenv import load_dotenv
from fastapi.testclient import TestClient
from supabase import create_client

# Ensure backend/.env is loaded for live integration tests
load_dotenv(Path(__file__).resolve().parent.parent / ".env")


def test_health_remains_operational(client: TestClient):
    """Verify Stage 1 health probe remains fully functional after Stage 2 auth changes."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["services"]["api"] == "healthy"
    assert data["services"]["supabase_configured"] is True


def test_auth_me_missing_token_returns_401(client: TestClient):
    """Calling /api/v1/auth/me without an Authorization header must return 401."""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_auth_me_malformed_token_returns_401(client: TestClient):
    """Calling /api/v1/auth/me with an invalid/malformed token must return generic 401."""
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer malformed.token.format"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authentication token"


def test_auth_me_tampered_token_returns_401(client: TestClient):
    """Calling /api/v1/auth/me with a forged/tampered JWT must return generic 401."""
    # Create an arbitrary unverified JWT signed with an untrusted secret
    fake_payload = {
        "sub": str(uuid.uuid4()),
        "iss": "https://yebmigbntwbapdcukbfz.supabase.co/auth/v1",
        "aud": "authenticated",
        "exp": 9999999999,
    }
    fake_jwt = jwt.encode(fake_payload, "untrusted_secret_key_32_bytes_long!", algorithm="HS256")
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {fake_jwt}"}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authentication token"


def test_auth_me_jwks_outage_returns_503(client: TestClient):
    """
    Infrastructure outage test:
    When JWKS cannot be reached, the system must return HTTP 503 (not false 401).
    """
    with patch("app.dependencies.get_jwks_client") as mock_jwks:
        mock_jwks.side_effect = ConnectionError("JWKS endpoint unreachable")
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer header.payload.signature"}
        )
        assert response.status_code == 503
        assert response.json()["detail"] == "Authentication service temporarily unavailable"


def test_auth_me_missing_profile_fails_closed(client: TestClient):
    """
    Fail-closed test:
    If a valid token subject has no matching row in public.profiles, access is denied with 401.
    """
    dummy_uuid = uuid.uuid4()
    mock_payload = {
        "sub": str(dummy_uuid),
        "iss": "https://yebmigbntwbapdcukbfz.supabase.co/auth/v1",
        "aud": "authenticated",
        "exp": 9999999999,
    }

    mock_key = MagicMock()
    mock_key.key = "mock_key"

    with patch("app.dependencies.get_jwks_client") as mock_jwks, \
         patch("jwt.decode", return_value=mock_payload), \
         patch("app.dependencies.get_supabase_admin_client") as mock_supabase:
        
        mock_jwks.return_value.get_signing_key_from_jwt.return_value = mock_key

        # Mock user exists in auth.users
        mock_user_obj = MagicMock()
        mock_user_obj.user.banned_until = None
        mock_supabase.return_value.auth.admin.get_user_by_id.return_value = mock_user_obj

        # But profiles query returns empty list (missing profile)
        mock_supabase.return_value.table.return_value.select.return_value.eq.return_value.execute.return_value.data = []

        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer valid.mock.token"}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "User profile not found"


def test_live_supabase_signup_role_tamper_resistance_and_auth_me(client: TestClient):
    """
    Live Supabase End-to-End Test:
    1. Sign up a new user via Supabase Auth client, attempting client-side role injection.
    2. Verify PostgreSQL trigger enforces 'viewer' role in public.profiles.
    3. Sign in to obtain live asymmetric JWT access token.
    4. Call FastAPI GET /api/v1/auth/me with Bearer token.
    5. Assert ES256 verification succeeds and returns verified profile and 'viewer' role.
    6. Clean up test user from auth.users.
    """
    supabase_url = os.getenv("SUPABASE_URL")
    anon_key = os.getenv("SUPABASE_ANON_KEY")
    service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    if not supabase_url or "placeholder" in supabase_url:
        pytest.skip("SUPABASE_URL not configured")

    public_client = create_client(supabase_url, anon_key)
    admin_client = create_client(supabase_url, service_key)

    test_email = f"tv_live_test_{uuid.uuid4().hex[:6]}@gmail.com"
    test_password = "SecureTestPassword2026!"
    test_user_id = None

    try:
        # 1. Create user with client-supplied admin role in metadata
        user_res = admin_client.auth.admin.create_user({
            "email": test_email,
            "password": test_password,
            "email_confirm": True,
            "user_metadata": {
                "full_name": "Test User",
                "role": "admin",  # Attacker attempts role escalation
            }
        })
        assert user_res.user is not None
        test_user_id = user_res.user.id

        # 2. Check public.profiles directly via admin client
        profile_res = admin_client.table("profiles").select("role, full_name").eq("id", test_user_id).execute()
        assert len(profile_res.data) == 1
        # Proves database trigger handle_new_user() discarded client-supplied 'admin' role:
        assert profile_res.data[0]["role"] == "viewer"
        assert profile_res.data[0]["full_name"] == "Test User"

        # 3. Authenticate to obtain live JWT
        signin_res = public_client.auth.sign_in_with_password({
            "email": test_email,
            "password": test_password,
        })
        assert signin_res.session is not None
        access_token = signin_res.session.access_token

        # 4. Invoke protected endpoint GET /api/v1/auth/me
        me_response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        assert me_response.status_code == 200
        me_data = me_response.json()

        assert me_data["status"] == "authenticated"
        assert me_data["user"]["id"] == test_user_id
        assert me_data["user"]["email"] == test_email
        assert me_data["user"]["role"] == "viewer"
        assert me_data["user"]["full_name"] == "Test User"

    finally:
        # 6. Teardown / cleanup test user
        if test_user_id:
            try:
                admin_client.auth.admin.delete_user(test_user_id)
            except Exception as e:
                print(f"Cleanup warning: {e}")
