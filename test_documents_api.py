
"""test_documents_api.py – Unit tests for TrustVault document management endpoints.
The tests mock Supabase storage and database interactions to avoid any real side‑effects.
Two distinct user UUIDs are used to verify isolation and permission logic.
"""

import io
import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.auth import AuthenticatedUser

client = TestClient(app)

def _auth_header(user: AuthenticatedUser) -> dict:
    return {"Authorization": f"Bearer dummy-token-for-{user.id}"}

USER_A = AuthenticatedUser(
    id=uuid.UUID("11111111-1111-1111-1111-111111111111"),
    email="a@example.com",
    role="owner",
    full_name="User A",
)
USER_B = AuthenticatedUser(
    id=uuid.UUID("22222222-2222-2222-2222-222222222222"),
    email="b@example.com",
    role="viewer",
    full_name="User B",
)

@pytest.fixture(autouse=True)
def mock_auth_dependency():
    """Patch get_current_user to return a deterministic user based on token."""
    from app import dependencies

    def _fake_get_current_user(credentials=None):  # type: ignore[override]
        token = credentials.credentials if credentials else ""
        if USER_A.id.hex in token:
            return USER_A
        if USER_B.id.hex in token:
            return USER_B
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    with patch.object(dependencies, "get_current_user", _fake_get_current_user):
        yield

# ---------------------------------------------------------------------------
# Mock Supabase admin client used inside app.services.storage
# ---------------------------------------------------------------------------
class MockSupabaseAdmin:
    def __init__(self):
        self._documents = {}
        self._permissions = []
        self._profiles = {
            str(USER_A.id): {"id": str(USER_A.id), "role": USER_A.role},
            str(USER_B.id): {"id": str(USER_B.id), "role": USER_B.role},
        }
        self._audit_logs = []

    # Table helpers ----------------------------------------------------------
    def table(self, name: str):
        return getattr(self, f"_table_{name}")(self)

    class _table_documents:
        def __init__(self, outer):
            self.outer = outer
            self.single_mode = False  # Track .single() usage
        def select(self, *args, **kwargs):
            return self

        def in_(self, column, values):
            self.in_filter = (column, values)
            return self
        def insert(self, payload):
            from datetime import datetime
            doc_id = str(uuid.uuid4())
            # Add version and timestamps to mimic real DB row
            row = {
                "id": doc_id,
                "version": 1,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
                **payload,
            }
            self.outer._documents[doc_id] = row
            self.res = {"data": [row]}
            return self
        def delete(self):
            self.to_delete = []
            return self
        def eq(self, column, value):
            # Handles both filter queries and delete ID collection
            if hasattr(self, "to_delete"):
                # Called after delete() to collect IDs to delete
                self.to_delete.append(value)
            else:
                self.filter = (column, value)
            return self
        def single(self):
            self.single_mode = True
            return self
        def execute(self):
            # Delete path
            if hasattr(self, "to_delete"):
                for doc_id in self.to_delete:
                    self.outer._documents.pop(doc_id, None)
                return {"data": []}
            # In_ filter path
            if hasattr(self, "in_filter"):
                col, vals = self.in_filter
                data = [doc for doc in self.outer._documents.values() if doc.get(col) in vals]
                return {"data": data}
            # Equality filter path
            if hasattr(self, "filter"):
                col, val = self.filter
                data = [doc for doc in self.outer._documents.values() if doc.get(col) == val]
                if getattr(self, "single_mode", False):
                    return {"data": data[0] if data else None}
                return {"data": data}
            # Insert result path
            if hasattr(self, "res"):
                return self.res
            return {"data": []}

    class _table_document_permissions:
        def __init__(self, outer):
            self.outer = outer
            self.single_mode = False
        def select(self, *args, **kwargs):
            return self
        def eq(self, column, value):
            self.filter = (column, value)
            return self
        def insert(self, payload):
            self.outer._permissions.append(payload)
            self.res = {"data": [payload]}
            return self
        def single(self):
            self.single_mode = True
            return self
        def execute(self):
            col, val = self.filter
            data = [p for p in self.outer._permissions if p[col] == val]
            if self.single_mode:
                return {"data": data[0] if data else None}
            return {"data": data}

    class _table_profiles:
        def __init__(self, outer):
            self.outer = outer
        def select(self, *args, **kwargs):
            return self
        def eq(self, column, value):
            self.filter = (column, value)
            return self
        def single(self):
            # Mimic Supabase .single() which just returns self for chaining
            return self
        def execute(self):
            # Return profile as a dict, matching real Supabase client behavior
            profile = self.outer._profiles.get(self.filter[1])
            if profile:
                return {"data": profile}
            return {"data": {}}

    class _table_audit_logs:
        def __init__(self, outer):
            self.outer = outer
        def insert(self, payload):
            self.outer._audit_logs.append(payload)
            self.res = {"data": [payload]}
            return self
        def execute(self):
            return self.res

    # Storage helpers --------------------------------------------------------
    class _storage:
        def __init__(self, outer):
            self.outer = outer
        def from_(self, bucket_name):
            return self
        def upload(self, path, data):
            # Simulate successful upload; no error field
            return {}
        def create_signed_url(self, path, expiry):
            return {"signedURL": f"https://example.com/{path}?exp={expiry}"}
        def remove(self, paths):
            return {}

    @property
    def storage(self):
        return self._storage(self)

    @property
    def auth(self):
        return MagicMock(admin=MagicMock())

def _setup_admin():
    admin = MockSupabaseAdmin()
    payload = {
        "owner_id": str(USER_A.id),
        "title": "Doc A",
        "file_name": "doc.txt",
        "file_path": f"{USER_A.id}/doc.txt",
        "file_size_bytes": 123,
        "mime_type": "text/plain",
    }
    insert_res = admin.table("documents").insert(payload).execute()
    doc_id = insert_res["data"][0]["id"]
    return admin, doc_id

@patch("app.services.storage.get_supabase_admin_client")
def test_successful_upload(mock_admin):
    admin, _ = _setup_admin()
    mock_admin.return_value = admin
    files = {"file": ("hello.txt", io.BytesIO(b"Hello"), "text/plain")}
    data = {"title": "Hello"}
    resp = client.post("/api/v1/documents", headers=_auth_header(USER_A), data=data, files=files)
    assert resp.status_code == 201
    json = resp.json()
    assert json["title"] == "Hello"
    assert json["owner_id"] == str(USER_A.id)
    assert json["file_name"] == "hello.txt"

@patch("app.services.storage.get_supabase_admin_client")
def test_list_owned_and_shared(mock_admin):
    admin, doc_id = _setup_admin()
    admin._permissions.append({"document_id": doc_id, "user_id": str(USER_B.id)})
    mock_admin.return_value = admin
    resp_a = client.get("/api/v1/documents", headers=_auth_header(USER_A))
    assert resp_a.status_code == 200
    assert any(d["id"] == doc_id for d in resp_a.json())
    resp_b = client.get("/api/v1/documents", headers=_auth_header(USER_B))
    assert resp_b.status_code == 200
    assert any(d["id"] == doc_id for d in resp_b.json())

@patch("app.services.storage.get_supabase_admin_client")
def test_download_authorization(mock_admin):
    admin, doc_id = _setup_admin()
    admin._permissions.append({"document_id": doc_id, "user_id": str(USER_B.id)})
    mock_admin.return_value = admin
    # Owner
    assert client.get(f"/api/v1/documents/{doc_id}", headers=_auth_header(USER_A)).status_code == 200
    # Shared user
    assert client.get(f"/api/v1/documents/{doc_id}", headers=_auth_header(USER_B)).status_code == 200
    # Unauthorized third user
    USER_C = AuthenticatedUser(
        id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
        email="c@example.com",
        role="viewer",
        full_name="User C",
    )
    assert client.get(f"/api/v1/documents/{doc_id}", headers=_auth_header(USER_C)).status_code == 403

@patch("app.services.storage.get_supabase_admin_client")
def test_delete_owner_and_denied(mock_admin):
    admin, doc_id = _setup_admin()
    mock_admin.return_value = admin
    # Owner can delete
    assert client.delete(f"/api/v1/documents/{doc_id}", headers=_auth_header(USER_A)).status_code == 204
    # Re‑create for denial test
    admin, doc_id = _setup_admin()
    mock_admin.return_value = admin
    # Non‑owner cannot delete
    assert client.delete(f"/api/v1/documents/{doc_id}", headers=_auth_header(USER_B)).status_code == 403

@patch("app.services.storage.get_supabase_admin_client")
def test_invalid_mime_and_oversize(mock_admin):
    admin, _ = _setup_admin()
    mock_admin.return_value = admin
    # Bad MIME type
    files = {"file": ("bad.exe", io.BytesIO(b"x"), "application/octet-stream")}
    resp = client.post("/api/v1/documents", headers=_auth_header(USER_A), data={"title": "Bad"}, files=files)
    assert resp.status_code == 400
    # Oversize >5MiB
    big = b"0" * (6 * 1024 * 1024)
    files = {"file": ("big.pdf", io.BytesIO(big), "application/pdf")}
    resp2 = client.post("/api/v1/documents", headers=_auth_header(USER_A), data={"title": "Big"}, files=files)
    assert resp2.status_code == 413

@patch("app.services.storage.get_supabase_admin_client")
def test_missing_and_invalid_token(mock_admin):
    admin, _ = _setup_admin()
    mock_admin.return_value = admin
    # No token
    assert client.get("/api/v1/documents").status_code == 401
    # Invalid token format (fallback auth raises 401)
    assert client.get("/api/v1/documents", headers={"Authorization": "Bearer invalid"}).status_code == 401

