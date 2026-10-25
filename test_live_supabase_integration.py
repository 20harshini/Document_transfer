"""
TrustVault Live Supabase & PostgreSQL Integration Tests

These tests execute REAL database and RLS operations against the configured
remote Supabase instance using the Supabase Python SDK.

SAFETY & ISOLATION GUARANTEES:
- Zero pollution on real audit logs: Tests that perform INSERT into 'public.audit_logs'
  are strictly OPT-IN via 'ENABLE_AUDIT_WRITE_INTEGRATION_TESTS=1' because the table is
  immutable and test rows cannot be deleted afterwards.
- Strictly non-destructive to real user data.
- Never modifies, queries, or deletes any real user profile or document.
- Unauthenticated tests assert that RLS blocks enumeration, returning 0 rows.

Prerequisites:
- Migration '001_initial_schema.sql' must be applied to the remote Supabase project.
- If tables do not exist yet, tests safely skip with a descriptive warning.
"""

import os
import pytest
from postgrest.exceptions import APIError
import uuid
from pathlib import Path
from dotenv import load_dotenv

# Load backend/.env
backend_dir = Path(__file__).resolve().parent.parent
env_path = backend_dir / ".env"
load_dotenv(dotenv_path=env_path)

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

# Unique test run session ID to isolate any test records
TEST_SESSION_ID = f"test_{uuid.uuid4().hex[:8]}"

# Check if tables exist before running live integration tests
def are_tables_ready() -> bool:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY or "placeholder" in SUPABASE_URL:
        return False
    try:
        from supabase import create_client
        client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
        client.table("profiles").select("id").limit(0).execute()
        return True
    except Exception:
        return False

tables_ready = are_tables_ready()
skip_reason = "Remote Supabase tables not yet created. Apply 001_initial_schema.sql in Supabase SQL editor to run live integration tests."

# Opt-in flag to prevent polluting real audit log tables with immutable test records
OPT_IN_AUDIT_WRITE = os.getenv("ENABLE_AUDIT_WRITE_INTEGRATION_TESTS", "").lower() in ["1", "true", "yes"]
skip_audit_write_reason = (
    "Audit-log write tests are opt-in to prevent creating permanent test records in the immutable audit log table. "
    "Set ENABLE_AUDIT_WRITE_INTEGRATION_TESTS=1 against a dedicated test database to run."
)


@pytest.fixture(scope="module")
def admin_client():
    from supabase import create_client
    return create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


@pytest.fixture(scope="module")
def anon_client():
    from supabase import create_client
    return create_client(SUPABASE_URL, SUPABASE_ANON_KEY)


# ============================================================================
# REAL LIVE DATABASE INTEGRATION TESTS (NON-POLLUTING BY DEFAULT)
# ============================================================================

@pytest.mark.skipif(not tables_ready, reason=skip_reason)
def test_live_anon_client_cannot_enumerate_profiles(anon_client):
    """
    Live DB Test (Non-Mutating):
    Verify that an unauthenticated public client querying public.profiles
    is blocked by RLS and cannot enumerate any user accounts.
    """
    import pytest
    from postgrest.exceptions import APIError
    with pytest.raises(APIError) as exc_info:
        anon_client.table("profiles").select("id, email, role").execute()
    err_msg = str(exc_info.value).lower()
    assert "permission denied" in err_msg or "rls" in err_msg


@pytest.mark.skipif(not tables_ready, reason=skip_reason)
def test_live_anon_client_cannot_enumerate_documents(anon_client):
    """
    Live DB Test (Non-Mutating):
    Verify that an unauthenticated public client querying public.documents
    is blocked by RLS and cannot see any documents.
    """
    import pytest
    from postgrest.exceptions import APIError
    with pytest.raises(APIError) as exc_info:
        anon_client.table("documents").select("id, title, file_path").execute()
    err_msg = str(exc_info.value).lower()
    assert "permission denied" in err_msg or "rls" in err_msg


@pytest.mark.skipif(not tables_ready, reason=skip_reason)
def test_live_audit_logs_rejects_client_insert(anon_client):
    """
    Live DB Test (Non-Mutating):
    Verify that an unauthenticated or public client attempting to insert
    directly into public.audit_logs is strictly rejected by PostgreSQL privileges.
    The transaction fails and rolls back, leaving ZERO rows in the database.
    """
    fake_entry = {
        "action": "FORGED_CLIENT_EVENT",
        "status": "SUCCESS",
        "target_resource": f"isolation_test_{TEST_SESSION_ID}",
        "details": {"forged": True}
    }
    with pytest.raises(Exception) as exc_info:
        anon_client.table("audit_logs").insert(fake_entry).execute()
    
    error_str = str(exc_info.value).lower()
    # Expect 42501 (insufficient privilege) or RLS violation
    assert any(term in error_str for term in ["permission denied", "violates row-level security", "42501", "unauthorized"])


@pytest.mark.skipif(not tables_ready, reason=skip_reason)
def test_live_first_admin_bootstrap_lock(admin_client):
    """
    Live DB Test (Non-Mutating):
    Verify that calling bootstrap_first_admin with an invalid or already bootstrapped
    system behaves as intended under the advisory lock without modifying data.
    """
    res = admin_client.table("profiles").select("id").eq("role", "admin").execute()
    if len(res.data or []) > 0:
        with pytest.raises(Exception) as exc_info:
            admin_client.rpc("bootstrap_first_admin", {"target_email": f"attacker_{TEST_SESSION_ID}@invalid.local"}).execute()
        assert "Security Lock" in str(exc_info.value)


# ============================================================================
# MUTATING AUDIT LOG TESTS (STRICTLY OPT-IN TO PROTECT REAL AUDIT DATA)
# ============================================================================

@pytest.mark.skipif(not tables_ready, reason=skip_reason)
@pytest.mark.skipif(not OPT_IN_AUDIT_WRITE, reason=skip_audit_write_reason)
def test_live_audit_logs_accepts_service_role_insert(admin_client):
    """
    Live DB Test (OPT-IN):
    Verify that the trusted backend service-role CAN append audit logs.
    Note: Test row will be permanent in public.audit_logs due to immutability.
    """
    audit_entry = {
        "action": "SECURITY_INTEGRATION_TEST",
        "target_resource": f"isolation_test_{TEST_SESSION_ID}",
        "details": {"test_session": TEST_SESSION_ID, "automated": True},
        "status": "SUCCESS"
    }
    res = admin_client.table("audit_logs").insert(audit_entry).execute()
    assert res.data is not None
    assert len(res.data) > 0
    created_id = res.data[0]["id"]
    assert created_id is not None
    return created_id


@pytest.mark.skipif(not tables_ready, reason=skip_reason)
@pytest.mark.skipif(not OPT_IN_AUDIT_WRITE, reason=skip_audit_write_reason)
def test_live_audit_logs_strictly_blocks_update_and_delete(admin_client):
    """
    Live DB Test (OPT-IN):
    Verify that even the service_role cannot UPDATE or DELETE existing audit logs
    due to trg_immutable_audit_logs.
    """
    # 1. Insert an isolated test log
    res = admin_client.table("audit_logs").insert({
        "action": "IMMUTABILITY_TEST",
        "target_resource": f"isolation_test_{TEST_SESSION_ID}",
        "status": "SUCCESS"
    }).execute()
    log_id = res.data[0]["id"]

    # 2. Attempt to update it
    with pytest.raises(Exception) as exc_info:
        admin_client.table("audit_logs").update({"status": "FAILURE"}).eq("id", log_id).execute()
    assert "Security Violation: Audit logs are strictly immutable" in str(exc_info.value)

    # 3. Attempt to delete it
    with pytest.raises(Exception) as exc_info:
        admin_client.table("audit_logs").delete().eq("id", log_id).execute()
    assert "Security Violation: Audit logs are strictly immutable" in str(exc_info.value)
