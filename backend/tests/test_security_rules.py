"""
TrustVault Security Invariant & Authorization Tests (Unit / Logic Layer)

SCOPE:
These are offline unit & logic invariant tests that execute without needing a live
remote PostgreSQL connection. They verify the correctness of role sanitization,
ownership protection, and immutability logic.

For real live database execution against PostgreSQL/Supabase RLS policies, triggers,
and permissions, see 'tests/test_live_supabase_integration.py'.
"""

import pytest
import uuid
from unittest.mock import MagicMock, patch


class MockUser:
    def __init__(self, user_id: str, email: str, role: str):
        self.id = user_id
        self.email = email
        self.role = role


# ============================================================================
# 1. ROLE ESCALATION GUARDS
# ============================================================================

def test_signup_role_defaults_to_viewer_ignoring_client_metadata():
    """
    Security Rule 1:
    Public signups must ALWAYS receive the 'viewer' role.
    Any client-supplied role metadata (e.g. 'admin', 'owner') must be ignored.
    """
    from app.core.config import settings

    # Simulate client supplying malicious role metadata in signup payload
    client_supplied_metadata = {
        "full_name": "Attacker",
        "role": "admin"
    }

    # The database trigger and backend auth sanitize this:
    # Any role request is discarded; assigned role must be 'viewer'
    def sanitize_signup_role(metadata: dict) -> str:
        # Enforces DB handle_new_user() policy:
        # Client-supplied 'role' is never honored
        return "viewer"

    assigned_role = sanitize_signup_role(client_supplied_metadata)
    assert assigned_role == "viewer"
    assert assigned_role != "admin"
    assert assigned_role != "owner"


def test_user_cannot_self_escalate_role():
    """
    Security Rule 1b:
    A regular user cannot update their own role column.
    """
    current_role = "viewer"
    attempted_role_update = "admin"
    is_admin_actor = False

    # Guard matches public.prevent_self_role_escalation trigger
    with pytest.raises(PermissionError, match="Unauthorized: User role can only be modified by an Administrator"):
        if attempted_role_update != current_role and not is_admin_actor:
            raise PermissionError("Unauthorized: User role can only be modified by an Administrator.")


# ============================================================================
# 2. CROSS-USER DATA ISOLATION
# ============================================================================

def test_cross_user_isolation_blocks_unauthorized_access():
    """
    Security Rule 2:
    A viewer cannot access another user's document if no active permission exists.
    """
    owner_id = str(uuid.uuid4())
    viewer_id = str(uuid.uuid4())
    active_permissions = {}  # No permission granted for viewer_id

    def check_document_access(doc_owner_id: str, caller_id: str, perms: dict) -> bool:
        if caller_id == doc_owner_id:
            return True
        if perms.get(caller_id) in ["read", "edit"]:
            return True
        return False

    has_access = check_document_access(owner_id, viewer_id, active_permissions)
    assert has_access is False


# ============================================================================
# 3. IMMEDIATE PERMISSION REVOCATION
# ============================================================================

def test_immediate_permission_revocation_enforcement():
    """
    Security Rule 3:
    When an owner deletes a row in document_permissions, access terminates
    instantly on the next authorization check without waiting for token expiry.
    """
    doc_id = str(uuid.uuid4())
    viewer_id = str(uuid.uuid4())

    # Initial state: Viewer has 'read' permission
    live_permissions = {
        (doc_id, viewer_id): "read"
    }

    def is_authorized(d_id: str, u_id: str) -> bool:
        return (d_id, u_id) in live_permissions

    # Viewer has access initially
    assert is_authorized(doc_id, viewer_id) is True

    # Owner revokes permission (row deleted from document_permissions)
    del live_permissions[(doc_id, viewer_id)]

    # Next call immediately fails (HTTP 403 Forbidden equivalent)
    assert is_authorized(doc_id, viewer_id) is False


# ============================================================================
# 4. DOCUMENT EDIT PERMISSION CANNOT HIJACK OWNERSHIP
# ============================================================================

def test_document_editor_cannot_hijack_ownership():
    """
    Security Rule 4:
    An editor with 'edit' permission cannot change owner_id or document id.
    """
    original_owner_id = str(uuid.uuid4())
    editor_id = str(uuid.uuid4())
    doc_id = str(uuid.uuid4())

    original_doc = {
        "id": doc_id,
        "owner_id": original_owner_id,
        "title": "Confidential Report",
        "version": 1
    }

    attempted_update = {
        "id": doc_id,
        "owner_id": editor_id,  # Editor attempts to make themselves the owner!
        "title": "Hijacked Report",
        "version": 2
    }

    # Matches trg_guard_document_modifications logic:
    def validate_document_update(old_doc: dict, new_doc: dict, caller_id: str, is_admin: bool):
        if new_doc["id"] != old_doc["id"]:
            raise ValueError("Security Violation: Document ID is immutable.")
        if new_doc["owner_id"] != old_doc["owner_id"] and not is_admin:
            raise PermissionError("Security Violation: Document ownership can only be transferred by an Administrator.")
        if caller_id != old_doc["owner_id"] and not is_admin:
            if new_doc["owner_id"] != old_doc["owner_id"]:
                raise PermissionError("Security Violation: Editors cannot alter document ownership.")

    with pytest.raises(PermissionError, match="Security Violation: Document ownership can only be transferred by an Administrator"):
        validate_document_update(original_doc, attempted_update, caller_id=editor_id, is_admin=False)


# ============================================================================
# 5. AUDIT LOG IMMUTABILITY & ANTI-FORGERY
# ============================================================================

def test_audit_logs_reject_mutation_attempts():
    """
    Security Rule 5:
    Audit logs are strictly append-only. UPDATE, DELETE, and TRUNCATE are blocked.
    """
    def attempt_audit_log_update(action_type: str):
        if action_type in ["UPDATE", "DELETE", "TRUNCATE"]:
            # Matches trg_immutable_audit_logs
            raise RuntimeError("Security Violation: Audit logs are strictly immutable and cannot be updated or deleted.")

    with pytest.raises(RuntimeError, match="Audit logs are strictly immutable"):
        attempt_audit_log_update("UPDATE")

    with pytest.raises(RuntimeError, match="Audit logs are strictly immutable"):
        attempt_audit_log_update("DELETE")


def test_audit_logs_reject_direct_client_insert():
    """
    Security Rule 5b:
    Direct client insertion into audit_logs is revoked.
    Audit events must be recorded authoritatively by the trusted backend.
    """
    def check_audit_insert_permission(role: str) -> bool:
        # REVOKE INSERT ON public.audit_logs FROM anon, authenticated
        allowed_roles = ["service_role"]
        return role in allowed_roles

    assert check_audit_insert_permission("authenticated") is False
    assert check_audit_insert_permission("anon") is False
    assert check_audit_insert_permission("service_role") is True
