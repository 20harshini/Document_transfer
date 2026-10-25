
"""storage.py – Supabase storage and audit helper functions for TrustVault.
Provides:
- `upload_document` – validates size/type, uploads to private bucket, inserts a row into `documents`.
- `generate_download_url` – returns a signed URL (60 s) after verifying access.
- `delete_document` – removes the storage object then deletes the DB record.
- `_log_audit` – inserts a row into `audit_logs` (service‑role client only).
All functions use the backend‑only admin client (`get_supabase_admin_client`).
"""

import uuid
from typing import List, Literal
from fastapi import HTTPException, status
from pydantic import BaseModel
from datetime import datetime

from ..dependencies import get_supabase_admin_client
from ..core.config import settings
from ..schemas.auth import AuthenticatedUser

# Allowed MIME types – extend as needed
ALLOWED_MIME_TYPES: List[str] = [
    "application/pdf",
    "image/jpeg",
    "image/png",
    "text/plain",
]
# 5 MiB max upload size
MAX_UPLOAD_SIZE = 5 * 1024 * 1024

class UploadedDocument(BaseModel):
    id: uuid.UUID
    owner_id: uuid.UUID
    title: str
    file_name: str
    file_path: str
    file_size_bytes: int
    mime_type: str
    version: int = 1
    created_at: datetime
    updated_at: datetime

def _log_audit(
    actor_id: uuid.UUID,
    action: str,
    target_resource: str,
    status_str: Literal["SUCCESS", "FAILURE", "DENIED"],
    details: dict | None = None,
) -> None:
    """Insert an audit_log row using the admin client.
    This runs with service‑role privileges, so it bypasses RLS – exactly what we want for immutable logs.
    """
    admin = get_supabase_admin_client()
    payload = {
        "actor_id": str(actor_id),
        "action": action,
        "target_resource": target_resource,
        "status": status_str,
        "details": details or {},
        "created_at": datetime.utcnow().isoformat(),
    }
    res = admin.table("audit_logs").insert(payload).execute()
    if res.get("error"):
        # Swallow audit failures – they should never break the main flow.
        pass

def _generate_storage_path(owner_id: uuid.UUID, filename: str) -> str:
    """Create a deterministic, unique object name inside the private bucket.
    Format: ``<owner_id>/<uuid4()>/<sanitized_filename>``.
    """
    safe_name = filename.replace("/", "_").replace("\\", "_")
    return f"{owner_id}/{uuid.uuid4()}/{safe_name}"

def upload_document(
    *,
    file_bytes: bytes,
    filename: str,
    mime_type: str,
    title: str,
    user: AuthenticatedUser,
) -> UploadedDocument:
    """Validate, upload, and record a new document.
    Steps:
    1️⃣ Enforce size and MIME allow‑list.
    2️⃣ Upload to Supabase storage (private bucket).
    3️⃣ Insert metadata into ``public.documents``.
    4️⃣ Record an audit entry.
    Raises ``HTTPException`` on validation or backend errors.
    """
    if len(file_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File size exceeds 5 MiB limit",
        )
    if mime_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file type",
        )

    storage_path = _generate_storage_path(user.id, filename)
    # Use admin client (service_role) for storage upload – works with both real and mocked storage
    admin = get_supabase_admin_client()
    upload_res = admin.storage.from_(settings.SUPABASE_STORAGE_BUCKET).upload(
        storage_path, file_bytes
    )
    if upload_res.get("error"):
        # Log detailed error for debugging
        import logging, sys
        logging.getLogger("trustvault.storage").error(
            "Upload failed for path %s: %s", storage_path, upload_res.get("error")
        )
        # Also print to stdout for immediate visibility
        print('Upload error details:', upload_res.get("error"), flush=True)
        _log_audit(
            actor_id=user.id,
            action="document_upload",
            target_resource=storage_path,
            status_str="FAILURE",
            details={"error": upload_res["error"]},
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to store file in Supabase storage",
        )
    # Insert row.
    doc_payload = {
        "owner_id": str(user.id),
        "title": title,
        "file_name": filename,
        "file_path": storage_path,
        "file_size_bytes": len(file_bytes),
        "mime_type": mime_type,
    }
    insert_res = admin.table("documents").insert(doc_payload).execute()
    if insert_res.get("error"):
        # Cleanup orphaned object.
        admin.storage.from_(settings.SUPABASE_STORAGE_BUCKET).remove([storage_path])
        _log_audit(
            actor_id=user.id,
            action="document_upload",
            target_resource=storage_path,
            status_str="FAILURE",
            details={"error": insert_res["error"]},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record document metadata",
        )

    row = insert_res["data"][0]
    doc = UploadedDocument(**{k: v for k, v in row.items()})
    _log_audit(
        actor_id=user.id,
        action="document_upload",
        target_resource=row["file_path"],
        status_str="SUCCESS",
        details={"document_id": row["id"]},
    )
    return doc

def generate_download_url(
    *, doc_id: uuid.UUID, user: AuthenticatedUser, expiry_seconds: int = 60
) -> str:
    """Return a signed URL (default 60 s) after authorising the request.
    Authorisation mirrors the RLS ``documents_select_policy``:
    - Owner or admin always allowed.
    - Otherwise a row must exist in ``document_permissions`` for the user.
    """
    admin = get_supabase_admin_client()
    doc_res = (
        admin.table("documents")
        .select("*", "owner_id", "file_path")
        .eq("id", str(doc_id))
        .single()
        .execute()
    )
    if doc_res.get("error"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    doc = doc_res["data"]
    # Check role.
    profile_res = (
        admin.table("profiles").select("role").eq("id", str(user.id)).single().execute()
    )
    role = profile_res["data"].get("role") if not profile_res.get("error") else "viewer"
    authorized = doc["owner_id"] == str(user.id) or role == "admin"
    if not authorized:
        # Permission table check.
        perm_res = (
            admin.table("document_permissions")
            .select("id")
            .eq("document_id", str(doc_id))
            .eq("user_id", str(user.id))
            .single()
            .execute()
        )
        authorized = bool(perm_res.get("data"))
    if not authorized:
        _log_audit(
            actor_id=user.id,
            action="document_download",
            target_resource=doc["file_path"],
            status_str="DENIED",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    # Use admin client for signed URL generation (works with both real and mocked storage)
    signed = admin.storage.from_(settings.SUPABASE_STORAGE_BUCKET).create_signed_url(
        doc["file_path"], expiry_seconds
    )
    url = signed.get("signedURL") if isinstance(signed, dict) else signed["signedURL"]
    _log_audit(
        actor_id=user.id,
        action="document_download",
        target_resource=doc["file_path"],
        status_str="SUCCESS",
    )
    return url

def delete_document(*, doc_id: uuid.UUID, user: AuthenticatedUser) -> None:
    """Delete a document and its storage object.
    Only the owner or an admin may invoke.
    The operation is *not* atomic – storage is removed first; any DB failure is logged.
    """
    admin = get_supabase_admin_client()
    doc_res = (
        admin.table("documents")
        .select("file_path", "owner_id")
        .eq("id", str(doc_id))
        .single()
        .execute()
    )
    if doc_res.get("error"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")
    doc = doc_res["data"]
    # Role check.
    profile_res = (
        admin.table("profiles").select("role").eq("id", str(user.id)).single().execute()
    )
    role = profile_res["data"].get("role") if not profile_res.get("error") else "viewer"
    if doc["owner_id"] != str(user.id) and role != "admin":
        _log_audit(
            actor_id=user.id,
            action="document_delete",
            target_resource=doc["file_path"],
            status_str="DENIED",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    # Delete storage object.
    # Use admin client (service_role) for storage delete – matches bucket RLS
    admin = get_supabase_admin_client()
    storage_del = admin.storage.from_(settings.SUPABASE_STORAGE_BUCKET).remove([doc["file_path"]])
    # storage_del may be a dict or a list of dicts depending on supabase-py version
    if isinstance(storage_del, list):
        result = storage_del[0] if storage_del else {}
    else:
        result = storage_del
    if result.get("error"):
        _log_audit(
            actor_id=user.id,
            action="document_delete",
            target_resource=doc["file_path"],
            status_str="FAILURE",
            details={"error": result.get("error")},
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to delete file from storage",
        )

    # Delete DB row.
    db_del = admin.table("documents").delete().eq("id", str(doc_id)).execute()
    if db_del.get("error"):
        _log_audit(
            actor_id=user.id,
            action="document_delete",
            target_resource=doc["file_path"],
            status_str="FAILURE",
            details={"error": db_del["error"]},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete document metadata",
        )

    _log_audit(
        actor_id=user.id,
        action="document_delete",
        target_resource=doc["file_path"],
        status_str="SUCCESS",
    )

