
"""documents.py – FastAPI endpoints for document management (Stage 3).
Implements:
- POST   /documents          – upload a new document (owner = authenticated user)
- GET    /documents          – list documents visible to the user (owner or shared)
- GET    /documents/{doc_id} – generate a short‑lived download URL (60 s)
- DELETE /documents/{doc_id} – delete a document (owner or admin)
All endpoints depend on ``get_current_user`` which verifies the Supabase JWT.
The service‑role Supabase client is used internally via ``app.services.storage`` which
performs explicit ownership / permission checks, never trusting client‑supplied IDs.
"""

from uuid import UUID
from typing import List
from fastapi import APIRouter, Depends, status, UploadFile, File, Form

import app.dependencies as deps
from app.schemas.auth import AuthenticatedUser
from app.services import storage
from app.dependencies import get_supabase_admin_client


router = APIRouter()

@router.post(
    "/",
    response_model=storage.UploadedDocument,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a new document to the vault",
)
async def upload_document(
    title: str = Form(...),
    file: UploadFile = File(...),
    current_user: AuthenticatedUser = Depends(deps.get_current_user),
) -> storage.UploadedDocument:
    """Validate the multipart payload and store the document.
    ``python-multipart`` is required for ``UploadFile`` handling.
    """
    content = await file.read()
    return storage.upload_document(
        file_bytes=content,
        filename=file.filename,
        mime_type=file.content_type or "application/octet-stream",
        title=title,
        user=current_user,
    )

@router.get(
    "/",
    response_model=List[storage.UploadedDocument],
    summary="List documents accessible to the caller",
)
def list_documents(
    current_user: AuthenticatedUser = Depends(deps.get_current_user),
) -> List[storage.UploadedDocument]:
    admin = storage.get_supabase_admin_client()
    # Owner documents
    owner_res = (
        admin.table("documents")
        .select("*")
        .eq("owner_id", str(current_user.id))
        .execute()
    )
    owner_docs = owner_res.get("data", [])
    # Shared documents via permission table
    perms_res = (
        admin.table("document_permissions")
        .select("document_id")
        .eq("user_id", str(current_user.id))
        .execute()
    )
    doc_ids = [p["document_id"] for p in perms_res.get("data", [])]
    shared_docs = []
    if doc_ids:
        shared_res = (
            admin.table("documents")
            .select("*")
            .in_("id", [str(d) for d in doc_ids])
            .execute()
        )
        shared_docs = shared_res.get("data", [])
    # Merge and de‑duplicate
    all_docs = {doc["id"]: doc for doc in owner_docs + shared_docs}.values()
    return [storage.UploadedDocument(**doc) for doc in all_docs]

@router.get(
    "/{doc_id}",
    summary="Generate a short‑lived signed download URL for a document",
)
def get_download_url(
    doc_id: UUID,
    current_user: AuthenticatedUser = Depends(deps.get_current_user),
) -> dict:
    url = storage.generate_download_url(doc_id=doc_id, user=current_user)
    return {"download_url": url}

@router.delete(
    "/{doc_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a document (owner or admin only)",
)
def delete_document(
    doc_id: UUID,
    current_user: AuthenticatedUser = Depends(deps.get_current_user),
) -> None:
    storage.delete_document(doc_id=doc_id, user=current_user)
    return None

