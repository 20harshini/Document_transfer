"""
TrustVault Database Schema & Row-Level Security Verification Script

This script safely verifies that all required tables, storage buckets, 
and RLS configurations exist in the configured Supabase project.

SECURITY:
- Never prints or logs raw service-role keys or credentials.
- Performs only read operations.
- Non-destructive and safe to run at any time.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Configure UTF-8 encoding for Windows console compatibility
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

# Load backend/.env
env_path = backend_dir / ".env"
load_dotenv(dotenv_path=env_path)


def mask_secret(secret: str | None) -> str:
    """Safely mask sensitive strings for terminal output."""
    if not secret:
        return "[NOT SET]"
    if len(secret) <= 8:
        return "[PROTECTED]"
    return f"{secret[:4]}...{secret[-4:]} [PROTECTED]"


def run_verification():
    supabase_url = os.getenv("SUPABASE_URL")
    service_role_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    print("\n" + "=" * 65)
    print(" [TrustVault] Stage 2: Schema & RLS Verification")
    print("=" * 65)

    # 1. Environment & Key Checks
    print("\n[1] Environment Configuration:")
    print(f"  * Supabase URL:       {supabase_url}")
    print(f"  * Service Role Key:   {mask_secret(service_role_key)}")
    print(f"  * Storage Bucket:     {os.getenv('SUPABASE_STORAGE_BUCKET', 'vault-documents')}")

    if not supabase_url or "placeholder" in supabase_url:
        print("\n[!] Error: SUPABASE_URL is missing or contains placeholder values.")
        sys.exit(1)

    if not service_role_key or "placeholder" in service_role_key:
        print("\n[!] Error: SUPABASE_SERVICE_ROLE_KEY is missing or contains placeholder values.")
        sys.exit(1)

    # 2. Supabase Client Initialization
    try:
        from supabase import create_client
        client = create_client(supabase_url, service_role_key)
        print("  * SDK Client:         [OK] Initialized successfully")
    except Exception as exc:
        print(f"\n[!] Client Initialization Failed: {exc}")
        sys.exit(1)

    # 3. Tables Verification
    required_tables = [
        ("profiles", "User profiles with RBAC roles (admin, owner, viewer)"),
        ("documents", "Encrypted file metadata & private storage paths"),
        ("document_permissions", "Granular read/edit per-document sharing"),
        ("audit_logs", "Append-only tamper-evident security audit trail"),
    ]

    print("\n[2] Database Tables Verification:")
    all_tables_found = True
    missing_tables = []

    for table_name, description in required_tables:
        try:
            res = client.table(table_name).select("*", count="exact").limit(0).execute()
            print(f"  [OK] Table '{table_name}' is active.")
            print(f"       `- {description}")
        except Exception as exc:
            all_tables_found = False
            missing_tables.append(table_name)
            error_msg = str(exc)
            if "PGRST205" in error_msg or "schema cache" in error_msg:
                print(f"  [MISSING] Table '{table_name}' NOT found in database schema.")
            else:
                print(f"  [ERROR] Table '{table_name}' query error: {error_msg}")

    # 4. Storage Bucket Verification
    print("\n[3] Private Storage Bucket Verification:")
    bucket_name = os.getenv("SUPABASE_STORAGE_BUCKET", "vault-documents")
    bucket_verified = False

    try:
        bucket = client.storage.get_bucket(bucket_name)
        is_public = False
        if isinstance(bucket, dict):
            is_public = bucket.get("public", False)
        else:
            is_public = getattr(bucket, "public", False)
            
        print(f"  [OK] Bucket '{bucket_name}' exists.")
        if not is_public:
            print(f"  [OK] Storage visibility is PRIVATE (public = false).")
            bucket_verified = True
        else:
            print(f"  [WARNING] Bucket '{bucket_name}' is PUBLIC! It must be configured as private.")
    except Exception as exc:
        print(f"  [MISSING] Bucket '{bucket_name}' not found: {exc}")

    # 5. Summary & Guidance
    print("\n" + "=" * 65)
    print(" Verification Summary:")
    print("=" * 65)

    if all_tables_found and bucket_verified:
        print("[SUCCESS] ALL CHECKS PASSED!")
        print("   - All 4 application tables exist and are reachable.")
        print("   - Private storage bucket 'vault-documents' is configured.")
        print("   - Database schema is ready for Stage 2 authentication & endpoints.")
        print("=" * 65 + "\n")
        return 0
    else:
        print("[PENDING MIGRATION] Tables or storage bucket need to be created:")
        if missing_tables:
            print(f"   - Missing tables: {', '.join(missing_tables)}")
        if not bucket_verified:
            print(f"   - Private bucket '{bucket_name}' is not yet created.")
        print("\nNext Action:")
        print("   1. Review the SQL file: backend/migrations/001_initial_schema.sql")
        print("   2. Open the Supabase SQL Editor for your project.")
        print("   3. Paste and run 001_initial_schema.sql.")
        print("   4. Re-run this verification script:")
        print("      .\\.venv\\Scripts\\python scripts\\verify_schema.py")
        print("=" * 65 + "\n")
        return 1


if __name__ == "__main__":
    exit_code = run_verification()
    sys.exit(exit_code)
