"""
TrustVault First-Administrator Bootstrap Utility

Usage:
    .\\.venv\\Scripts\\python scripts\\bootstrap_admin.py <admin_email>

Security Guarantees:
- Runs strictly on the backend with SUPABASE_SERVICE_ROLE_KEY.
- Never prints or leaks credentials to logs or terminal.
- Enforces the 'first-admin lock': Only succeeds when zero administrators exist in the database.
- Once a single administrator exists, this script refuses to promote any additional admins,
  requiring subsequent promotions to be performed by an active administrator via RBAC.
"""

import os
import sys
import argparse
from pathlib import Path
from dotenv import load_dotenv

# Ensure UTF-8 output on Windows consoles
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
    if not secret:
        return "[NOT SET]"
    if len(secret) <= 8:
        return "[PROTECTED]"
    return f"{secret[:4]}...{secret[-4:]} [PROTECTED]"


def bootstrap_admin(target_email: str):
    target_email = target_email.strip().lower()
    supabase_url = os.getenv("SUPABASE_URL")
    service_role_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

    print("\n" + "=" * 65)
    print(" [TrustVault] First-Administrator Bootstrap Utility")
    print("=" * 65)
    print(f"Target User Email:    {target_email}")
    print(f"Supabase URL:         {supabase_url}")
    print(f"Service Role Key:     {mask_secret(service_role_key)}")

    if not supabase_url or "placeholder" in supabase_url:
        print("\n[!] Error: SUPABASE_URL is not properly configured in backend/.env.")
        sys.exit(1)

    if not service_role_key or "placeholder" in service_role_key:
        print("\n[!] Error: SUPABASE_SERVICE_ROLE_KEY is missing from backend/.env.")
        sys.exit(1)

    try:
        from supabase import create_client
        client = create_client(supabase_url, service_role_key)
    except Exception as exc:
        print(f"\n[!] Client initialization failed: {exc}")
        sys.exit(1)

    # 1. Verify if an administrator already exists
    try:
        res = client.table("profiles").select("id, email, role").eq("role", "admin").execute()
        existing_admins = res.data or []
        if len(existing_admins) > 0:
            print(f"\n[!] SECURITY LOCK ACTIVATED:")
            print(f"    The system already has {len(existing_admins)} active administrator(s).")
            print("    The initial bootstrap procedure is permanently closed.")
            print("    Subsequent promotions must be executed by an active Administrator.")
            sys.exit(1)
    except Exception as exc:
        print(f"\n[!] Database query failed: {exc}")
        print("    Please ensure migration '001_initial_schema.sql' has been applied first.")
        sys.exit(1)

    # 2. Check if the target user profile exists
    try:
        res = client.table("profiles").select("id, email, role").eq("email", target_email).execute()
        users = res.data or []
        if len(users) == 0:
            print(f"\n[!] Error: No user profile found for email '{target_email}'.")
            print("    Please register the user through Supabase Auth / the TrustVault frontend first.")
            sys.exit(1)
        
        user_id = users[0]["id"]
    except Exception as exc:
        print(f"\n[!] User lookup failed: {exc}")
        sys.exit(1)

    # 3. Call the security definer function bootstrap_first_admin
    try:
        client.rpc("bootstrap_first_admin", {"target_email": target_email}).execute()
        print(f"\n[SUCCESS] User '{target_email}' (ID: {user_id}) is now the Administrator!")
        print("          All bootstrap locks are now engaged.")
        print("=" * 65 + "\n")
    except Exception as exc:
        print(f"\n[!] Bootstrap RPC call failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootstrap the initial TrustVault administrator.")
    parser.add_argument("email", help="Email of the registered user to promote to administrator.")
    args = parser.parse_args()
    bootstrap_admin(args.email)
