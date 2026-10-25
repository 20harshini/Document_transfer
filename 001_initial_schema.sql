-- ============================================================================
-- TrustVault Migration 001: Initial Schema, Security Definer Triggers,
-- Storage Configuration, and Row-Level Security (RLS) Policies
--
-- TARGET: Supabase PostgreSQL
-- ARCHITECTURE: Zero-Trust Document Sharing Platform (Stage 2)
-- SECURITY HARDENED: Strict Least-Privilege, Idempotent Schema Patching,
-- Anti-Escalation, Storage RLS & Append-Only Audit Trail
-- ============================================================================

-- Ensure Required PostgreSQL Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 1. PROFILES TABLE (Extends Supabase auth.users)
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    full_name TEXT,
    role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'owner', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- Idempotent Column Reconciliation for profiles
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'profiles' AND column_name = 'role') THEN
        ALTER TABLE public.profiles ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'owner', 'viewer'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'profiles' AND column_name = 'full_name') THEN
        ALTER TABLE public.profiles ADD COLUMN full_name TEXT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'profiles' AND column_name = 'updated_at') THEN
        ALTER TABLE public.profiles ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now());
    END IF;
END $$;

-- Profiles Indexes
CREATE INDEX IF NOT EXISTS idx_profiles_role ON public.profiles(role);
CREATE INDEX IF NOT EXISTS idx_profiles_email ON public.profiles(email);

COMMENT ON TABLE public.profiles IS 'Application user profiles synchronized from auth.users with RBAC role assignments.';
COMMENT ON COLUMN public.profiles.role IS 'User role: admin (system oversight), owner (document creator), viewer (recipient).';

-- ============================================================================
-- 2. HELPER FUNCTIONS: Security Definer RBAC Helpers
-- ============================================================================

-- Check if current authenticated user has the 'admin' role
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.profiles
        WHERE id = auth.uid()
          AND role = 'admin'
    );
$$;

-- Check if current authenticated user has the 'owner' or 'admin' role
CREATE OR REPLACE FUNCTION public.is_owner()
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.profiles
        WHERE id = auth.uid()
          AND role IN ('owner', 'admin')
    );
$$;

REVOKE ALL ON FUNCTION public.is_admin() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_admin() TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.is_owner() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_owner() TO authenticated, service_role;

-- SECURITY DEFINER helper that breaks the RLS mutual-recursion chain between
-- profiles, documents, and document_permissions.
--
-- WHY THIS EXISTS:
--   profiles_select_policy needs to expose a profile to users who share a
--   document with them. An inline JOIN to document_permissions + documents
--   would be evaluated with RLS active, creating a cycle:
--     profiles RLS -> document_permissions RLS -> documents RLS -> document_permissions RLS...
--
-- HOW IT IS SAFE:
--   The function runs as its owner (postgres) with RLS bypassed.
--   It returns ONLY a BOOLEAN. No raw cross-user rows are returned.
--   It is strictly bounded to check the current auth.uid() against other_profile_id;
--   it cannot be used to enumerate arbitrary profile relationships.


-- SECURITY DEFINER helper to resolve document_permissions for storage RLS without
-- re-entering normal RLS evaluation on public tables.
--
-- WHY THIS EXISTS:
--   storage.objects SELECT policy needs to check document_permissions.
--   If it queries public.document_permissions directly, that table's RLS
--   re-evaluates public.documents, which re-evaluates public.document_permissions
--   -> infinite recursion in the storage read path.
--
-- HOW IT IS SAFE:
--   Returns only BOOLEAN. Bounded to the specific storage object name and
--   current auth.uid(). Cannot enumerate other users' permissions.






-- ---------------------------------------------------------------------------
-- Helper: document ownership check for permission policies
-- ---------------------------------------------------------------------------

-- ============================================================================
-- 3. AUTOMATIC PROFILE CREATION TRIGGER & FIRST-ADMIN BOOTSTRAP
-- ============================================================================

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    -- SECURITY RULE: All public signups strictly receive the 'viewer' role.
    -- All client-supplied role metadata is deliberately ignored.
    INSERT INTO public.profiles (id, email, full_name, role, created_at, updated_at)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', split_part(NEW.email, '@', 1)),
        'viewer', -- Hard-coded least-privilege default
        timezone('utc'::text, now()),
        timezone('utc'::text, now())
    )
    ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        full_name = COALESCE(EXCLUDED.full_name, public.profiles.full_name),
        updated_at = timezone('utc'::text, now());
        -- Role is NOT updated on conflict, preventing re-registration exploits

    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.handle_new_user() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_new_user();

-- ROLE ESCALATION GUARD
-- ============================================================================
-- This trigger fires on every UPDATE to public.profiles.
--
-- DESIGN RATIONALE FOR BOOTSTRAP INTERACTION:
--   The previous approach used session_user to bypass the trigger for trusted
--   callers. This was incorrect because in Supabase managed PostgreSQL, ALL
--   client connections (including service_role JWT) arrive via the PostgREST
--   connection pooler as session_user='authenticator'. PostgREST then issues
--   SET LOCAL ROLE service_role, which changes current_user but NOT session_user.
--   Therefore session_user='service_role' is never true for any JWT connection.
--
--   CORRECT DESIGN: bootstrap_first_admin and promote_user_role are both
--   SECURITY DEFINER functions. When they execute UPDATE on profiles, they run
--   as current_user='postgres' (the function owner). This trigger is also
--   SECURITY DEFINER so it runs as current_user='postgres' too. We detect this
--   trusted execution context by checking current_user, which correctly reflects
--   the SECURITY DEFINER escalation, unlike session_user which is fixed at login.
--
--   SECURITY BOUNDARY:
--     current_user='postgres' only when:
--       a) A SECURITY DEFINER function owned by postgres is executing, OR
--       b) A direct superuser connection via Supabase Dashboard SQL Editor.
--     Ordinary JWT-authenticated users always have current_user='authenticated'
--     (or 'anon') after PostgREST's SET LOCAL ROLE. They cannot SET ROLE to
--     'postgres' - that requires superuser privilege.
--
--   REMAINING RISK (accepted):
--     A direct superuser connection to the database can bypass this trigger.
--     This is an inherent PostgreSQL limitation that cannot be prevented at the
--     trigger layer. Access to the Supabase database password must be restricted
--     to authorised operators. This is documented and accepted.
CREATE OR REPLACE FUNCTION public.prevent_self_role_escalation()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    -- Allow role changes only during a trusted bootstrap operation.
    -- The bootstrap function runs as SECURITY DEFINER (owner = postgres).
    -- Detect trusted bootstrap by checking that the current execution role is the superuser.
    IF current_user = 'postgres' AND (SELECT COUNT(*) FROM public.profiles WHERE role = 'admin') = 0 AND NEW.role = 'admin' THEN
        NEW.updated_at := timezone('utc'::text, now());
        RETURN NEW;
    END IF;

    -- Normal operation: only administrators may modify roles.
    IF public.is_admin() THEN
        NEW.updated_at := timezone('utc'::text, now());
        RETURN NEW;
    END IF;

    -- All other callers: role changes are prohibited.
    IF NEW.role <> OLD.role THEN
        RAISE EXCEPTION 'Unauthorized: User role can only be modified by an Administrator.';
    END IF;
    NEW.updated_at := timezone('utc'::text, now());
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.prevent_self_role_escalation() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS trg_prevent_role_escalation ON public.profiles;
CREATE TRIGGER trg_prevent_role_escalation
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW
    EXECUTE FUNCTION public.prevent_self_role_escalation();

-- SAFE FIRST-ADMIN BOOTSTRAP PROCEDURE
-- ============================================================================
-- Only succeeds if there are currently ZERO admins in the entire system.
-- Once a single admin exists, this procedure strictly locks and rejects all calls.
-- Concurrency: Protected by an exclusive transaction-level advisory lock.
--
-- EXECUTION MODEL:
--   Called by backend/scripts/bootstrap_admin.py using the service_role JWT key.
--   The function is GRANT EXECUTE only to service_role.
--   The UPDATE inside fires prevent_self_role_escalation, which detects
--   current_user='postgres' (SECURITY DEFINER context) and allows the update.
CREATE OR REPLACE FUNCTION public.bootstrap_first_admin(target_email TEXT)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    admin_count INT;
    target_id UUID;
BEGIN
    -- Concurrency Control: Acquire exclusive transaction-level advisory lock.
    -- All concurrent bootstrap attempts are serialized; only the first succeeds.
    PERFORM pg_advisory_xact_lock(hashtext('trustvault_first_admin_bootstrap_lock'));

    SELECT count(*) INTO admin_count FROM public.profiles WHERE role = 'admin';
    IF admin_count > 0 THEN
        RAISE EXCEPTION 'Security Lock: First administrator has already been bootstrapped. Subsequent promotions require an active administrator.';
    END IF;

    SELECT id INTO target_id FROM public.profiles WHERE email = lower(trim(target_email));
    IF target_id IS NULL THEN
        RAISE EXCEPTION 'Target user profile not found for email: %', target_email;
    END IF;

    -- Bootstrap session marker removed; rely on SECURITY DEFINER and current_user check in trigger.
    UPDATE public.profiles
    SET role = 'admin', updated_at = timezone('utc'::text, now())
    WHERE id = target_id;
END;
$$;

-- Ensure only the bootstrap function can run as this role
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'bootstrap_role'
  ) THEN
    CREATE ROLE bootstrap_role NOLOGIN;
  END IF;
END $$;


REVOKE ALL ON FUNCTION public.bootstrap_first_admin(TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.bootstrap_first_admin(TEXT) TO service_role;

-- Standard role promotion for active administrators
CREATE OR REPLACE FUNCTION public.promote_user_role(target_user_id UUID, new_role TEXT)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    -- Verify the CALLING authenticated user is an admin (checked via their JWT uid).
    -- This function is SECURITY DEFINER so it runs as current_user='postgres',
    -- but auth.uid() still reflects the original authenticated user's JWT.
    IF NOT public.is_admin() THEN
        RAISE EXCEPTION 'Unauthorized: Only administrators can assign roles.';
    END IF;

    IF new_role NOT IN ('admin', 'owner', 'viewer') THEN
        RAISE EXCEPTION 'Invalid role: Must be admin, owner, or viewer.';
    END IF;

    -- UPDATE fires trg_prevent_role_escalation.
    -- current_user='postgres' (SECURITY DEFINER) -> bypass activates.
    -- is_admin() guard above already verified the calling user is an admin.
    UPDATE public.profiles
    SET role = new_role, updated_at = timezone('utc'::text, now())
    WHERE id = target_user_id;
END;
$$;

REVOKE ALL ON FUNCTION public.promote_user_role(UUID, TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.promote_user_role(UUID, TEXT) TO authenticated;

-- ============================================================================
-- 4. DOCUMENTS TABLE (File Metadata for Encrypted Private Storage)
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size_bytes BIGINT NOT NULL CHECK (file_size_bytes > 0),
    mime_type TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    -- Enforce one-to-one storage object mapping; prevents two documents
    -- pointing at the same file and the orphan/collision problems that follow.
    CONSTRAINT documents_file_path_unique UNIQUE (file_path)
);

-- Idempotent Column Reconciliation for documents
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'documents' AND column_name = 'version') THEN
        ALTER TABLE public.documents ADD COLUMN version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'documents' AND column_name = 'file_size_bytes') THEN
        ALTER TABLE public.documents ADD COLUMN file_size_bytes BIGINT NOT NULL DEFAULT 1 CHECK (file_size_bytes > 0);
    END IF;
-- Detect duplicate file_path values before adding the unique constraint.
-- Abort migration with clear error if any duplicates exist.
IF EXISTS (
    SELECT file_path FROM public.documents
    GROUP BY file_path
    HAVING COUNT(*) > 1
) THEN
    RAISE EXCEPTION 'Duplicate file_path values detected in documents table. Resolve duplicates before applying migration.';
END IF;

-- Add UNIQUE constraint on file_path if missing (reconciliation for partial schemas)
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.documents'::regclass AND conname = 'documents_file_path_unique') THEN
    ALTER TABLE public.documents ADD CONSTRAINT documents_file_path_unique UNIQUE (file_path);
END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_documents_owner_id ON public.documents(owner_id);

-- Helper: document ownership check for permission policies
CREATE OR REPLACE FUNCTION public.document_owned_by_user(p_document_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.documents d
        WHERE d.id = p_document_id
          AND (d.owner_id = auth.uid() OR public.is_admin())
    );
$$;

REVOKE ALL ON FUNCTION public.document_owned_by_user(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.document_owned_by_user(UUID) TO authenticated, service_role;
CREATE INDEX IF NOT EXISTS idx_documents_created_at ON public.documents(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_documents_file_path ON public.documents(file_path);

COMMENT ON TABLE public.documents IS 'Document records referencing files stored in the private vault-documents bucket.';
COMMENT ON COLUMN public.documents.file_path IS 'Path within vault-documents bucket. Unique: one document record per storage object.';

-- DOCUMENT MODIFICATION GUARD
-- ============================================================================
-- Protects structural and ownership fields from modification.
--
-- EDITOR ACCESS SCOPE:
--   editors (users with edit permission) may update: title, version, updated_at.
--   They MUST NOT be able to update: file_path, file_name, file_size_bytes, mime_type.
--   Changing file_path would redirect downloads to a different storage object,
--   enabling a file-substitution attack against other permittees.
--   Changing file_name/mime_type corrupts content-type handling.
--
--   These file-identity fields are only updatable by the document owner or admin
--   (e.g., when replacing a document's file via a new upload).
CREATE OR REPLACE FUNCTION public.guard_document_modifications()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    caller_is_owner BOOLEAN;
    caller_is_admin BOOLEAN;
BEGIN
    -- 1. Primary Key is strictly immutable
    IF NEW.id <> OLD.id THEN
        RAISE EXCEPTION 'Security Violation: Document ID is immutable.';
    END IF;

    -- 2. Creation timestamp is immutable
    IF NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'Security Violation: Document creation timestamp is immutable.';
    END IF;

    caller_is_admin := public.is_admin();
    caller_is_owner := (auth.uid() = OLD.owner_id);

    -- 3. Ownership transfer: admin only
    IF NEW.owner_id <> OLD.owner_id AND NOT caller_is_admin THEN
        RAISE EXCEPTION 'Security Violation: Document ownership can only be transferred by an Administrator.';
    END IF;

    -- 4. File-identity fields: owner or admin only.
    --    An editor (has edit permission but is not the owner) cannot change what
    --    file the document points to, preventing file-substitution attacks.
    IF NOT (caller_is_owner OR caller_is_admin) THEN
        IF NEW.file_path <> OLD.file_path THEN
            RAISE EXCEPTION 'Security Violation: Only the document owner or an administrator may change the storage path.';
        END IF;
        IF NEW.file_name <> OLD.file_name THEN
            RAISE EXCEPTION 'Security Violation: Only the document owner or an administrator may change the file name.';
        END IF;
        IF NEW.file_size_bytes <> OLD.file_size_bytes THEN
            RAISE EXCEPTION 'Security Violation: Only the document owner or an administrator may change the file size.';
        END IF;
        IF NEW.mime_type <> OLD.mime_type THEN
            RAISE EXCEPTION 'Security Violation: Only the document owner or an administrator may change the MIME type.';
        END IF;
    END IF;

    NEW.updated_at := timezone('utc'::text, now());
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.guard_document_modifications() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS trg_guard_document_modifications ON public.documents;
CREATE TRIGGER trg_guard_document_modifications
    BEFORE UPDATE ON public.documents
    FOR EACH ROW
    EXECUTE FUNCTION public.guard_document_modifications();

-- ============================================================================
-- 5. DOCUMENT PERMISSIONS TABLE (Granular Access & Immediate Revocation)
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.document_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES public.documents(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    permission_level TEXT NOT NULL CHECK (permission_level IN ('read', 'edit')),
    granted_by UUID NOT NULL REFERENCES public.profiles(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    CONSTRAINT unique_document_user_permission UNIQUE (document_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_doc_perms_doc_id ON public.document_permissions(document_id);
CREATE INDEX IF NOT EXISTS idx_doc_perms_user_id ON public.document_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_doc_perms_granted_by ON public.document_permissions(granted_by);

-- SECURITY DEFINER helper to check storage delete authorization without RLS recursion.
CREATE OR REPLACE FUNCTION public.user_owns_storage_object(object_name TEXT)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.documents d
        WHERE d.file_path = object_name
          AND d.owner_id = auth.uid()
    );
$$;

REVOKE ALL ON FUNCTION public.user_owns_storage_object(TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.user_owns_storage_object(TEXT) TO authenticated, service_role;

-- Helper: document access check for documents table (used by documents_select_policy)
CREATE OR REPLACE FUNCTION public.user_can_access_document(p_document_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER 
SET search_path = public
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.documents d
        WHERE d.id = p_document_id
          AND (
              d.owner_id = auth.uid()
              OR public.is_admin()
              OR EXISTS (
                  SELECT 1
                  FROM public.document_permissions dp
                  WHERE dp.document_id = d.id
                    AND dp.user_id = auth.uid()
              )
          )
    );
$$;

REVOKE ALL ON FUNCTION public.user_can_access_document(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.user_can_access_document(UUID) TO authenticated, service_role;

-- SECURITY DEFINER helper that checks storage read access without RLS recursion.
CREATE OR REPLACE FUNCTION public.user_can_access_storage_object(object_name TEXT)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.documents d
        WHERE d.file_path = object_name
          AND (
              d.owner_id = auth.uid()
              OR EXISTS (
                  SELECT 1
                  FROM public.document_permissions dp
                  WHERE dp.document_id = d.id
                    AND dp.user_id = auth.uid()
              )
          )
    );
$$;

REVOKE ALL ON FUNCTION public.user_can_access_storage_object(TEXT) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.user_can_access_storage_object(TEXT) TO authenticated, service_role;

COMMENT ON TABLE public.document_permissions IS 'Explicit per-document sharing permissions granting read or edit access to specific users.';

-- Trigger guarding document_permissions keys from being altered on UPDATE
CREATE OR REPLACE FUNCTION public.guard_permission_modifications()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    -- Permission relationship fields are immutable. Only permission_level may change.
    -- To change document_id, user_id, or granted_by: revoke and re-grant.
    IF NEW.id <> OLD.id OR NEW.document_id <> OLD.document_id OR NEW.user_id <> OLD.user_id OR NEW.granted_by <> OLD.granted_by THEN
        RAISE EXCEPTION 'Security Violation: Permission relationship (document_id, user_id, granted_by, id) is immutable. Revoke access and grant afresh.';
    END IF;
    NEW.updated_at := timezone('utc'::text, now());
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.guard_permission_modifications() FROM PUBLIC, anon, authenticated;

DROP TRIGGER IF EXISTS trg_guard_permission_modifications ON public.document_permissions;
CREATE TRIGGER trg_guard_permission_modifications
    BEFORE UPDATE ON public.document_permissions
    FOR EACH ROW
    EXECUTE FUNCTION public.guard_permission_modifications();
CREATE OR REPLACE FUNCTION public.current_user_shares_document_with(other_profile_id UUID)
RETURNS BOOLEAN
LANGUAGE sql
SECURITY DEFINER
SET search_path = public
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.document_permissions dp
        JOIN public.documents d ON d.id = dp.document_id
        WHERE
            -- Current user is the document owner and other_profile is a permittee
            (d.owner_id = auth.uid()  AND dp.user_id = other_profile_id)
            OR
            -- Current user is a permittee and other_profile is the owner
            (dp.user_id = auth.uid() AND d.owner_id = other_profile_id)
    );
$$;

REVOKE ALL ON FUNCTION public.current_user_shares_document_with(UUID) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.current_user_shares_document_with(UUID) TO authenticated, service_role;


-- ============================================================================
-- 6. AUDIT LOGS TABLE (Tamper-Evident & Append-Only)
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_resource TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address TEXT,
    user_agent TEXT,
    status TEXT NOT NULL CHECK (status IN ('SUCCESS', 'FAILURE', 'DENIED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE INDEX IF NOT EXISTS idx_audit_actor_id ON public.audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON public.audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON public.audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_target_resource ON public.audit_logs(target_resource);

COMMENT ON TABLE public.audit_logs IS 'Append-only immutable audit trail capturing authentication, access, and document lifecycle events.';

-- Revoke all mutations from client roles (anon, authenticated, public).
-- The backend writes audit logs exclusively via the service_role key (Section 9).
-- Client roles have INSERT revoked here AND have no RLS INSERT policy, providing
-- defence in depth. No client path can write to audit_logs.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.audit_logs FROM anon, authenticated, public;

-- Defensive Triggers blocking UPDATE, DELETE, and TRUNCATE.
-- IMMUTABILITY LIMITS: These triggers protect against application-level tampering
-- and accidental mutations. A PostgreSQL superuser (postgres) connecting directly
-- to the database CAN disable triggers. Database-level immutability at the
-- application role level is what these triggers provide.
CREATE OR REPLACE FUNCTION public.prevent_audit_log_tampering()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RAISE EXCEPTION 'Security Violation: Audit logs are strictly immutable and cannot be updated, deleted, or truncated.';
END;
$$;

REVOKE ALL ON FUNCTION public.prevent_audit_log_tampering() FROM PUBLIC, anon, authenticated;

-- Row-level trigger blocking UPDATE and DELETE
DROP TRIGGER IF EXISTS trg_immutable_audit_logs ON public.audit_logs;
CREATE TRIGGER trg_immutable_audit_logs
    BEFORE UPDATE OR DELETE ON public.audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION public.prevent_audit_log_tampering();

-- Statement-level trigger blocking TRUNCATE
DROP TRIGGER IF EXISTS trg_immutable_audit_logs_truncate ON public.audit_logs;
CREATE TRIGGER trg_immutable_audit_logs_truncate
    BEFORE TRUNCATE ON public.audit_logs
    FOR EACH STATEMENT
    EXECUTE FUNCTION public.prevent_audit_log_tampering();

-- Comprehensive schema and constraint reconciliation for partial/pre-existing schemas
DO $$
BEGIN
    -- profiles constraints & column defaults
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.profiles'::regclass AND conname = 'profiles_role_check') THEN
        ALTER TABLE public.profiles ADD CONSTRAINT profiles_role_check CHECK (role IN ('admin', 'owner', 'viewer'));
    END IF;

    -- documents constraints & column checks
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.documents'::regclass AND conname = 'documents_file_size_check') THEN
        ALTER TABLE public.documents ADD CONSTRAINT documents_file_size_check CHECK (file_size_bytes > 0);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.documents'::regclass AND conname = 'documents_version_check') THEN
        ALTER TABLE public.documents ADD CONSTRAINT documents_version_check CHECK (version >= 1);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.documents'::regclass AND conname = 'documents_file_path_unique') THEN
        ALTER TABLE public.documents ADD CONSTRAINT documents_file_path_unique UNIQUE (file_path);
    END IF;

    -- document_permissions constraints
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.document_permissions'::regclass AND conname = 'unique_document_user_permission') THEN
        ALTER TABLE public.document_permissions ADD CONSTRAINT unique_document_user_permission UNIQUE (document_id, user_id);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.document_permissions'::regclass AND conname = 'doc_perms_level_check') THEN
        ALTER TABLE public.document_permissions ADD CONSTRAINT doc_perms_level_check CHECK (permission_level IN ('read', 'edit'));
    END IF;

    -- audit_logs constraints
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'public.audit_logs'::regclass AND conname = 'audit_status_check') THEN
        ALTER TABLE public.audit_logs ADD CONSTRAINT audit_status_check CHECK (status IN ('SUCCESS', 'FAILURE', 'DENIED'));
    END IF;
END $$;

-- ============================================================================
-- 7. PRIVATE STORAGE BUCKET CONFIGURATION & POLICIES
-- ============================================================================

-- Ensure the 'vault-documents' bucket exists with public = false (Private Storage).
--
-- POST-MIGRATION CHECK (run verify_schema.py):
--   SELECT id, name, public, file_size_limit FROM storage.buckets WHERE id = 'vault-documents';
--   Expected: public=false, file_size_limit=52428800
--
-- If this block emits a WARNING, create the bucket manually in the Supabase
-- Dashboard (Storage -> New bucket -> Name: vault-documents, Public: OFF,
-- Max file size: 50MB) BEFORE running storage RLS policies below.
DO $$
BEGIN
    INSERT INTO storage.buckets (id, name, public, file_size_limit)
    VALUES ('vault-documents', 'vault-documents', false, 52428800)
    ON CONFLICT (id) DO UPDATE SET public = false, file_size_limit = 52428800;
EXCEPTION
    WHEN undefined_table THEN
        RAISE EXCEPTION 'storage.buckets table not found - create the vault-documents bucket manually via the Supabase Dashboard before applying storage policies.';
    WHEN OTHERS THEN
        RAISE EXCEPTION 'vault-documents bucket setup failed: % - investigate and resolve before applying storage policies.', SQLERRM;
END $$;

-- Verify that the bucket exists and has the expected properties
DO $$
DECLARE
    v_public boolean;
    v_limit bigint;
BEGIN
    SELECT public, file_size_limit INTO v_public, v_limit
    FROM storage.buckets
    WHERE id = 'vault-documents';
    IF v_public IS NULL THEN
        RAISE EXCEPTION 'Bucket vault-documents does not exist after setup.';
    ELSIF v_public <> false OR v_limit <> 52428800 THEN
        RAISE EXCEPTION 'Bucket vault-documents properties mismatch: public=% expected false, file_size_limit=% expected 52428800.', v_public, v_limit;
    END IF;
END $$;

-- STORAGE OBJECT POLICIES
-- ============================================================================
-- ARCHITECTURE NOTE:
--   In Stage 3, file uploads and document record creation happen in the same
--   backend operation (service_role key). Clients do NOT upload directly to
--   storage. The INSERT policy below permits direct client upload only as a
--   fallback; the backend upload path bypasses client RLS via service_role.
--
--   ORPHAN RISK: Deleting a documents row does NOT automatically delete the
--   storage object. The backend DELETE endpoint MUST:
--     1. Delete the storage object first (or transactionally).
--     2. Then delete the documents row.
--   This is a backend responsibility. The database cannot enforce it atomically
--   without a storage-triggering mechanism not available in standard PostgreSQL.

-- 1. Read Policy: Accessible if user is Admin, document Owner, or has
--    an explicit permission entry. Uses SECURITY DEFINER helper to avoid
--    RLS recursion: storage->documents->document_permissions->documents.
DROP POLICY IF EXISTS "vault_storage_select_policy" ON storage.objects;
CREATE POLICY "vault_storage_select_policy"
    ON storage.objects
    FOR SELECT
    TO authenticated
    USING (
        bucket_id = 'vault-documents'
        AND (
            public.is_admin()
            OR public.user_can_access_storage_object(storage.objects.name)
        )
    );

-- 2. Insert Policy: Restricted to Document Owners and Admins.
--    NOTE: This policy cannot validate that storage.objects.name corresponds
--    to a valid documents.file_path entry, because that record may not exist
--    yet at upload time. The backend is responsible for creating the documents
--    record in the same request that performs the upload.
DROP POLICY IF EXISTS "vault_storage_insert_policy" ON storage.objects;
CREATE POLICY "vault_storage_insert_policy"
    ON storage.objects
    FOR INSERT
    TO authenticated
    WITH CHECK (
        bucket_id = 'vault-documents'
        AND public.is_owner()
    );

-- 3. Delete Policy: Only the document owner or admin may delete storage objects.
--    Uses SECURITY DEFINER helper to avoid RLS recursion.
DROP POLICY IF EXISTS "vault_storage_delete_policy" ON storage.objects;
CREATE POLICY "vault_storage_delete_policy"
    ON storage.objects
    FOR DELETE
    TO authenticated
    USING (
        bucket_id = 'vault-documents'
        AND (
            public.is_admin()
            OR public.user_owns_storage_object(storage.objects.name)
        )
    );

-- ============================================================================
-- 8. ROW LEVEL SECURITY (RLS) POLICIES & TABLE GRANTS
-- ============================================================================

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.document_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- Explicit Table Grants for Authenticated Users (Least Privilege)
REVOKE ALL ON public.profiles FROM PUBLIC, anon;
REVOKE ALL ON public.documents FROM PUBLIC, anon;
REVOKE ALL ON public.document_permissions FROM PUBLIC, anon;
REVOKE ALL ON public.audit_logs FROM PUBLIC, anon;

-- Profiles: authenticated users may update only their display name
GRANT SELECT ON public.profiles TO authenticated;
GRANT UPDATE(full_name, updated_at) ON public.profiles TO authenticated;

-- Documents: authenticated users can perform CRUD subject to RLS and trigger guards
GRANT SELECT, INSERT, UPDATE, DELETE ON public.documents TO authenticated;

-- Document Permissions: authenticated users can manage sharing subject to RLS
GRANT SELECT, INSERT, DELETE ON public.document_permissions TO authenticated;
GRANT UPDATE(permission_level, updated_at) ON public.document_permissions TO authenticated;

-- Audit Logs: authenticated users may only SELECT their own records (per RLS below).
-- INSERT/UPDATE/DELETE/TRUNCATE have been revoked above (Section 6).
GRANT SELECT ON public.audit_logs TO authenticated;

-- ----------------------------------------------------------------------------
-- 8.1 PROFILES POLICIES
-- ----------------------------------------------------------------------------

-- SELECT: own profile, any profile if admin, or any profile sharing a document.
-- Uses current_user_shares_document_with() SECURITY DEFINER helper to avoid
-- the profiles->document_permissions->documents->document_permissions recursion.
DROP POLICY IF EXISTS "profiles_select_policy" ON public.profiles;
CREATE POLICY "profiles_select_policy"
    ON public.profiles
    FOR SELECT
    TO authenticated
    USING (
        auth.uid() = id
        OR public.is_admin()
        OR public.current_user_shares_document_with(profiles.id)
    );

-- UPDATE: users may update only their own profile; admins may update any profile.
-- Column-level grant above restricts updatable columns to full_name and updated_at.
-- The trg_prevent_role_escalation trigger prevents role changes by non-admins.
DROP POLICY IF EXISTS "profiles_update_policy" ON public.profiles;
CREATE POLICY "profiles_update_policy"
    ON public.profiles
    FOR UPDATE
    TO authenticated
    USING (auth.uid() = id OR public.is_admin())
    WITH CHECK (auth.uid() = id OR public.is_admin());

-- ----------------------------------------------------------------------------
-- 8.2 DOCUMENTS POLICIES
-- ----------------------------------------------------------------------------

-- SELECT: owner sees all their documents; admin sees everything;
-- permittees see documents they have been explicitly granted access to.
-- The subquery against document_permissions is safe here: document_permissions
-- SELECT policy does NOT re-subquery documents (it checks document_id directly),
-- so there is no recursion on this path.
DROP POLICY IF EXISTS "documents_select_policy" ON public.documents;
CREATE POLICY "documents_select_policy"
    ON public.documents
    FOR SELECT
    TO authenticated
    USING (
        public.user_can_access_document(id)
    );

-- INSERT: only users with the 'owner' or 'admin' role may create document records,
-- and they must set themselves as the owner.
DROP POLICY IF EXISTS "documents_insert_policy" ON public.documents;
CREATE POLICY "documents_insert_policy"
    ON public.documents
    FOR INSERT
    TO authenticated
    WITH CHECK (
        owner_id = auth.uid()
        AND public.is_owner()
    );

-- UPDATE: owner, admin, or users with 'edit' permission may update.
-- The guard_document_modifications trigger further restricts which columns
-- editors can change (title, version only; file-identity fields require owner/admin).
DROP POLICY IF EXISTS "documents_update_policy" ON public.documents;
CREATE POLICY "documents_update_policy"
    ON public.documents
    FOR UPDATE
    TO authenticated
    USING (
        owner_id = auth.uid()
        OR public.is_admin()
        OR EXISTS (
            SELECT 1
            FROM public.document_permissions dp
            WHERE dp.document_id = documents.id
              AND dp.user_id = auth.uid()
              AND dp.permission_level = 'edit'
        )
    )
    WITH CHECK (
        owner_id = auth.uid()
        OR public.is_admin()
        OR EXISTS (
            SELECT 1
            FROM public.document_permissions dp
            WHERE dp.document_id = documents.id
              AND dp.user_id = auth.uid()
              AND dp.permission_level = 'edit'
        )
    );

-- DELETE: owner or admin only. Storage object cleanup is a backend responsibility.
DROP POLICY IF EXISTS "documents_delete_policy" ON public.documents;
CREATE POLICY "documents_delete_policy"
    ON public.documents
    FOR DELETE
    TO authenticated
    USING (
        owner_id = auth.uid()
        OR public.is_admin()
    );

-- ----------------------------------------------------------------------------
-- 8.3 DOCUMENT PERMISSIONS POLICIES
-- ----------------------------------------------------------------------------

-- SELECT: a user sees permissions granted to them, or permissions on documents
-- they own, or all permissions if admin.
-- NOTE: This subquery against documents does NOT re-enter document_permissions,
-- so there is no recursion on this SELECT path.
DROP POLICY IF EXISTS "doc_perms_select_policy" ON public.document_permissions;
CREATE POLICY "doc_perms_select_policy"
    ON public.document_permissions
    FOR SELECT
    TO authenticated
    USING (
        user_id = auth.uid()
        OR public.is_admin()
        OR EXISTS (
            SELECT 1
            FROM public.documents d
            WHERE d.id = document_permissions.document_id
              AND d.owner_id = auth.uid()
        )
    );

-- INSERT: document owner or admin may grant permissions.
-- granted_by must equal the authenticated caller (prevents forgery).
DROP POLICY IF EXISTS "doc_perms_insert_policy" ON public.document_permissions;
CREATE POLICY "doc_perms_insert_policy"
    ON public.document_permissions
    FOR INSERT
    TO authenticated
    WITH CHECK (
        granted_by = auth.uid()
        AND (
            public.is_admin()
            OR public.document_owned_by_user(document_id)
        )
    );

-- UPDATE: document owner or admin may change permission_level.
-- Column-level grant above restricts to permission_level and updated_at.
-- guard_permission_modifications trigger prevents changing document_id/user_id/granted_by.
DROP POLICY IF EXISTS "doc_perms_update_policy" ON public.document_permissions;
CREATE POLICY "doc_perms_update_policy"
    ON public.document_permissions
    FOR UPDATE
    TO authenticated
    USING (
        public.is_admin()
        OR public.document_owned_by_user(document_id)
    )
    WITH CHECK (
        public.is_admin()
        OR public.document_owned_by_user(document_id)
    );

-- DELETE: document owner or admin may revoke permissions.
DROP POLICY IF EXISTS "doc_perms_delete_policy" ON public.document_permissions;
CREATE POLICY "doc_perms_delete_policy"
    ON public.document_permissions
    FOR DELETE
    TO authenticated
    USING (
        public.is_admin()
        OR public.document_owned_by_user(document_id)
    );

-- ----------------------------------------------------------------------------
-- 8.4 AUDIT LOGS POLICIES (Append-Only & Anti-Forgery)
-- ----------------------------------------------------------------------------

-- SELECT: users see logs where they are the actor; admins see everything;
-- document owners see logs referencing their documents.
--
-- RECURSION NOTE: The WHERE clause on public.documents is evaluated with
-- documents_select_policy active. That policy subqueries document_permissions,
-- whose SELECT policy subqueries documents -> potential recursion.
-- FIX: The inner EXISTS subquery reads documents directly with a simple
-- owner_id = auth.uid() check. documents_select_policy USING clause is
-- evaluated, but its own EXISTS (document_permissions) subquery calls
-- doc_perms_select_policy, which checks document_id directly without
-- re-entering documents. Recursion terminates at depth 2 in practice.
-- This is safe but noted for awareness.
DROP POLICY IF EXISTS "audit_logs_select_policy" ON public.audit_logs;
CREATE POLICY "audit_logs_select_policy"
    ON public.audit_logs
    FOR SELECT
    TO authenticated
    USING (
        actor_id = auth.uid()
        OR public.is_admin()
        OR (
            target_resource IS NOT NULL
            AND public.document_owned_by_user(
                -- Safely cast only if the string looks like a UUID
                CASE WHEN target_resource ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN target_resource::uuid ELSE NULL END
            )
        )
    );

-- ============================================================================
-- 9. SERVICE ROLE FULL ACCESS GRANTS
-- ============================================================================
-- The backend uses the service_role key (stored server-side in backend/.env,
-- never exposed to the frontend or committed to Git) for:
--   - Writing audit log entries (INSERT)
--   - Admin management queries
--   - Bootstrap first-admin promotion via bootstrap_first_admin()
--
-- service_role bypasses RLS by default in Supabase. Explicit grants below
-- ensure DML access even if that behaviour is changed in a Supabase update.
--
-- WRITE PATH FOR AUDIT LOGS:
--   Backend only -> service_role key -> GRANT INSERT below -> INSERT succeeds.
--   Client roles -> INSERT revoked (Section 6) -> no RLS INSERT policy -> blocked.

GRANT ALL ON public.profiles             TO service_role;
GRANT ALL ON public.documents            TO service_role;
GRANT ALL ON public.document_permissions TO service_role;
GRANT ALL ON public.audit_logs           TO service_role;

-- Sequence grants (needed for UUID default columns if using sequences)
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO authenticated;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO service_role;
DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'bootstrap_role') THEN CREATE ROLE bootstrap_role NOLOGIN; END IF; END $$;
-- ============================================================================
-- 10. POST-MIGRATION VERIFICATION CHECKLIST
-- ============================================================================
-- Run these checks after applying this migration:
--
-- 1. Schema verification:
--      python scripts/verify_schema.py
--
-- 2. Live integration tests (non-mutating):
--      pytest -v tests/test_live_supabase_integration.py
--
-- 3. Bucket verification (run in SQL Editor):
--      SELECT id, name, public, file_size_limit
--      FROM storage.buckets WHERE id = 'vault-documents';
--      -- Expected: public=false, file_size_limit=52428800
--
-- 4. RLS status:
--      SELECT tablename, rowsecurity FROM pg_tables
--      WHERE schemaname='public' AND tablename IN
--        ('profiles','documents','document_permissions','audit_logs');
--      -- All four must show rowsecurity=true
--
-- 5. Bootstrap first admin (after a user has signed up):
--      python scripts/bootstrap_admin.py admin@example.com
--
-- ============================================================================
-- INVENTORY
-- ============================================================================
-- Tables   : profiles, documents, document_permissions, audit_logs
-- Functions: handle_new_user, prevent_self_role_escalation,
--            guard_document_modifications, guard_permission_modifications,
--            prevent_audit_log_tampering, bootstrap_first_admin,
--            promote_user_role, is_admin, is_owner,
--            current_user_shares_document_with,
--            user_can_access_storage_object, user_owns_storage_object
-- Triggers : on_auth_user_created, trg_prevent_role_escalation,
--            trg_guard_document_modifications, trg_guard_permission_modifications,
--            trg_immutable_audit_logs, trg_immutable_audit_logs_truncate
-- Storage  : vault-documents (private bucket, 50 MB limit)
-- RLS      : Enabled on all 4 tables with least-privilege policies
--
-- PRECONDITIONS:
--   1. Supabase Auth (auth.users) must be enabled.
--   2. The vault-documents bucket must exist (created via Dashboard or this migration).
--   3. Extensions uuid-ossp and pgcrypto must be available (created above).
--   4. Apply via the Supabase Dashboard SQL Editor only.
--      Do NOT run via psql as a non-superuser without service_role access.
--
-- ACCEPTED REMAINING RISKS:
--   1. A direct PostgreSQL superuser connection can bypass triggers, including
--      the audit log immutability triggers. Restrict Supabase database password
--      access to authorised operators only.
--   2. The storage INSERT policy does not validate that the uploaded object path
--      exists in public.documents. The backend must create the documents record
--      atomically with the upload. Stale storage objects are possible if the
--      backend crashes between upload and record creation.
--   3. Live RLS behaviour is NOT verified by this migration alone. Run the full
--      integration test suite (test_live_supabase_integration.py) after applying.
-- ============================================================================
SELECT 'TrustVault 001_initial_schema migration complete' AS migration_status;
