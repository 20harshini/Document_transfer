from fastapi import APIRouter, Depends
from app.dependencies import get_current_user
from app.schemas.auth import AuthenticatedUser, AuthMeResponse, UserProfileResponse

router = APIRouter()

# Import required FastAPI utilities
from fastapi import HTTPException, status
from pydantic import BaseModel

# Supabase admin client for auth operations
from app.dependencies import get_supabase_admin_client

class AuthCredentials(BaseModel):
    email: str
    password: str



@router.get("/me", response_model=AuthMeResponse, summary="Get Current Authenticated User Profile")
def get_me(current_user: AuthenticatedUser = Depends(get_current_user)) -> AuthMeResponse:
    """
    Returns verified user profile and database-authoritative role.
    Requires Authorization: Bearer <valid_supabase_access_token>.
    """
    return AuthMeResponse(
        status="authenticated",
        user=UserProfileResponse(
            id=current_user.id,
            email=current_user.email,
            role=current_user.role,
            full_name=current_user.full_name,
        ),
    )


# Sign‑up endpoint – creates a new user via Supabase Auth
from supabase import create_client
from app.core.config import settings

# Sign‑up endpoint – creates a new user via Supabase Auth (public client)
@router.post("/signup", summary="Create a new user account")
def signup(creds: AuthCredentials):
    admin_client = get_supabase_admin_client()
    try:
        admin_client.auth.admin.create_user({
            "email": creds.email,
            "password": creds.password,
            "email_confirm": True,
        })
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    client = create_client(settings.SUPABASE_URL, settings.SUPABASE_ANON_KEY)
    try:
        sign_in_res = client.auth.sign_in_with_password({"email": creds.email, "password": creds.password})
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    if not sign_in_res.session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed after signup")
    return {"access_token": sign_in_res.session.access_token, "user": sign_in_res.user}

# Login endpoint – authenticates an existing user and returns an access token (public client)
@router.post("/login", summary="Authenticate user and obtain access token")
def login(creds: AuthCredentials):
    client = create_client(settings.SUPABASE_URL, settings.SUPABASE_ANON_KEY)
    try:
        response = client.auth.sign_in_with_password({"email": creds.email, "password": creds.password})
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    if not response.session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    return {"access_token": response.session.access_token, "user": response.user}
