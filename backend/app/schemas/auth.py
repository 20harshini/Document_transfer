from typing import Optional
from uuid import UUID
from pydantic import BaseModel


class AuthenticatedUser(BaseModel):
    id: UUID
    email: str
    role: str
    full_name: Optional[str] = None


class UserProfileResponse(BaseModel):
    id: UUID
    email: str
    role: str
    full_name: Optional[str] = None


class AuthMeResponse(BaseModel):
    status: str = "authenticated"
    user: UserProfileResponse
