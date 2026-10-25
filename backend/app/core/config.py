from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

# Resolve absolute path to the project root (backend) and .env file
_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_ENV_PATH = _BACKEND_ROOT / ".env"


class Settings(BaseSettings):
    """
    Application Settings configured via environment variables or .env file.
    
    Security note:
    SUPABASE_SERVICE_ROLE_KEY bypasses Row Level Security (RLS) in Supabase.
    It MUST remain strictly in backend memory and never sent to clients or browser code.
    """
    ENVIRONMENT: str = "development"
    PROJECT_NAME: str = "TrustVault API"
    VERSION: str = "0.1.0"
    PORT: int = 8000
    HOST: str = "0.0.0.0"

    # CORS configuration - specifies which frontend origins can call this backend
    ALLOWED_ORIGINS: Union[str, List[str]] = "http://localhost:5173,http://127.0.0.1:5173"

    # Supabase connection credentials
    SUPABASE_URL: str = "https://yebmigbntwbapdcukbfz.supabase.co"
    SUPABASE_ANON_KEY: str = "placeholder-anon-key"
    SUPABASE_SERVICE_ROLE_KEY: str = "placeholder-service-role-key"
    SUPABASE_STORAGE_BUCKET: str = "vault-documents"

    @field_validator("ALLOWED_ORIGINS", mode="after")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @property
    def jwks_url(self) -> str:
        return f"{self.SUPABASE_URL.rstrip('/')}/auth/v1/.well-known/jwks.json"

    model_config = SettingsConfigDict(
        env_file=str(_ENV_PATH),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()

# Simple diagnostic helper (no secrets revealed)
def diagnostics() -> dict:
    """Return non‑sensitive configuration diagnostics.
    - supabase_host: hostname part of the URL
    - service_key_present: bool indicating a non‑empty key
    - service_key_placeholder: bool indicating the key looks like a placeholder value
    """
    url = settings.SUPABASE_URL.rstrip('/')
    hostname = url.split('://')[-1]
    key = settings.SUPABASE_SERVICE_ROLE_KEY
    placeholder = key.startswith('placeholder') or not key
    return {
        "supabase_host": hostname,
        "service_key_present": bool(key),
        "service_key_placeholder": placeholder,
    }

# Duplicate diagnostics removed
