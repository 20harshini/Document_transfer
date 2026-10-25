from datetime import datetime, timezone
from fastapi import APIRouter
from ....core.config import settings

router = APIRouter()


@router.get("", summary="System Health Check")
def check_health():
    """
    Health check endpoint to verify backend operational readiness.
    
    Used by:
    - Frontend startup check
    - Monitoring/Uptime probes
    - CI/CD deployment verification
    """
    is_supabase_configured = bool(
        settings.SUPABASE_URL
        and "placeholder" not in settings.SUPABASE_URL
        and settings.SUPABASE_SERVICE_ROLE_KEY
        and "placeholder" not in settings.SUPABASE_SERVICE_ROLE_KEY
    )

    return {
        "status": "ok",
        "app": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "api": "healthy",
            "supabase_configured": is_supabase_configured,
        },
    }
