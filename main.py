from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.v1 import api_router
from app.core.config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="TrustVault: Enterprise-grade secure document-sharing platform backend API.",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS (Cross-Origin Resource Sharing)
# This allows our React frontend (running on localhost:5173) to securely communicate with this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include v1 API router
app.include_router(api_router, prefix="/api/v1")


@app.get("/", summary="Root Index", tags=["General"])
def root():
    """
    Root endpoint offering API information and documentation links.
    """
    return {
        "message": "Welcome to TrustVault API",
        "version": settings.VERSION,
        "docs": "/docs",
        "health": "/api/v1/health",
        "status": "operational",
    }
