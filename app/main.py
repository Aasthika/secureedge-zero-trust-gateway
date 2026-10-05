from fastapi import FastAPI

from app.config import settings


app = FastAPI(
    title=settings.app_name,
    description="Zero-Trust API Gateway & Policy Enforcement Platform",
    version=settings.app_version,
)


@app.get("/")
async def root():
    return {
        "service": settings.app_name,
        "status": "running",
        "version": settings.app_version,
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
    }
