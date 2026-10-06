from fastapi import FastAPI

from app.config import settings


app = FastAPI(
    title=settings.app_name,
    description="Zero-Trust API Gateway & Policy Enforcement Platform",
    version="0.1.0",
)


@app.get("/")
async def root():
    return {
        "service": settings.app_name,
        "status": "running",
        "environment": settings.environment,
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
    }
