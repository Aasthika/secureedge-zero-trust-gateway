from fastapi import FastAPI, Request
from prometheus_client import make_asgi_app

from app.config import settings
from app.middleware import audit_middleware
from app.routes.auth import router as auth_router
from app.routes.documents import router as documents_router
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.database import engine
from app.redis_client import redis_client
import redis

app = FastAPI(
    title=settings.app_name,
    description="Zero-Trust API Gateway & Policy Enforcement Platform",
    version=settings.app_version,
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url="/redoc" if settings.environment != "production" else None,
    openapi_url=("/openapi.json" if settings.environment != "production" else None),
)


@app.middleware("http")
async def security_headers_middleware(
    request: Request,
    call_next,
):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    # Enable HSTS only when production traffic is served over HTTPS.
    if settings.environment == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"

    return response


# Audit logging middleware
app.middleware("http")(audit_middleware)


# Authentication and protected API routes
app.include_router(auth_router)
app.include_router(documents_router)

# Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


@app.get("/", include_in_schema=True)
async def root():
    return {
        "service": settings.app_name,
        "status": "running",
        "environment": settings.environment,
    }


@app.get("/health/live")
async def liveness_check():
    return {"status": "alive"}


@app.get("/health/ready")
async def readiness_check():
    checks = {
        "database": "unavailable",
        "redis": "unavailable",
    }

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        checks["database"] = "available"
    except SQLAlchemyError:
        pass

    try:
        if redis_client.ping():
            checks["redis"] = "available"
    except redis.exceptions.RedisError:
        pass

    ready = all(value == "available" for value in checks.values())

    if not ready:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=503,
            detail={
                "status": "not_ready",
                "checks": checks,
            },
        )

    return {
        "status": "ready",
        "checks": checks,
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}
