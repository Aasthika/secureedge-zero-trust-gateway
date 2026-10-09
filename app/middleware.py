import logging
import time

from fastapi import Request
from sqlalchemy.exc import SQLAlchemyError

from app.audit import AuditService
from app.database import SessionLocal
from app.metrics import (
    http_request_duration_seconds,
    http_requests_total,
)

logger = logging.getLogger(__name__)


async def audit_middleware(request: Request, call_next):
    start_time = time.perf_counter()
    response = None
    status_code = 500

    try:
        response = await call_next(request)
        status_code = response.status_code
        return response

    except Exception:
        logger.exception(
            "Unhandled request exception: %s %s",
            request.method,
            request.url.path,
        )
        raise

    finally:
        latency_seconds = time.perf_counter() - start_time
        latency_ms = latency_seconds * 1000

        try:
            http_requests_total.labels(
                method=request.method,
                status=str(status_code),
            ).inc()

            http_request_duration_seconds.labels(
                method=request.method,
                status=str(status_code),
            ).observe(latency_seconds)

        except Exception:
            logger.exception("Failed to record request metrics")

        db = None

        try:
            db = SessionLocal()
            user = getattr(request.state, "user", None)

            AuditService.log(
                db,
                user_id=user.id if user else None,
                username=user.username if user else None,
                role=user.role if user else None,
                endpoint=request.url.path,
                method=request.method,
                decision="ALLOW" if status_code < 400 else "DENY",
                status_code=status_code,
                ip_address=(request.client.host if request.client else None),
                latency_ms=latency_ms,
            )

        except SQLAlchemyError:
            if db is not None:
                db.rollback()

            logger.exception(
                "Audit persistence failed for %s %s",
                request.method,
                request.url.path,
            )

        except Exception:
            logger.exception(
                "Unexpected audit middleware failure for %s %s",
                request.method,
                request.url.path,
            )

        finally:
            if db is not None:
                try:
                    db.close()
                except SQLAlchemyError:
                    logger.exception("Failed to close audit database session")
