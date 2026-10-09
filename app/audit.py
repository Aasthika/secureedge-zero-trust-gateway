from sqlalchemy.orm import Session

from app.models import AuditLog


class AuditService:
    @staticmethod
    def log(
        db: Session,
        *,
        user_id: int | None,
        username: str | None,
        role: str | None,
        endpoint: str,
        method: str,
        decision: str,
        status_code: int,
        ip_address: str | None = None,
        latency_ms: float | None = None,
    ) -> AuditLog:

        audit_log = AuditLog(
            user_id=user_id,
            username=username,
            role=role,
            endpoint=endpoint,
            method=method,
            decision=decision,
            status_code=status_code,
            ip_address=ip_address,
            latency_ms=latency_ms,
        )

        db.add(audit_log)
        db.commit()
        db.refresh(audit_log)

        return audit_log
