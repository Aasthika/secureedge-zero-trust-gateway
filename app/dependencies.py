import jwt

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authorization import Permission, ROLE_PERMISSIONS
from app.config import settings
from app.database import get_db
from app.metrics import rate_limited_requests_total
from app.models import User
from app.policy_engine import PolicyEngine, PolicyRequest
from app.rate_limiter import RateLimiter
from app.security import ALGORITHM
import redis


security = HTTPBearer()


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[ALGORITHM],
            options={
                "require": ["sub", "iat", "exp"],
            },
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user_id = payload.get("sub")

    # This application issues JWT subjects as string user IDs.
    if not isinstance(user_id, str) or not user_id.isdecimal():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.scalar(select(User).where(User.id == int(user_id)))

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    request.state.user = user
    return user


def require_role(required_role: str):
    def role_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        return current_user

    return role_checker


def require_permission(required_permission: Permission):
    def permission_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        user_permissions = ROLE_PERMISSIONS.get(
            current_user.role,
            set(),
        )

        if required_permission not in user_permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        return current_user

    return permission_checker


rate_limiter = RateLimiter(
    limit=5,
    window_seconds=60,
)


def enforce_rate_limit(
    current_user: User = Depends(get_current_user),
) -> User:
    key = f"rate_limit:user:{current_user.id}"

    try:
        allowed, count, ttl = rate_limiter.check(key)
    except redis.exceptions.RedisError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiting service is temporarily unavailable",
            headers={"Retry-After": "5"},
        ) from exc

    if not allowed:
        rate_limited_requests_total.inc()

        retry_after = max(ttl, 0)

        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": "Rate limit exceeded",
                "limit": rate_limiter.limit,
                "retry_after_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )

    return current_user


# ABAC Policy Engine
policy_engine = PolicyEngine()


def require_policy(
    action: str,
    resource: str,
):
    def policy_checker(
        current_user: User = Depends(get_current_user),
    ) -> User:
        # Identity attributes come from the authenticated database user,
        # not from request-body or query-string values.
        subject = {
            "id": current_user.id,
            "username": current_user.username,
            "role": current_user.role,
        }

        # Resource attributes must be supplied by trusted server-side
        # code when a particular resource requires ownership or clearance.
        policy_request = PolicyRequest(
            subject=subject,
            action=action,
            resource=resource,
            context={},
        )

        decision = policy_engine.evaluate(policy_request)

        if not decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=decision.reason,
            )

        return current_user

    return policy_checker
