import redis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.authorization import Permission
from app.database import get_db
from app.dependencies import (
    enforce_rate_limit,
    get_current_user,
    login_rate_limiter,
    require_permission,
    require_policy,
    require_role,
)
from app.models import User
from app.schemas import (
    TokenResponse,
    UserCreate,
    UserLogin,
    UserResponse,
)
from app.security import (
    create_access_token,
    hash_password,
    verify_password,
)


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
):
    existing_user = db.scalar(
        select(User).where(
            or_(
                User.username == user_data.username,
                User.email == user_data.email,
            )
        )
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered",
        )

    password_hash = hash_password(user_data.password)

    user = User(
        username=user_data.username,
        email=user_data.email,
        role="user",
        password_hash=password_hash,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


@router.post(
    "/login",
    response_model=TokenResponse,
)
def login_user(
    user_data: UserLogin,
    request: Request,
    db: Session = Depends(get_db),
):
    # Apply login rate limiting by client IP.
    client_ip = request.client.host if request.client else "unknown"
    key = f"rate_limit:login:{client_ip}:{user_data.username.strip().lower()}"

    try:
        allowed, count, ttl = login_rate_limiter.check(key)
    except redis.exceptions.RedisError as exc:
        # Fail closed if the rate-limiting service is unavailable.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Login service is temporarily unavailable",
            headers={"Retry-After": "5"},
        ) from exc

    if not allowed:
        retry_after = max(ttl, 1)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": str(retry_after)},
        )

    # Continue with normal authentication.
    user = db.scalar(select(User).where(User.username == user_data.username))

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not verify_password(
        user_data.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    access_token = create_access_token(
        subject=str(user.id),
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


@router.get(
    "/me",
    response_model=UserResponse,
)
def get_me(
    current_user: User = Depends(get_current_user),
):
    return current_user


@router.get(
    "/admin-test",
    response_model=UserResponse,
)
def admin_test(
    current_user: User = Depends(require_role("admin")),
):
    return current_user


@router.get(
    "/write-test",
    response_model=UserResponse,
)
def write_test(
    current_user: User = Depends(require_permission(Permission.USERS_WRITE)),
):
    return current_user


@router.get(
    "/rate-limit-test",
    response_model=UserResponse,
)
def rate_limit_test(
    current_user: User = Depends(enforce_rate_limit),
):
    return current_user


@router.get("/analytics-test")
def analytics_test(
    current_user: User = Depends(
        require_policy(
            action="read",
            resource="analytics",
        )
    ),
):
    return {
        "message": "Analytics access granted",
        "username": current_user.username,
        "role": current_user.role,
    }
