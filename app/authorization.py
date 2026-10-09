from enum import Enum


class Permission(str, Enum):
    USERS_READ = "users:read"
    USERS_WRITE = "users:write"
    ANALYTICS_READ = "analytics:read"
    POLICIES_MANAGE = "policies:manage"


ROLE_PERMISSIONS = {
    "admin": {
        Permission.USERS_READ,
        Permission.USERS_WRITE,
        Permission.ANALYTICS_READ,
        Permission.POLICIES_MANAGE,
    },
    "user": {
        Permission.ANALYTICS_READ,
    },
}
