from enum import Enum


class Permission(str, Enum):
    USERS_READ = "users:read"
    USERS_WRITE = "users:write"
    ANALYTICS_READ = "analytics:read"
    ANALYTICS_WRITE = "analytics:write"
    POLICIES_MANAGE = "policies:manage"
    DOCUMENTS_READ = "documents:read"
    DOCUMENTS_WRITE = "documents:write"


ROLE_PERMISSIONS = {
    "admin": {
        Permission.USERS_READ,
        Permission.USERS_WRITE,
        Permission.ANALYTICS_READ,
        Permission.ANALYTICS_WRITE,
        Permission.POLICIES_MANAGE,
        Permission.DOCUMENTS_READ,
        Permission.DOCUMENTS_WRITE,
    },
    "analyst": {
        Permission.ANALYTICS_READ,
    },
    "user": {
        Permission.DOCUMENTS_READ,
        Permission.DOCUMENTS_WRITE,
    },
}
