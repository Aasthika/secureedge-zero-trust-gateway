from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PolicyRequest:
    subject: dict[str, Any]
    action: str
    resource: str
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str


class PolicyEngine:
    """Evaluate access requests using explicit, default-deny policies."""

    ROLE_ACTIONS = {
        "admin": {
            ("read", "analytics"),
            ("write", "analytics"),
            ("read", "users"),
            ("write", "users"),
            ("manage", "policies"),
        },
        "analyst": {
            ("read", "analytics"),
        },
        "user": set(),
    }

    SENSITIVITY_LEVELS = {
        "public": 0,
        "internal": 1,
        "confidential": 2,
        "restricted": 3,
    }

    def evaluate(self, request: PolicyRequest) -> PolicyDecision:
        subject = request.subject
        context = request.context

        role = subject.get("role")
        subject_id = subject.get("id")

        if not isinstance(role, str) or role not in self.ROLE_ACTIONS:
            return PolicyDecision(False, "Unknown or missing subject role")

        if (
            not isinstance(request.action, str)
            or not request.action
            or not isinstance(request.resource, str)
            or not request.resource
        ):
            return PolicyDecision(False, "Action and resource are required")

        allowed_actions = self.ROLE_ACTIONS[role]

        if (request.action, request.resource) not in allowed_actions:
            return PolicyDecision(
                False,
                "Role is not permitted to perform this action",
            )

        if context.get("require_owner", False):
            owner_id = context.get("resource_owner_id")

            if subject_id is None or owner_id is None:
                return PolicyDecision(
                    False,
                    "Ownership attributes are required",
                )

            if str(subject_id) != str(owner_id):
                return PolicyDecision(
                    False,
                    "Resource ownership check failed",
                )

        sensitivity = context.get("resource_sensitivity")

        if sensitivity is not None:
            required_level = self.SENSITIVITY_LEVELS.get(sensitivity)
            clearance = subject.get("clearance")
            clearance_level = self.SENSITIVITY_LEVELS.get(clearance)

            if required_level is None or clearance_level is None:
                return PolicyDecision(
                    False,
                    "Unknown sensitivity or clearance level",
                )

            if clearance_level < required_level:
                return PolicyDecision(False, "Insufficient clearance")

        return PolicyDecision(True, "Policy explicitly permits the action")
