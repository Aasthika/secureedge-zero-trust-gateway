from dataclasses import dataclass


@dataclass
class PolicyRequest:
    subject: dict
    action: str
    resource: str
    context: dict


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str


class PolicyEngine:
    def evaluate(self, request: PolicyRequest) -> PolicyDecision:

        role = request.subject.get("role")

        if (
            role == "analyst"
            and request.action == "read"
            and request.resource == "analytics"
        ):
            return PolicyDecision(
                allowed=True,
                reason="Analyst is allowed to read analytics",
            )

        return PolicyDecision(
            allowed=False,
            reason="Policy denied the requested action",
        )
