import pytest

from app.authorization import Permission, ROLE_PERMISSIONS
from app.policy_engine import PolicyEngine, PolicyRequest


@pytest.fixture
def engine():
    return PolicyEngine()


def evaluate(
    engine,
    subject,
    action="read",
    resource="analytics",
    context=None,
):
    return engine.evaluate(
        PolicyRequest(
            subject=subject,
            action=action,
            resource=resource,
            context=context or {},
        )
    )


def test_analyst_can_read_analytics(engine):
    decision = evaluate(
        engine,
        {"id": 1, "role": "analyst"},
    )
    assert decision.allowed is True


def test_unknown_role_is_denied(engine):
    decision = evaluate(
        engine,
        {"id": 1, "role": "unknown"},
    )
    assert decision.allowed is False


def test_missing_role_is_denied(engine):
    decision = evaluate(engine, {"id": 1})
    assert decision.allowed is False


def test_unsupported_action_is_denied(engine):
    decision = evaluate(
        engine,
        {"id": 1, "role": "analyst"},
        action="delete",
    )
    assert decision.allowed is False


def test_user_can_write_documents(engine):
    decision = evaluate(
        engine,
        {"id": 1, "role": "user"},
        action="write",
        resource="documents",
    )
    assert decision.allowed is True


def test_user_cannot_delete_documents(engine):
    decision = evaluate(
        engine,
        {"id": 1, "role": "user"},
        action="delete",
        resource="documents",
    )
    assert decision.allowed is False


def test_admin_can_delete_documents(engine):
    decision = evaluate(
        engine,
        {"id": 1, "role": "admin"},
        action="delete",
        resource="documents",
    )
    assert decision.allowed is True


def test_ownership_allows_resource_owner(engine):
    decision = evaluate(
        engine,
        {"id": 10, "role": "analyst"},
        context={
            "require_owner": True,
            "resource_owner_id": 10,
        },
    )
    assert decision.allowed is True


def test_ownership_denies_different_user(engine):
    decision = evaluate(
        engine,
        {"id": 10, "role": "analyst"},
        context={
            "require_owner": True,
            "resource_owner_id": 20,
        },
    )
    assert decision.allowed is False


def test_ownership_denies_missing_owner(engine):
    decision = evaluate(
        engine,
        {"id": 10, "role": "analyst"},
        context={"require_owner": True},
    )
    assert decision.allowed is False


def test_sensitivity_allows_sufficient_clearance(engine):
    decision = evaluate(
        engine,
        {
            "id": 10,
            "role": "analyst",
            "clearance": "confidential",
        },
        context={"resource_sensitivity": "internal"},
    )
    assert decision.allowed is True


def test_sensitivity_denies_insufficient_clearance(engine):
    decision = evaluate(
        engine,
        {
            "id": 10,
            "role": "analyst",
            "clearance": "internal",
        },
        context={"resource_sensitivity": "restricted"},
    )
    assert decision.allowed is False


@pytest.mark.parametrize("clearance", [None, "unknown"])
def test_sensitivity_denies_missing_or_unknown_clearance(
    engine,
    clearance,
):
    decision = evaluate(
        engine,
        {
            "id": 10,
            "role": "analyst",
            "clearance": clearance,
        },
        context={"resource_sensitivity": "confidential"},
    )
    assert decision.allowed is False


def test_sensitivity_denies_unknown_classification(engine):
    decision = evaluate(
        engine,
        {
            "id": 10,
            "role": "analyst",
            "clearance": "restricted",
        },
        context={"resource_sensitivity": "top-secret"},
    )
    assert decision.allowed is False


def test_role_permissions_match_policy_engine():
    permission_to_action = {
        Permission.USERS_READ: ("read", "users"),
        Permission.USERS_WRITE: ("write", "users"),
        Permission.ANALYTICS_READ: ("read", "analytics"),
        Permission.ANALYTICS_WRITE: ("write", "analytics"),
        Permission.POLICIES_MANAGE: ("manage", "policies"),
        Permission.DOCUMENTS_READ: ("read", "documents"),
        Permission.DOCUMENTS_WRITE: ("write", "documents"),
        Permission.DOCUMENTS_DELETE: ("delete", "documents"),
    }

    for role, permissions in ROLE_PERMISSIONS.items():
        expected_actions = {
            permission_to_action[permission] for permission in permissions
        }

        assert PolicyEngine.ROLE_ACTIONS[role] == expected_actions
