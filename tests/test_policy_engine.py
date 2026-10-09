from app.policy_engine import PolicyEngine, PolicyRequest


def test_analyst_can_read_analytics():

    engine = PolicyEngine()

    request = PolicyRequest(
        subject={
            "role": "analyst",
        },
        action="read",
        resource="analytics",
        context={},
    )

    decision = engine.evaluate(request)

    assert decision.allowed is True


def test_analyst_cannot_write_analytics():

    engine = PolicyEngine()

    request = PolicyRequest(
        subject={
            "role": "analyst",
        },
        action="write",
        resource="analytics",
        context={},
    )

    decision = engine.evaluate(request)

    assert decision.allowed is False


def test_user_cannot_read_analytics():

    engine = PolicyEngine()

    request = PolicyRequest(
        subject={
            "role": "user",
        },
        action="read",
        resource="analytics",
        context={},
    )

    decision = engine.evaluate(request)

    assert decision.allowed is False
