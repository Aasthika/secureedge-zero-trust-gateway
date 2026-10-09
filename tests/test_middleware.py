from unittest.mock import MagicMock, patch

import pytest
from starlette.responses import Response

from app.middleware import audit_middleware


@pytest.mark.anyio
async def test_audit_middleware_records_successful_request():
    request = MagicMock()
    request.method = "GET"
    request.url.path = "/health"
    request.client.host = "127.0.0.1"
    request.state.user = None

    response = Response(status_code=200)

    with (
        patch("app.middleware.SessionLocal") as session_factory,
        patch("app.middleware.AuditService.log") as audit_log,
        patch("app.middleware.http_requests_total") as requests_total,
        patch("app.middleware.http_request_duration_seconds") as duration_metric,
    ):
        session = session_factory.return_value

        async def call_next(_request):
            return response

        result = await audit_middleware(request, call_next)

    assert result.status_code == 200
    requests_total.labels.assert_called_once_with(
        method="GET",
        status="200",
    )
    duration_metric.labels.assert_called_once_with(
        method="GET",
        status="200",
    )
    audit_log.assert_called_once()
    assert audit_log.call_args.kwargs["decision"] == "ALLOW"
    assert audit_log.call_args.kwargs["status_code"] == 200
    session.close.assert_called_once()


@pytest.mark.anyio
async def test_audit_middleware_records_server_error_before_reraising():
    request = MagicMock()
    request.method = "GET"
    request.url.path = "/test-error"
    request.client.host = "127.0.0.1"
    request.state.user = None

    with (
        patch("app.middleware.SessionLocal"),
        patch("app.middleware.AuditService.log") as audit_log,
        patch("app.middleware.http_requests_total") as requests_total,
        patch("app.middleware.http_request_duration_seconds") as duration_metric,
    ):

        async def call_next(_request):
            raise RuntimeError("simulated failure")

        with pytest.raises(
            RuntimeError,
            match="simulated failure",
        ):
            await audit_middleware(request, call_next)

    requests_total.labels.assert_called_once_with(
        method="GET",
        status="500",
    )
    duration_metric.labels.assert_called_once_with(
        method="GET",
        status="500",
    )
    audit_log.assert_called_once()
    assert audit_log.call_args.kwargs["decision"] == "DENY"
    assert audit_log.call_args.kwargs["status_code"] == 500
