import hashlib
import uuid

import httpx
import pytest
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser, authorization_context
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from wlanpi_mcp.auth.token_context import current_token, get_token
from wlanpi_mcp.middleware.bearer_token import BearerTokenMiddleware


async def _echo_token(request):
    # Reports what the downstream app sees in the token contextvar and the
    # principal the middleware published for the connection.
    user = request.scope.get("user")
    return JSONResponse(
        {
            "token": get_token(),
            "client_id": getattr(user, "username", None),
        }
    )


def _make_app():
    app = Starlette(routes=[Route("/probe", _echo_token)])
    return BearerTokenMiddleware(app)


@pytest.fixture
def http():
    transport = httpx.ASGITransport(app=_make_app())
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


async def test_rejects_missing_authorization(http):
    response = await http.get("/probe")
    assert response.status_code == 401
    assert "Bearer" in response.json()["detail"]


async def test_rejects_non_bearer_authorization(http):
    response = await http.get("/probe", headers={"Authorization": "Basic dXNlcjpwdw=="})
    assert response.status_code == 401


async def test_rejects_empty_bearer(http):
    response = await http.get("/probe", headers={"Authorization": "Bearer   "})
    assert response.status_code == 401


async def test_passes_token_to_downstream_context(http):
    response = await http.get(
        "/probe", headers={"Authorization": "Bearer core.jwt.abc123"}
    )
    assert response.status_code == 200
    assert response.json()["token"] == "core.jwt.abc123"


async def test_context_reset_after_request(http):
    await http.get("/probe", headers={"Authorization": "Bearer core.jwt.abc123"})
    assert current_token.get() is None


async def test_publishes_token_fingerprint_principal(http):
    token = "core.jwt.abc123"
    response = await http.get("/probe", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    expected = hashlib.sha256(token.encode()).hexdigest()
    assert response.json()["client_id"] == expected


def _principal(token: str) -> AuthenticatedUser:
    # Mirror what BearerTokenMiddleware publishes for a given token.
    from wlanpi_mcp.middleware.bearer_token import _principal_for

    return _principal_for(token)


async def _post_message(transport, session_id, principal, body=b"{}"):
    """Drive SseServerTransport.handle_post_message and return the HTTP status."""
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/messages/",
        "headers": [(b"host", b"testserver"), (b"content-type", b"application/json")],
        "query_string": f"session_id={session_id.hex}".encode(),
        "user": principal,
    }
    await transport.handle_post_message(scope, receive, send)
    start = next(m for m in sent if m["type"] == "http.response.start")
    return start["status"]


async def test_sse_session_rejects_mismatched_token():
    """A message carrying a different token than opened the session is refused."""
    transport = SseServerTransport("/messages/")
    session_id = uuid.uuid4()
    # Simulate an established session owned by token A.
    received = []

    class _Writer:
        async def send(self, item):
            received.append(item)

    transport._read_stream_writers[session_id] = _Writer()
    transport._session_owners[session_id] = authorization_context(_principal("token-A"))

    # Token B cannot drive token A's session: same 404 as a nonexistent session.
    status_b = await _post_message(transport, session_id, _principal("token-B"))
    assert status_b == 404
    assert received == []

    # Token A (the opener) is accepted and its message is delivered.
    status_a = await _post_message(
        transport, session_id, _principal("token-A"), body=b'{"jsonrpc":"2.0","id":1,"method":"ping"}'
    )
    assert status_a == 202
    assert len(received) == 1
