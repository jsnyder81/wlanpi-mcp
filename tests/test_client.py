import httpx
import pytest
import respx

from wlanpi_mcp.client.core_client import CoreClient


@respx.mock
async def test_get_passes_client_token_through(client, bearer_token):
    route = respx.get("http://localhost:31415/api/v1/system/device/info").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    await client.get("/api/v1/system/device/info")
    assert route.called
    assert route.calls[0].request.headers["Authorization"] == f"Bearer {bearer_token}"


@respx.mock
async def test_tags_requests_for_nginx_jwt_routing(client):
    route = respx.get("http://localhost:31415/api/v1/system/device/info").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    await client.get("/api/v1/system/device/info")
    assert route.calls[0].request.headers["X-Wlanpi-Client"] == "mcp"


@respx.mock
async def test_raises_on_404(client):
    respx.get("http://localhost:31415/api/v1/not/found").mock(
        return_value=httpx.Response(404, json={"detail": "not found"})
    )
    with pytest.raises(httpx.HTTPStatusError):
        await client.get("/api/v1/not/found")


@respx.mock
async def test_401_propagates(client):
    # The client doesn't own the token, so an invalid/expired token is the
    # MCP client's problem — wlanpi-core's 401 must surface, not be retried.
    route = respx.get("http://localhost:31415/api/v1/system/device/info").mock(
        return_value=httpx.Response(401, json={"detail": "unauthorized"})
    )
    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await client.get("/api/v1/system/device/info")
    assert exc_info.value.response.status_code == 401
    assert route.call_count == 1


async def test_missing_token_raises(settings):
    client = CoreClient(settings)
    with pytest.raises(RuntimeError, match="No wlanpi-core token"):
        await client.get("/api/v1/system/device/info")


@respx.mock
async def test_stdio_fallback_uses_configured_token(settings):
    settings.WLANPI_CORE_TOKEN = "stdio.jwt.token"
    client = CoreClient(settings)
    route = respx.get("http://localhost:31415/api/v1/system/device/info").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    await client.get("/api/v1/system/device/info")
    assert route.calls[0].request.headers["Authorization"] == "Bearer stdio.jwt.token"
