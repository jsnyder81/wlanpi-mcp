import pytest
import respx
import httpx

from wlanpi_mcp.client.core_client import CoreClient


@pytest.fixture
def client(settings, mock_token):
    c = CoreClient.__new__(CoreClient)
    c._settings = settings
    c._token_manager = mock_token
    c._http = httpx.AsyncClient(base_url=settings.WLANPI_CORE_URL)
    return c


@respx.mock
@pytest.mark.asyncio
async def test_get_injects_auth_header(client):
    route = respx.get("http://localhost:31415/api/v1/system/device/info").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    await client.get("/api/v1/system/device/info")
    assert route.called
    assert "Authorization" in route.calls[0].request.headers
    assert route.calls[0].request.headers["Authorization"] == "Bearer fake.jwt.token"


@respx.mock
@pytest.mark.asyncio
async def test_raises_on_404(client):
    respx.get("http://localhost:31415/api/v1/not/found").mock(
        return_value=httpx.Response(404, json={"detail": "not found"})
    )
    with pytest.raises(httpx.HTTPStatusError):
        await client.get("/api/v1/not/found")


@respx.mock
@pytest.mark.asyncio
async def test_retries_on_401(client, settings, mock_token):
    call_count = 0

    def side_effect(request):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(401, json={"detail": "unauthorized"})
        return httpx.Response(200, json={"ok": True})

    respx.get("http://localhost:31415/api/v1/system/device/info").mock(
        side_effect=side_effect
    )
    # After the 401, token_manager.invalidate() is called and token is re-fetched.
    # The second call should succeed.
    result = await client.get("/api/v1/system/device/info")
    assert result == {"ok": True}
    assert call_count == 2
