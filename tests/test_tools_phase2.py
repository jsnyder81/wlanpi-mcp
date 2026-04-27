import pytest
import respx
import httpx

from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.config import Settings


@pytest.fixture
def client(settings, mock_token):
    c = CoreClient.__new__(CoreClient)
    c._settings = settings
    c._token_manager = mock_token
    c._http = httpx.AsyncClient(base_url=settings.WLANPI_CORE_URL)
    return c


# ── WLAN ─────────────────────────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_scan_wlan(client):
    respx.get("http://localhost:31415/api/v1/network/wlan/scan").mock(
        return_value=httpx.Response(200, json={"nets": [{"ssid": "TestNet", "bssid": "aa:bb:cc:dd:ee:ff", "signal": -65, "freq": 5180, "key_mgmt": "wpa-psk", "minrate": 6000000}]})
    )
    result = await client.get("/api/v1/network/wlan/scan", params={"type": "active", "interface": "wlan0"})
    assert "nets" in result


@respx.mock
@pytest.mark.asyncio
async def test_connect_wlan_requires_psk_for_wpa2():
    from mcp.server.fastmcp import FastMCP
    from wlanpi_mcp.tools.wlan import register
    from unittest.mock import AsyncMock, MagicMock

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value={"status": "connected"})

    mcp = FastMCP("test")
    register(mcp, mock_client)

    # Access the registered tool by name
    tool_fn = mcp._tool_manager._tools["connect_wlan"].fn
    result = await tool_fn(interface="wlan0", ssid="MyNet", security="WPA2-PSK", psk=None)
    assert "error" in result
    assert "psk is required" in result["error"]


@respx.mock
@pytest.mark.asyncio
async def test_connect_wlan_builds_correct_body():
    from unittest.mock import AsyncMock, MagicMock
    from wlanpi_mcp.tools.wlan import register
    from mcp.server.fastmcp import FastMCP

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value={"status": "connected"})

    mcp = FastMCP("test")
    register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["connect_wlan"].fn
    await tool_fn(interface="wlan0", ssid="Corp", security="WPA2-PSK", psk="secret123")

    mock_client.post.assert_called_once()
    body = mock_client.post.call_args.kwargs["json"]
    assert body["interface"] == "wlan0"
    assert body["netConfig"]["id"] == "mcp-Corp"
    ns = body["netConfig"]["namespaces"][0]
    assert ns["security"]["ssid"] == "Corp"
    assert ns["security"]["psk"] == "secret123"


# ── VLAN ─────────────────────────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_get_vlans(client):
    respx.get("http://localhost:31415/api/v1/network/ethernet/all/vlan").mock(
        return_value=httpx.Response(200, json={"eth0.10": []})
    )
    result = await client.get("/api/v1/network/ethernet/all/vlan")
    assert "eth0.10" in result


@respx.mock
@pytest.mark.asyncio
async def test_create_vlan(client):
    respx.post("http://localhost:31415/api/v1/network/ethernet/eth0/vlan/10").mock(
        return_value=httpx.Response(200, json={"result": {}})
    )
    result = await client.post(
        "/api/v1/network/ethernet/eth0/vlan/10",
        json=[{"family": 4, "local": "192.168.10.1", "prefixlen": 24}],
    )
    assert "result" in result


@respx.mock
@pytest.mark.asyncio
async def test_delete_vlan(client):
    respx.delete("http://localhost:31415/api/v1/network/ethernet/eth0/vlan/10").mock(
        return_value=httpx.Response(200, json={"result": {}})
    )
    result = await client.delete("/api/v1/network/ethernet/eth0/vlan/10")
    assert "result" in result


# ── Profiler ──────────────────────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_get_profiler_status(client):
    respx.get("http://localhost:31415/api/v1/profiler/status").mock(
        return_value=httpx.Response(200, json={"running": False, "ssid": None})
    )
    result = await client.get("/api/v1/profiler/status")
    assert "running" in result


@respx.mock
@pytest.mark.asyncio
async def test_start_profiler_builds_minimal_body():
    from unittest.mock import AsyncMock, MagicMock
    from wlanpi_mcp.tools.profiler import register
    from mcp.server.fastmcp import FastMCP

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value={"success": True})

    mcp = FastMCP("test")
    register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["start_profiler"].fn
    await tool_fn(interface="wlan0", channel=6)

    body = mock_client.post.call_args.kwargs["json"]
    assert body["interface"] == "wlan0"
    assert body["channel"] == 6
    assert "frequency" not in body  # omitted None fields


# ── Bluetooth ─────────────────────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_get_bluetooth_status(client):
    respx.get("http://localhost:31415/api/v1/bluetooth/status").mock(
        return_value=httpx.Response(200, json={"name": "WlanPi", "power": True, "paired_devices": []})
    )
    result = await client.get("/api/v1/bluetooth/status")
    assert result["name"] == "WlanPi"


@respx.mock
@pytest.mark.asyncio
async def test_set_bluetooth_power_on(client):
    respx.post("http://localhost:31415/api/v1/bluetooth/power/on").mock(
        return_value=httpx.Response(200, json={"status": "success", "action": "on"})
    )
    result = await client.post("/api/v1/bluetooth/power/on")
    assert result["action"] == "on"


# ── Network Config ────────────────────────────────────────────────────────────

@respx.mock
@pytest.mark.asyncio
async def test_list_network_configs(client):
    respx.get("http://localhost:31415/api/v1/network/config/").mock(
        return_value=httpx.Response(200, json={"office": True, "home": False})
    )
    result = await client.get("/api/v1/network/config/")
    assert "office" in result


@respx.mock
@pytest.mark.asyncio
async def test_activate_network_config(client):
    respx.post("http://localhost:31415/api/v1/network/config/activate/office").mock(
        return_value=httpx.Response(200, json={"id": "office", "message": "Configuration activated successfully"})
    )
    result = await client.post("/api/v1/network/config/activate/office")
    assert result["id"] == "office"
