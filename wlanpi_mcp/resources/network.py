import json
import time
from typing import Any

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient

_cache: dict[str, tuple[Any, float]] = {}


async def _cached_get(client: CoreClient, path: str, ttl: float) -> Any:
    now = time.monotonic()
    if path in _cache:
        data, ts = _cache[path]
        if now - ts < ttl:
            return data
    data = await client.get(path)
    _cache[path] = (data, now)
    return data


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.resource("network://interfaces")
    async def network_interfaces() -> str:
        """All WlanPi network interfaces with addresses, flags, MTU, and link state."""
        data = await _cached_get(client, "/api/v1/network/interfaces", ttl=30.0)
        return json.dumps(data, indent=2)

    @mcp.resource("network://info")
    async def network_info() -> str:
        """Full WlanPi network snapshot: interfaces, WLAN details, LLDP/CDP neighbours, public IP."""
        data = await _cached_get(client, "/api/v1/network/info/", ttl=60.0)
        return json.dumps(data, indent=2)
