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

    @mcp.resource("device://info")
    async def device_info() -> str:
        """WlanPi device identity: model, hostname, software version, and operating mode."""
        import json
        data = await _cached_get(client, "/api/v1/system/device/info", ttl=60.0)
        return json.dumps(data, indent=2)

    @mcp.resource("device://stats")
    async def device_stats() -> str:
        """WlanPi live system metrics: CPU, RAM, disk, temperature, uptime, IP."""
        import json
        data = await _cached_get(client, "/api/v1/system/device/stats", ttl=10.0)
        return json.dumps(data, indent=2)
