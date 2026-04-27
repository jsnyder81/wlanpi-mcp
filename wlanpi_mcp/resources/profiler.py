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

    @mcp.resource("profiler://status")
    async def profiler_status() -> str:
        """WlanPi profiler running state, SSID, channel, and interface."""
        data = await _cached_get(client, "/api/v1/profiler/status", ttl=10.0)
        return json.dumps(data, indent=2)
