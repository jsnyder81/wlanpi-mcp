import json

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.config import ALLOWED_SERVICES


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.resource("services://status/{name}")
    async def service_status(name: str) -> str:
        """Live status of a WlanPi systemd service. Name must be in the allowed services list."""
        if name not in ALLOWED_SERVICES:
            return json.dumps({"error": f"'{name}' is not an allowed service"})
        data = await client.get("/api/v1/system/service/status", params={"name": name})
        return json.dumps(data, indent=2)
