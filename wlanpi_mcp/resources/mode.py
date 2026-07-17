import json

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient

VALID_MODES = {"classic", "wconsole", "hotspot", "wiperf", "server", "bridge"}


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.resource("device://mode")
    async def device_mode() -> str:
        """Current WlanPi operating mode reported by wlanpi-core."""
        try:
            info = await client.get("/api/v1/system/device/info")
            mode = info.get("mode", "")
            return json.dumps({"mode": mode, "valid": mode in VALID_MODES}, indent=2)
        except Exception as exc:
            return json.dumps({"error": str(exc)})
