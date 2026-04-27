import json

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient

MODE_FILE = "/etc/wlanpi-state"
VALID_MODES = {"classic", "wconsole", "hotspot", "wiperf", "server", "bridge"}


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.resource("device://mode")
    async def device_mode() -> str:
        """Current WlanPi operating mode read directly from /etc/wlanpi-state."""
        try:
            with open(MODE_FILE) as f:
                mode = f.readline().strip()
            return json.dumps({"mode": mode, "valid": mode in VALID_MODES}, indent=2)
        except FileNotFoundError:
            return json.dumps({"mode": "classic", "valid": True, "note": f"{MODE_FILE} not found"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})
