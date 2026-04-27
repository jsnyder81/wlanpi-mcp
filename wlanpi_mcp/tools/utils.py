from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.tool()
    async def get_reachability() -> dict:
        """
        Test WlanPi network reachability: pings the default gateway, checks DNS resolution,
        and verifies internet access. Use this to diagnose connectivity problems.
        """
        return await client.get("/api/v1/utils/reachability")

    @mcp.tool()
    async def get_usb_interfaces() -> dict:
        """List USB network adapters currently plugged into the WlanPi."""
        return await client.get("/api/v1/utils/usb")

    @mcp.tool()
    async def get_ufw_status() -> dict:
        """Get the current UFW firewall status and active rules on the WlanPi."""
        return await client.get("/api/v1/utils/ufw")
