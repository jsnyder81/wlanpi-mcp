from typing import Optional

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.tool()
    async def get_network_interfaces(interface: Optional[str] = None) -> dict:
        """
        Get network interface details including IP addresses, flags, MTU, and link state.

        Args:
            interface: Optional interface name (e.g. 'eth0'). If omitted, returns all interfaces.
        """
        if interface:
            return await client.get(f"/api/v1/network/interfaces/{interface}")
        return await client.get("/api/v1/network/interfaces")

    @mcp.tool()
    async def get_network_info() -> dict:
        """
        Get a full network snapshot: all interfaces, WLAN details, ethernet IP config, VLAN info,
        LLDP/CDP neighbours, and public IP address. Best starting point for network diagnostics.
        """
        return await client.get("/api/v1/network/info/")
