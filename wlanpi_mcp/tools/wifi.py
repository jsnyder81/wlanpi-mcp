from typing import Optional

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.tool()
    async def get_wifi_capabilities() -> dict:
        """
        Get Wi-Fi adapter capabilities: 'iw phy' capability dumps for each PHY,
        including supported bands, channels, HT/VHT/HE features, and interface modes.
        """
        return await client.get("/api/v1/wifi/capabilities")

    @mcp.tool()
    async def get_wifi_regulatory() -> dict:
        """Get Wi-Fi regulatory domain information reported by the kernel."""
        return await client.get("/api/v1/wifi/regulatory")

    @mcp.tool()
    async def get_hotspot_stations(iface: Optional[str] = None) -> dict:
        """
        List stations connected to the hotspot AP interface.
        Returns an error if the device is not in hotspot mode.

        Args:
            iface: Optional AP interface name; auto-detected if omitted.
        """
        params = {"iface": iface} if iface else None
        return await client.get("/api/v1/wifi/hotspot/stations", params=params)

    @mcp.tool()
    async def get_hotspot_link_stats(iface: Optional[str] = None) -> dict:
        """
        Get per-station link statistics (signal, rates, retries) for hotspot AP clients.
        Returns an error if the device is not in hotspot mode.

        Args:
            iface: Optional AP interface name; auto-detected if omitted.
        """
        params = {"iface": iface} if iface else None
        return await client.get("/api/v1/wifi/hotspot/link", params=params)
