from typing import Literal, Optional

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.tool()
    async def scan_wlan(
        interface: Optional[str] = None,
        namespace: Optional[str] = None,
        include_hidden: bool = True,
        detail: Literal["short", "full"] = "short",
    ) -> dict:
        """
        Scan for Wi-Fi networks. Namespace-aware, with automatic monitor adapter
        selection. If multiple monitor adapters exist and no interface is given,
        returns 'needsSelection' with candidates instead of scanning — call again
        with one of the candidate interfaces.

        To connect to a network found by this scan, create and activate a network
        configuration (create_network_config / activate_network_config).

        Args:
            interface: WLAN interface to scan with (e.g. 'wlan0'); auto-selected if omitted
            namespace: Optional network namespace the interface lives in
            include_hidden: Include hidden SSIDs in results
            detail: 'short' for list-friendly fields plus RF extensions, 'full' for everything
        """
        params: dict = {"hidden": include_hidden, "detail": detail}
        if interface:
            params["iface"] = interface
        if namespace:
            params["namespace"] = namespace
        return await client.get("/api/v1/utils/wlan/scan", params=params)

    @mcp.tool()
    async def revert_wlan(
        interface: str,
        namespace: str = "testns",
        delete_namespace: bool = True,
    ) -> dict:
        """
        Revert a WLAN interface from its namespace back to the root namespace.

        Args:
            interface: WLAN interface name (e.g. 'wlan0')
            namespace: Network namespace to revert from (default: 'testns')
            delete_namespace: Delete the namespace after reverting
        """
        body = {
            "iface": interface,
            "namespace": namespace,
            "delete_namespace": delete_namespace,
        }
        return await client.post("/api/v1/network/wlan/revert", json=body)
