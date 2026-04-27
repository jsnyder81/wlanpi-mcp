from typing import Optional

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.tool()
    async def get_vlans(
        interface: Optional[str] = None,
        vlan_id: Optional[int] = None,
    ) -> dict:
        """
        Get VLAN interfaces on the WlanPi.

        Args:
            interface: Ethernet interface to filter by (e.g. 'eth0'). If omitted, returns all interfaces.
            vlan_id: VLAN ID to filter by. If omitted, returns all VLANs.
        """
        iface = interface or "all"
        if vlan_id is not None:
            path = f"/api/v1/network/ethernet/{iface}/vlan/{vlan_id}"
        else:
            path = f"/api/v1/network/ethernet/{iface}/vlan"
        return await client.get(path)

    @mcp.tool()
    async def create_vlan(
        interface: str,
        vlan_id: int,
        addresses: Optional[list[dict]] = None,
    ) -> dict:
        """
        Create (or replace) a VLAN on an ethernet interface.

        Args:
            interface: Ethernet interface (e.g. 'eth0'). Cannot be 'all'.
            vlan_id: VLAN ID (1–4094)
            addresses: Optional list of IP addresses to assign, each a dict with
                       'family' (4 or 6), 'local' (IP string), and 'prefixlen' (int).
                       Example: [{"family": 4, "local": "192.168.10.1", "prefixlen": 24}]
        """
        body = addresses or []
        return await client.post(
            f"/api/v1/network/ethernet/{interface}/vlan/{vlan_id}",
            json=body,
        )

    @mcp.tool()
    async def delete_vlan(
        interface: str,
        vlan_id: int,
        allow_missing: bool = False,
    ) -> dict:
        """
        Delete a VLAN from an ethernet interface.

        Args:
            interface: Ethernet interface (e.g. 'eth0'). Cannot be 'all'.
            vlan_id: VLAN ID to delete
            allow_missing: If True, don't error if the VLAN doesn't exist
        """
        return await client.delete(
            f"/api/v1/network/ethernet/{interface}/vlan/{vlan_id}",
            params={"allow_missing": allow_missing},
        )
