from typing import Literal, Optional

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.tool()
    async def get_wlan_interfaces() -> dict:
        """Get all WLAN interfaces known to wpa_supplicant via D-Bus."""
        return await client.get("/api/v1/network/wlan/getInterfaces")

    @mcp.tool()
    async def scan_wlan(
        interface: str,
        type: Literal["active", "passive"] = "active",
    ) -> dict:
        """
        Scan for Wi-Fi networks on the given interface.

        Args:
            interface: WLAN interface name (e.g. 'wlan0')
            type: Scan type — 'active' (sends probe requests) or 'passive' (listen only)
        """
        return await client.get(
            "/api/v1/network/wlan/scan",
            params={"type": type, "interface": interface},
        )

    @mcp.tool()
    async def get_connected_network(interface: str) -> dict:
        """
        Get the currently associated Wi-Fi network on an interface.

        Args:
            interface: WLAN interface name (e.g. 'wlan0')
        """
        return await client.get(
            "/api/v1/network/wlan/getConnected",
            params={"interface": interface},
        )

    @mcp.tool()
    async def connect_wlan(
        interface: str,
        ssid: str,
        security: Literal["WPA2-PSK", "WPA3-PSK", "OPEN", "OWE"],
        psk: Optional[str] = None,
        remove_all_first: bool = True,
    ) -> dict:
        """
        Connect a WLAN interface to a Wi-Fi network.

        This reconfigures wpa_supplicant on the specified interface. The connection
        runs inside a network namespace (testns) and does not affect the root namespace.

        Args:
            interface: WLAN interface name (e.g. 'wlan0')
            ssid: Network SSID to connect to
            security: Security type — WPA2-PSK, WPA3-PSK, OPEN, or OWE
            psk: Pre-shared key (required for WPA2-PSK and WPA3-PSK)
            remove_all_first: Remove existing wpa_supplicant configs before connecting
        """
        if security in ("WPA2-PSK", "WPA3-PSK") and not psk:
            return {"error": f"psk is required for {security}"}

        net_security = {"ssid": ssid, "security": security}
        if psk:
            net_security["psk"] = psk

        body = {
            "interface": interface,
            "netConfig": {
                "id": f"mcp-{ssid}",
                "namespaces": [
                    {
                        "namespace": "testns",
                        "mode": "managed",
                        "iface_display_name": ssid,
                        "phy": "phy0",
                        "interface": interface,
                        "security": net_security,
                    }
                ],
            },
            "removeAllFirst": remove_all_first,
        }
        return await client.post("/api/v1/network/wlan/set", json=body)

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
