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

    @mcp.tool()
    async def get_public_ipv6() -> dict:
        """Get the WlanPi's public IPv6 address and related details."""
        return await client.get("/api/v1/network/info/publicip6")

    @mcp.tool()
    async def get_ethernet_interface(interface: str) -> dict:
        """
        Get ethernet interface details for a specific interface.

        Args:
            interface: Ethernet interface name (e.g. 'eth0'), or 'all' for every interface
        """
        return await client.get(f"/api/v1/network/ethernet/{interface}")

    @mcp.tool()
    async def get_routing_table(namespace: Optional[str] = None) -> dict:
        """
        Get the structured IP routing table.

        Args:
            namespace: Optional network namespace to query (default: root namespace)
        """
        params = {"namespace": namespace} if namespace else None
        return await client.get("/api/v1/network/routing", params=params)

    @mcp.tool()
    async def get_tcp_connections(namespace: Optional[str] = None) -> dict:
        """
        Get active TCP sockets/connections on the WlanPi.

        Args:
            namespace: Optional network namespace to query (default: root namespace)
        """
        params = {"namespace": namespace} if namespace else None
        return await client.get("/api/v1/network/connections/tcp", params=params)

    @mcp.tool()
    async def get_udp_connections(namespace: Optional[str] = None) -> dict:
        """
        Get active UDP sockets on the WlanPi.

        Args:
            namespace: Optional network namespace to query (default: root namespace)
        """
        params = {"namespace": namespace} if namespace else None
        return await client.get("/api/v1/network/connections/udp", params=params)

    @mcp.tool()
    async def get_dhcp_leases() -> dict:
        """Get DHCP leases held by the WlanPi (parsed from dhclient lease files)."""
        return await client.get("/api/v1/network/dhcp/leases")

    @mcp.tool()
    async def get_interface_link_stats(interface: str) -> dict:
        """
        Get per-interface link statistics (via ethtool): speed, duplex, errors, drops.

        Args:
            interface: Interface name (e.g. 'eth0')
        """
        return await client.get(f"/api/v1/network/interfaces/{interface}/link-stats")

    @mcp.tool()
    async def renew_dhcp_lease(interface: str) -> dict:
        """
        Renew the DHCP lease for an interface in its current namespace.
        The interface IP address may change as a result.

        Args:
            interface: Interface name (e.g. 'eth0')
        """
        return await client.post(f"/api/v1/network/interfaces/{interface}/renew")

    @mcp.tool()
    async def get_wlan_usb_drivers() -> dict:
        """
        List USB-attached WLAN adapters and their bound drivers. If 'adapters' is
        empty but interfaces_scanned > 0, the radios are PCI/on-board — use
        get_wlan_pci_drivers instead.
        """
        return await client.get("/api/v1/network/wlan/usb-drivers")

    @mcp.tool()
    async def get_wlan_pci_drivers() -> dict:
        """
        List PCI/platform wireless devices (from lspci) and bound WLAN interface
        drivers for built-in Wi-Fi radios.
        """
        return await client.get("/api/v1/network/wlan/pci-drivers")
