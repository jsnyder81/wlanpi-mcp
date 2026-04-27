from typing import Optional

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.tool()
    async def get_network_config_status() -> dict:
        """
        Get the status of all saved network configurations, showing which is active.
        """
        return await client.get("/api/v1/network/config/status")

    @mcp.tool()
    async def list_network_configs() -> dict:
        """
        List all saved network configuration profiles and whether each is active.
        Returns a dict mapping config ID to active state (True/False).
        """
        return await client.get("/api/v1/network/config/")

    @mcp.tool()
    async def get_network_config(id: str) -> dict:
        """
        Get the full details of a saved network configuration by ID.

        Args:
            id: Configuration profile ID (use list_network_configs to see available IDs)
        """
        return await client.get(f"/api/v1/network/config/{id}")

    @mcp.tool()
    async def create_network_config(config: dict) -> dict:
        """
        Create a new saved network configuration profile.

        The config dict must include:
          - id (str): Unique profile name (cannot be 'root' or 'default')
          - namespaces (list, optional): Namespace-based interface configs
          - roots (list, optional): Root namespace interface configs

        Each interface config in namespaces/roots needs:
          - mode: 'managed' or 'monitor'
          - iface_display_name: Human-readable name
          - phy: PHY device (e.g. 'phy0')
          - interface: Interface name (e.g. 'wlan0')
          - namespace (namespaces only): Namespace name (e.g. 'testns')
          - security (optional): {ssid, security, psk} for WPA2-PSK/WPA3-PSK networks

        Args:
            config: Network configuration dict matching the NetConfig schema
        """
        return await client.post("/api/v1/network/config/", json=config)

    @mcp.tool()
    async def update_network_config(id: str, config_update: dict) -> dict:
        """
        Update an existing network configuration profile.

        The config_update dict may include:
          - namespaces (list, optional): Updated namespace interface configs
          - roots (list, optional): Updated root namespace interface configs

        Args:
            id: Configuration profile ID to update
            config_update: Partial config update (namespaces and/or roots)
        """
        return await client.patch(f"/api/v1/network/config/{id}", json=config_update)

    @mcp.tool()
    async def activate_network_config(
        id: str, override_active: bool = False
    ) -> dict:
        """
        Activate a saved network configuration profile.

        Args:
            id: Configuration profile ID to activate
            override_active: If True, force activation even if another profile is active
        """
        return await client.post(
            f"/api/v1/network/config/activate/{id}",
            params={"override_active": override_active},
        )

    @mcp.tool()
    async def deactivate_network_config(
        id: str, override_active: bool = False
    ) -> dict:
        """
        Deactivate a currently active network configuration profile.

        Args:
            id: Configuration profile ID to deactivate
            override_active: If True, force deactivation even if flagged as active
        """
        return await client.post(
            f"/api/v1/network/config/deactivate/{id}",
            params={"override_active": override_active},
        )

    @mcp.tool()
    async def delete_network_config(id: str, force: bool = False) -> dict:
        """
        Delete a saved network configuration profile.

        Args:
            id: Configuration profile ID to delete
            force: If True, delete even if the profile is currently active
        """
        return await client.delete(
            f"/api/v1/network/config/{id}",
            params={"force": force},
        )
