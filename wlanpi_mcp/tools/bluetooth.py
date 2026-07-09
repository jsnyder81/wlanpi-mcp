from typing import Literal

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.tool()
    async def get_bluetooth_status() -> dict:
        """
        Get Bluetooth adapter status including name, address, power state,
        and list of paired devices.
        """
        return await client.get("/api/v1/bluetooth/status")

    @mcp.tool()
    async def set_bluetooth_power(action: Literal["on", "off"]) -> dict:
        """
        Turn Bluetooth on or off.

        Args:
            action: 'on' to enable Bluetooth, 'off' to disable it
        """
        return await client.post(f"/api/v1/bluetooth/power/{action}")

    @mcp.tool()
    async def start_bluetooth_pairing() -> dict:
        """
        Put the WlanPi into Bluetooth discoverable pairing mode (starts bt-timedpair)
        so a phone or laptop can pair with it.
        """
        return await client.post("/api/v1/bluetooth/pair")
