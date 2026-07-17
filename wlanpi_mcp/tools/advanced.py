import re

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient

VALID_MODES = {"classic", "wconsole", "hotspot", "wiperf", "server", "bridge"}


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.tool()
    async def get_device_mode() -> dict:
        """
        Get the current WlanPi operating mode (classic, wconsole, hotspot, wiperf, server, bridge).
        """
        info = await client.get("/api/v1/system/device/info")
        mode = info.get("mode", "")
        return {"mode": mode, "valid": mode in VALID_MODES}

    @mcp.tool()
    async def get_regulatory_domain() -> dict:
        """
        Get the current Wi-Fi regulatory domain (country code) set on the WlanPi.
        Returns 'country' as an ISO 3166-1 alpha-2 code.
        """
        return await client.get("/api/v1/system/reg-domain")

    @mcp.tool()
    async def set_regulatory_domain(country_code: str) -> dict:
        """
        Set the Wi-Fi regulatory domain (country code) on the WlanPi.

        This controls which channels and transmit power levels are permitted.
        Use a valid ISO 3166-1 alpha-2 country code (e.g. 'US', 'GB', 'DE').

        Args:
            country_code: Two-letter ISO 3166-1 alpha-2 country code
        """
        if not re.match(r"^[A-Z]{2}$", country_code.upper()):
            return {"error": "country_code must be a two-letter ISO 3166-1 alpha-2 code (e.g. 'US')"}

        return await client.post(
            "/api/v1/system/reg-domain/set", json={"country": country_code.upper()}
        )

    @mcp.tool()
    async def get_battery_status() -> dict:
        """
        Get battery status on WlanPi models with a battery (e.g. WlanPi Pro).

        Returns 'present': false on hardware without a battery, otherwise
        capacity percentage and charging status.
        """
        return await client.get("/api/v1/system/battery")
