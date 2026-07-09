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

    @mcp.tool()
    async def run_speedtest() -> dict:
        """
        Run an internet speed test (LibreSpeed CLI) from the WlanPi. Slow: typically
        takes 30-90 seconds to complete. Returns download/upload speed, ping, IP
        address, and the test server used.
        """
        return await client.get("/api/v1/utils/speedtest", timeout=180.0)

    @mcp.tool()
    async def start_blinker(interface: str = "eth0") -> dict:
        """
        Start the Ethernet port blinker (cable finder) — flashes the port LED so
        the cable can be located at the switch end.

        Args:
            interface: Ethernet interface to blink (default 'eth0')
        """
        return await client.post(
            "/api/v1/utils/blinker/start", params={"interface": interface}
        )

    @mcp.tool()
    async def stop_blinker() -> dict:
        """Stop the Ethernet port blinker."""
        return await client.post("/api/v1/utils/blinker/stop")

    @mcp.tool()
    async def get_blinker_status() -> dict:
        """Check whether the Ethernet port blinker is currently running."""
        return await client.get("/api/v1/utils/blinker/status")
