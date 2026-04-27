from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.config import ALLOWED_SERVICES


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.tool()
    async def get_device_info() -> dict:
        """Get WlanPi device identity: model, hostname, software version, and current operating mode."""
        return await client.get("/api/v1/system/device/info")

    @mcp.tool()
    async def get_device_stats() -> dict:
        """Get WlanPi live system metrics: IP address, CPU usage, RAM usage, disk usage, CPU temperature, and uptime."""
        return await client.get("/api/v1/system/device/stats")

    @mcp.tool()
    async def list_allowed_services() -> dict:
        """List all services that can be managed on this WlanPi (started, stopped, or queried)."""
        return {"services": ALLOWED_SERVICES}

    @mcp.tool()
    async def get_service_status(name: str) -> dict:
        """
        Get the running status of a WlanPi service.

        Args:
            name: Service name (use list_allowed_services to see valid names)
        """
        return await client.get("/api/v1/system/service/status", params={"name": name})

    @mcp.tool()
    async def start_service(name: str) -> dict:
        """
        Start a WlanPi service.

        Args:
            name: Service name (use list_allowed_services to see valid names)
        """
        if name.replace(".service", "") not in ALLOWED_SERVICES:
            return {"error": f"'{name}' is not in the allowed services list"}
        return await client.post("/api/v1/system/service/start", params={"name": name})

    @mcp.tool()
    async def stop_service(name: str) -> dict:
        """
        Stop a WlanPi service.

        Args:
            name: Service name (use list_allowed_services to see valid names)
        """
        if name.replace(".service", "") not in ALLOWED_SERVICES:
            return {"error": f"'{name}' is not in the allowed services list"}
        return await client.post("/api/v1/system/service/stop", params={"name": name})
