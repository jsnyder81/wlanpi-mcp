from typing import Optional

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.tool()
    async def get_profiler_status() -> dict:
        """
        Get the current status of the wlanpi-profiler.
        Returns whether the profiler is running, its SSID, channel, and interface.
        """
        return await client.get("/api/v1/profiler/status")

    @mcp.tool()
    async def start_profiler(
        interface: Optional[str] = None,
        channel: Optional[int] = None,
        frequency: Optional[int] = None,
        ssid: Optional[str] = None,
        no11r: Optional[bool] = None,
        no11ax: Optional[bool] = None,
        no11be: Optional[bool] = None,
        wpa3_personal: Optional[bool] = None,
        wpa3_personal_transition: Optional[bool] = None,
        noAP: Optional[bool] = None,
        debug: Optional[bool] = None,
    ) -> dict:
        """
        Start the wlanpi-profiler to capture 802.11 client capability information.

        The profiler brings up a fake AP and captures association frames from clients
        to determine their 802.11 capabilities (PHY support, spatial streams, etc.).

        Args:
            interface: WLAN interface to use (e.g. 'wlan0')
            channel: 802.11 channel number to operate on
            frequency: Frequency in MHz (alternative to channel)
            ssid: SSID for the fake AP (default chosen by profiler)
            no11r: Disable 802.11r (Fast BSS Transition) support
            no11ax: Disable 802.11ax (Wi-Fi 6) support
            no11be: Disable 802.11be (Wi-Fi 7) support
            wpa3_personal: Enable WPA3-Personal only mode
            wpa3_personal_transition: Enable WPA3-Personal Transition mode
            noAP: Run without bringing up an AP (passive capture only)
            debug: Enable debug logging in profiler
        """
        body = {}
        if interface is not None:
            body["interface"] = interface
        if channel is not None:
            body["channel"] = channel
        if frequency is not None:
            body["frequency"] = frequency
        if ssid is not None:
            body["ssid"] = ssid
        if no11r is not None:
            body["no11r"] = no11r
        if no11ax is not None:
            body["no11ax"] = no11ax
        if no11be is not None:
            body["no11be"] = no11be
        if wpa3_personal is not None:
            body["wpa3_personal"] = wpa3_personal
        if wpa3_personal_transition is not None:
            body["wpa3_personal_transition"] = wpa3_personal_transition
        if noAP is not None:
            body["noAP"] = noAP
        if debug is not None:
            body["debug"] = debug

        return await client.post("/api/v1/profiler/start", json=body)

    @mcp.tool()
    async def stop_profiler() -> dict:
        """
        Stop the wlanpi-profiler and return summary results.
        """
        return await client.post("/api/v1/profiler/stop")
