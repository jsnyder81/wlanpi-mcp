import asyncio
import os
import re
from typing import Optional

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient

MODE_FILE = "/etc/wlanpi-state"
REG_DOMAIN_BIN = "/usr/bin/wlanpi-reg-domain"
IW_BIN = "/sbin/iw"
BATTERY_PATH = "/sys/class/power_supply/bq27546-0/uevent"

VALID_MODES = {"classic", "wconsole", "hotspot", "wiperf", "server", "bridge"}


async def _run_subprocess(cmd: list[str], timeout: float = 30.0) -> tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"Command timed out after {timeout}s"
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.tool()
    async def get_device_mode() -> dict:
        """
        Get the current WlanPi operating mode (classic, wconsole, hotspot, wiperf, server, bridge).
        Reads directly from /etc/wlanpi-state.
        """
        try:
            with open(MODE_FILE) as f:
                mode = f.readline().strip()
            return {"mode": mode, "valid": mode in VALID_MODES}
        except FileNotFoundError:
            return {"mode": "classic", "valid": True, "note": f"{MODE_FILE} not found, defaulting to classic"}
        except Exception as exc:
            return {"error": str(exc)}

    @mcp.tool()
    async def run_iw_scan(interface: str) -> dict:
        """
        Run a raw 'iw dev scan' on the specified interface.

        Returns richer RF data than wpa_supplicant scan: power, capability flags,
        information elements, supported rates, etc. The interface must not be
        managed by wpa_supplicant during the scan (or use a secondary interface).

        Args:
            interface: WLAN interface name (e.g. 'wlan0', 'wlan1')
        """
        if not os.path.exists(IW_BIN):
            return {"error": f"iw not found at {IW_BIN}"}

        rc, stdout, stderr = await _run_subprocess(
            [IW_BIN, "dev", interface, "scan"], timeout=30.0
        )
        if rc != 0:
            return {"error": stderr.strip() or f"iw scan exited with code {rc}"}

        return {"interface": interface, "raw_output": stdout}

    @mcp.tool()
    async def get_regulatory_domain() -> dict:
        """
        Get the current Wi-Fi regulatory domain (country code) set on the WlanPi.
        """
        if not os.path.exists(REG_DOMAIN_BIN):
            return {"error": f"wlanpi-reg-domain not found at {REG_DOMAIN_BIN}"}

        rc, stdout, stderr = await _run_subprocess([REG_DOMAIN_BIN])
        if rc != 0:
            return {"error": stderr.strip() or f"wlanpi-reg-domain exited with code {rc}"}

        return {"regulatory_domain": stdout.strip()}

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

        if not os.path.exists(REG_DOMAIN_BIN):
            return {"error": f"wlanpi-reg-domain not found at {REG_DOMAIN_BIN}"}

        rc, stdout, stderr = await _run_subprocess(
            [REG_DOMAIN_BIN, country_code.upper()]
        )
        if rc != 0:
            return {"error": stderr.strip() or f"wlanpi-reg-domain exited with code {rc}"}

        return {"regulatory_domain": country_code.upper(), "result": stdout.strip()}

    @mcp.tool()
    async def get_battery_status() -> dict:
        """
        Get battery status on WlanPi Pro models.

        Reads from the BQ27546 fuel gauge chip. Returns 'not_available' on
        hardware that does not have a battery (e.g. WlanPi R4 without battery).
        """
        if not os.path.exists(BATTERY_PATH):
            return {"available": False, "note": "No battery hardware detected (not a WlanPi Pro or battery not installed)"}

        try:
            props: dict[str, str] = {}
            with open(BATTERY_PATH) as f:
                for line in f:
                    line = line.strip()
                    if "=" in line:
                        key, _, val = line.partition("=")
                        props[key] = val

            capacity = props.get("POWER_SUPPLY_CAPACITY")
            status = props.get("POWER_SUPPLY_STATUS", "Unknown")
            voltage_now = props.get("POWER_SUPPLY_VOLTAGE_NOW")
            current_now = props.get("POWER_SUPPLY_CURRENT_NOW")
            temp = props.get("POWER_SUPPLY_TEMP")

            result: dict = {
                "available": True,
                "status": status,
            }
            if capacity is not None:
                result["capacity_percent"] = int(capacity)
            if voltage_now is not None:
                result["voltage_mv"] = round(int(voltage_now) / 1000, 1)
            if current_now is not None:
                result["current_ma"] = round(int(current_now) / 1000, 1)
            if temp is not None:
                result["temperature_c"] = round(int(temp) / 10, 1)

            return result

        except Exception as exc:
            return {"available": False, "error": str(exc)}
