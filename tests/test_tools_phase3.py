import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp.server.fastmcp import FastMCP
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.config import Settings


# ── Advanced (mode, iw, regulatory, battery) ─────────────────────────────────

@pytest.mark.asyncio
async def test_get_device_mode_reads_file(tmp_path):
    mode_file = tmp_path / "wlanpi-state"
    mode_file.write_text("hotspot\n")

    from wlanpi_mcp.tools import advanced
    mock_client = MagicMock()
    mcp = FastMCP("test")

    with patch.object(advanced, "MODE_FILE", str(mode_file)):
        advanced.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["get_device_mode"].fn
    with patch.object(advanced, "MODE_FILE", str(mode_file)):
        result = await tool_fn()

    assert result["mode"] == "hotspot"
    assert result["valid"] is True


@pytest.mark.asyncio
async def test_get_device_mode_missing_file(tmp_path):
    from wlanpi_mcp.tools import advanced
    mock_client = MagicMock()
    mcp = FastMCP("test")
    advanced.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["get_device_mode"].fn
    with patch.object(advanced, "MODE_FILE", str(tmp_path / "nonexistent")):
        result = await tool_fn()

    assert result["mode"] == "classic"


@pytest.mark.asyncio
async def test_get_battery_status_not_available(tmp_path):
    from wlanpi_mcp.tools import advanced
    mock_client = MagicMock()
    mcp = FastMCP("test")
    advanced.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["get_battery_status"].fn
    with patch.object(advanced, "BATTERY_PATH", str(tmp_path / "no_battery")):
        result = await tool_fn()

    assert result["available"] is False


@pytest.mark.asyncio
async def test_get_battery_status_parses_uevent(tmp_path):
    uevent = tmp_path / "uevent"
    uevent.write_text(
        "POWER_SUPPLY_STATUS=Discharging\n"
        "POWER_SUPPLY_CAPACITY=78\n"
        "POWER_SUPPLY_VOLTAGE_NOW=3850000\n"
        "POWER_SUPPLY_CURRENT_NOW=500000\n"
        "POWER_SUPPLY_TEMP=250\n"
    )
    from wlanpi_mcp.tools import advanced
    mock_client = MagicMock()
    mcp = FastMCP("test")
    advanced.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["get_battery_status"].fn
    with patch.object(advanced, "BATTERY_PATH", str(uevent)):
        result = await tool_fn()

    assert result["available"] is True
    assert result["capacity_percent"] == 78
    assert result["status"] == "Discharging"
    assert result["voltage_mv"] == 3850.0
    assert result["temperature_c"] == 25.0


@pytest.mark.asyncio
async def test_set_regulatory_domain_validates_code():
    from wlanpi_mcp.tools import advanced
    mock_client = MagicMock()
    mcp = FastMCP("test")
    advanced.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["set_regulatory_domain"].fn
    result = await tool_fn(country_code="USA")  # invalid — 3 letters
    assert "error" in result


@pytest.mark.asyncio
async def test_set_regulatory_domain_accepts_valid_code(tmp_path):
    fake_bin = tmp_path / "wlanpi-reg-domain"
    fake_bin.write_text("#!/bin/sh\necho 'set'\n")
    fake_bin.chmod(0o755)

    from wlanpi_mcp.tools import advanced
    mock_client = MagicMock()
    mcp = FastMCP("test")
    advanced.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["set_regulatory_domain"].fn
    with patch.object(advanced, "REG_DOMAIN_BIN", str(fake_bin)):
        result = await tool_fn(country_code="US")

    assert result["regulatory_domain"] == "US"


# ── Packet Capture ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_start_capture_missing_dumpcap(tmp_path):
    from wlanpi_mcp.tools import capture
    mock_client = MagicMock()
    mcp = FastMCP("test")
    capture.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["start_packet_capture"].fn
    with patch.object(capture, "DUMPCAP_BIN", str(tmp_path / "no_dumpcap")):
        result = await tool_fn(interface="eth0")

    assert "error" in result
    assert "dumpcap not found" in result["error"]


@pytest.mark.asyncio
async def test_get_capture_status_unknown_session():
    from wlanpi_mcp.tools import capture
    mock_client = MagicMock()
    mcp = FastMCP("test")
    capture.register(mcp, mock_client)

    tool_fn = mcp._tool_manager._tools["get_capture_status"].fn
    result = await tool_fn(session_id="doesnotexist")

    assert "error" in result


@pytest.mark.asyncio
async def test_list_capture_sessions_empty():
    from wlanpi_mcp.tools import capture
    mock_client = MagicMock()
    mcp = FastMCP("test")
    capture.register(mcp, mock_client)
    capture._sessions.clear()

    tool_fn = mcp._tool_manager._tools["list_capture_sessions"].fn
    result = await tool_fn()

    assert result == {"sessions": {}}
