import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp.server.fastmcp import FastMCP
from wlanpi_mcp.tools import capture as capture_mod
from wlanpi_mcp.resources import capture as capture_res_mod


@pytest.fixture(autouse=True)
def clear_sessions():
    capture_mod._sessions.clear()
    yield
    capture_mod._sessions.clear()


def _make_mock_client():
    return MagicMock()


def _register_tools(extra_sessions: dict = None):
    mcp = FastMCP("test")
    capture_mod.register(mcp, _make_mock_client())
    if extra_sessions:
        capture_mod._sessions.update(extra_sessions)
    return mcp


# ── get_capture_analysis ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_analysis_unknown_session():
    mcp = _register_tools()
    fn = mcp._tool_manager._tools["get_capture_analysis"].fn
    result = await fn(session_id="nosuchid")
    assert "error" in result


@pytest.mark.asyncio
async def test_analysis_missing_file(tmp_path):
    proc = MagicMock()
    proc.returncode = 0
    capture_mod._sessions["abc123"] = {
        "proc": proc,
        "file": str(tmp_path / "missing.pcap"),
        "interface": "eth0",
        "duration": 10,
        "filter": None,
    }
    mcp = _register_tools()
    fn = mcp._tool_manager._tools["get_capture_analysis"].fn
    result = await fn(session_id="abc123")
    assert "error" in result
    assert "not found" in result["error"]


@pytest.mark.asyncio
async def test_analysis_empty_file(tmp_path):
    pcap = tmp_path / "empty.pcap"
    pcap.write_bytes(b"")
    proc = MagicMock()
    proc.returncode = 0
    capture_mod._sessions["abc123"] = {
        "proc": proc, "file": str(pcap), "interface": "eth0", "duration": 10, "filter": None,
    }
    mcp = _register_tools()
    fn = mcp._tool_manager._tools["get_capture_analysis"].fn
    result = await fn(session_id="abc123")
    assert "error" in result
    assert "empty" in result["error"]


@pytest.mark.asyncio
async def test_analysis_still_running_returns_warning(tmp_path):
    pcap = tmp_path / "running.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)  # fake PCAP magic
    proc = MagicMock()
    proc.returncode = None  # still running
    capture_mod._sessions["abc123"] = {
        "proc": proc, "file": str(pcap), "interface": "eth0", "duration": 30, "filter": None,
    }
    mcp = _register_tools()
    fn = mcp._tool_manager._tools["get_capture_analysis"].fn
    result = await fn(session_id="abc123")
    assert "warning" in result


@pytest.mark.asyncio
async def test_analysis_missing_tshark(tmp_path):
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    proc = MagicMock()
    proc.returncode = 0
    capture_mod._sessions["abc123"] = {
        "proc": proc, "file": str(pcap), "interface": "eth0", "duration": 10, "filter": None,
    }
    mcp = _register_tools()
    fn = mcp._tool_manager._tools["get_capture_analysis"].fn
    with patch.object(capture_mod, "TSHARK_BIN", str(tmp_path / "no_tshark")):
        result = await fn(session_id="abc123")
    assert "error" in result
    assert "tshark not found" in result["error"]


@pytest.mark.asyncio
async def test_analysis_summary_calls_tshark(tmp_path):
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    proc = MagicMock()
    proc.returncode = 0
    capture_mod._sessions["abc123"] = {
        "proc": proc, "file": str(pcap), "interface": "eth0", "duration": 10, "filter": None,
    }

    fake_tshark = tmp_path / "tshark"
    fake_tshark.write_text("#!/bin/sh\necho 'Protocol Hierarchy'\n")
    fake_tshark.chmod(0o755)

    mcp = _register_tools()
    fn = mcp._tool_manager._tools["get_capture_analysis"].fn
    with patch.object(capture_mod, "TSHARK_BIN", str(fake_tshark)):
        result = await fn(session_id="abc123", report_type="summary")

    assert result["report_type"] == "summary"
    assert "protocol_hierarchy" in result
    assert "io_statistics" in result


@pytest.mark.asyncio
async def test_analysis_packets_report(tmp_path):
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    proc = MagicMock()
    proc.returncode = 0
    capture_mod._sessions["abc123"] = {
        "proc": proc, "file": str(pcap), "interface": "eth0", "duration": 10, "filter": None,
    }

    fake_tshark = tmp_path / "tshark"
    fake_tshark.write_text(
        "#!/bin/sh\necho 'frame.number\tframe.time_relative\tip.src\tip.dst\t_ws.col.Protocol\tframe.len\t_ws.col.Info'\n"
        "echo '1\t0.000000\t10.0.0.1\t10.0.0.2\tTCP\t74\t443 -> 52000'\n"
    )
    fake_tshark.chmod(0o755)

    mcp = _register_tools()
    fn = mcp._tool_manager._tools["get_capture_analysis"].fn
    with patch.object(capture_mod, "TSHARK_BIN", str(fake_tshark)):
        result = await fn(session_id="abc123", report_type="packets", max_packets=100)

    assert result["report_type"] == "packets"
    assert "table" in result
    assert result["max_packets"] == 100


# ── capture://sessions/{id}/pcap resource ─────────────────────────────────────

@pytest.mark.asyncio
async def test_pcap_resource_unknown_session():
    mcp = FastMCP("test")
    capture_res_mod.register(mcp, _make_mock_client())

    templates = mcp._resource_manager._templates
    assert len(templates) == 1
    tmpl = list(templates.values())[0]

    with pytest.raises(ValueError, match="No capture session"):
        await tmpl.fn(session_id="nosuchid")


@pytest.mark.asyncio
async def test_pcap_resource_returns_bytes(tmp_path):
    pcap = tmp_path / "test.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1PCAPDATA")

    proc = MagicMock()
    proc.returncode = 0
    capture_mod._sessions["myid"] = {
        "proc": proc, "file": str(pcap), "interface": "eth0", "duration": 10, "filter": None,
    }

    mcp = FastMCP("test")
    capture_res_mod.register(mcp, _make_mock_client())

    templates = mcp._resource_manager._templates
    tmpl = list(templates.values())[0]

    data = await tmpl.fn(session_id="myid")
    assert isinstance(data, bytes)
    assert data == b"\xd4\xc3\xb2\xa1PCAPDATA"


@pytest.mark.asyncio
async def test_pcap_resource_mime_type():
    mcp = FastMCP("test")
    capture_res_mod.register(mcp, _make_mock_client())

    templates = mcp._resource_manager._templates
    tmpl = list(templates.values())[0]
    assert tmpl.mime_type == "application/vnd.tcpdump.pcap"
