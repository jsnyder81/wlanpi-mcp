import asyncio
import os
import signal
import tempfile
import uuid
from typing import Optional

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient

DUMPCAP_BIN = "/usr/bin/dumpcap"

# Active capture sessions: session_id -> {"proc": Process, "file": str, "interface": str}
_sessions: dict[str, dict] = {}


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.tool()
    async def start_packet_capture(
        interface: str,
        duration_seconds: int = 30,
        capture_filter: Optional[str] = None,
        output_file: Optional[str] = None,
    ) -> dict:
        """
        Start a packet capture on a WlanPi interface using dumpcap.

        The capture runs for the specified duration and saves to a PCAP file.
        Requires the MCP server process to have capture privileges (CAP_NET_RAW
        or membership in the 'wireshark' group).

        Args:
            interface: Network interface to capture on (e.g. 'eth0', 'wlan0')
            duration_seconds: How long to capture (default 30, max 3600)
            capture_filter: BPF capture filter (e.g. 'tcp port 80', 'udp', 'host 10.0.0.1')
            output_file: Path to save the PCAP file. If omitted, a temp file is created.
        """
        if not os.path.exists(DUMPCAP_BIN):
            return {"error": f"dumpcap not found at {DUMPCAP_BIN}"}

        duration_seconds = max(1, min(duration_seconds, 3600))
        pcap_path = output_file or os.path.join(
            tempfile.gettempdir(), f"wlanpi-cap-{uuid.uuid4().hex[:8]}.pcap"
        )

        cmd = [DUMPCAP_BIN, "-i", interface, "-a", f"duration:{duration_seconds}", "-w", pcap_path]
        if capture_filter:
            cmd += ["-f", capture_filter]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except PermissionError:
            return {
                "error": (
                    "Permission denied starting dumpcap. "
                    "Ensure the service user is in the 'wireshark' group or has CAP_NET_RAW."
                )
            }
        except Exception as exc:
            return {"error": str(exc)}

        session_id = uuid.uuid4().hex[:12]
        _sessions[session_id] = {
            "proc": proc,
            "file": pcap_path,
            "interface": interface,
            "duration": duration_seconds,
        }

        return {
            "session_id": session_id,
            "interface": interface,
            "output_file": pcap_path,
            "duration_seconds": duration_seconds,
            "capture_filter": capture_filter,
            "pid": proc.pid,
            "status": "running",
        }

    @mcp.tool()
    async def get_capture_status(session_id: str) -> dict:
        """
        Get the status of a running or completed packet capture.

        Args:
            session_id: Session ID returned by start_packet_capture
        """
        if session_id not in _sessions:
            return {"error": f"No capture session found with id '{session_id}'"}

        sess = _sessions[session_id]
        proc = sess["proc"]
        running = proc.returncode is None
        file_size = 0
        if os.path.exists(sess["file"]):
            file_size = os.path.getsize(sess["file"])

        return {
            "session_id": session_id,
            "interface": sess["interface"],
            "output_file": sess["file"],
            "duration_seconds": sess["duration"],
            "status": "running" if running else "complete",
            "return_code": proc.returncode,
            "file_size_bytes": file_size,
        }

    @mcp.tool()
    async def stop_packet_capture(session_id: str) -> dict:
        """
        Stop a running packet capture before its duration expires.

        Args:
            session_id: Session ID returned by start_packet_capture
        """
        if session_id not in _sessions:
            return {"error": f"No capture session found with id '{session_id}'"}

        sess = _sessions[session_id]
        proc = sess["proc"]

        if proc.returncode is not None:
            return {"session_id": session_id, "status": "already_complete", "return_code": proc.returncode}

        try:
            proc.send_signal(signal.SIGTERM)
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

        file_size = 0
        if os.path.exists(sess["file"]):
            file_size = os.path.getsize(sess["file"])

        return {
            "session_id": session_id,
            "status": "stopped",
            "output_file": sess["file"],
            "file_size_bytes": file_size,
        }

    @mcp.tool()
    async def list_capture_sessions() -> dict:
        """List all active and completed packet capture sessions in this server session."""
        result = {}
        for sid, sess in _sessions.items():
            proc = sess["proc"]
            result[sid] = {
                "interface": sess["interface"],
                "output_file": sess["file"],
                "status": "running" if proc.returncode is None else "complete",
            }
        return {"sessions": result}
