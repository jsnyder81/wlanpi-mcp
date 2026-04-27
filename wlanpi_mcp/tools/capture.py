import asyncio
import os
import signal
import tempfile
import uuid
from typing import Literal, Optional

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient

DUMPCAP_BIN = "/usr/bin/dumpcap"
TSHARK_BIN = "/usr/bin/tshark"

# Active capture sessions: session_id -> {"proc": Process, "file": str, "interface": str, "duration": int}
_sessions: dict[str, dict] = {}


async def _run_tshark(args: list[str], timeout: float = 60.0) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"tshark timed out after {timeout}s"
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def _session_or_error(session_id: str) -> tuple[Optional[dict], Optional[dict]]:
    """Returns (session, None) if found, (None, error_dict) if not."""
    sess = _sessions.get(session_id)
    if sess is None:
        return None, {"error": f"No capture session found with id '{session_id}'"}
    return sess, None


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
        Use get_capture_status to poll for completion, then get_capture_analysis
        to analyse the results or access the raw PCAP via the MCP resource
        capture://sessions/{session_id}/pcap.

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
            "filter": capture_filter,
        }

        return {
            "session_id": session_id,
            "interface": interface,
            "output_file": pcap_path,
            "duration_seconds": duration_seconds,
            "capture_filter": capture_filter,
            "pid": proc.pid,
            "status": "running",
            "pcap_resource": f"capture://sessions/{session_id}/pcap",
        }

    @mcp.tool()
    async def get_capture_status(session_id: str) -> dict:
        """
        Get the status of a running or completed packet capture.

        Args:
            session_id: Session ID returned by start_packet_capture
        """
        sess, err = _session_or_error(session_id)
        if err:
            return err

        proc = sess["proc"]
        running = proc.returncode is None
        file_size = os.path.getsize(sess["file"]) if os.path.exists(sess["file"]) else 0

        return {
            "session_id": session_id,
            "interface": sess["interface"],
            "output_file": sess["file"],
            "duration_seconds": sess["duration"],
            "status": "running" if running else "complete",
            "return_code": proc.returncode,
            "file_size_bytes": file_size,
            "pcap_resource": f"capture://sessions/{session_id}/pcap",
        }

    @mcp.tool()
    async def stop_packet_capture(session_id: str) -> dict:
        """
        Stop a running packet capture before its duration expires.

        Args:
            session_id: Session ID returned by start_packet_capture
        """
        sess, err = _session_or_error(session_id)
        if err:
            return err

        proc = sess["proc"]
        if proc.returncode is not None:
            return {"session_id": session_id, "status": "already_complete", "return_code": proc.returncode}

        try:
            proc.send_signal(signal.SIGTERM)
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

        file_size = os.path.getsize(sess["file"]) if os.path.exists(sess["file"]) else 0

        return {
            "session_id": session_id,
            "status": "stopped",
            "output_file": sess["file"],
            "file_size_bytes": file_size,
            "pcap_resource": f"capture://sessions/{session_id}/pcap",
        }

    @mcp.tool()
    async def get_capture_analysis(
        session_id: str,
        report_type: Literal["summary", "packets", "conversations"] = "summary",
        display_filter: Optional[str] = None,
        max_packets: int = 500,
    ) -> dict:
        """
        Analyse a completed packet capture using tshark and return human-readable results.

        Call get_capture_status first to confirm the capture is complete before analysing.

        Report types:
          - summary: Protocol hierarchy statistics + frame/byte totals. Best first look.
          - packets: Tab-separated table of packets (time, src, dst, protocol, length, info).
                     Ideal for LLM reasoning about traffic patterns. Capped at max_packets.
          - conversations: IP conversation pairs with frame and byte counts in each direction.
                           Use to identify top talkers.

        Args:
            session_id: Session ID returned by start_packet_capture
            report_type: Type of analysis to run (default: 'summary')
            display_filter: Wireshark display filter to apply (e.g. 'tcp', 'dns', 'ip.addr==10.0.0.1')
            max_packets: Maximum packets to include in 'packets' report (default 500, max 5000)
        """
        sess, err = _session_or_error(session_id)
        if err:
            return err

        pcap_file = sess["file"]
        if sess["proc"].returncode is None:
            return {
                "warning": "Capture is still running. Analysis will cover packets captured so far.",
                "session_id": session_id,
            }

        if not os.path.exists(pcap_file):
            return {"error": f"Capture file not found: {pcap_file}"}
        if os.path.getsize(pcap_file) == 0:
            return {"error": "Capture file is empty — the capture may not have started correctly"}
        if not os.path.exists(TSHARK_BIN):
            return {"error": f"tshark not found at {TSHARK_BIN} — install wireshark-common on the WlanPi"}

        base_args = [TSHARK_BIN, "-r", pcap_file]
        if display_filter:
            base_args += ["-Y", display_filter]

        if report_type == "summary":
            # Protocol hierarchy + overall stats
            phs_rc, phs_out, phs_err = await _run_tshark(
                [TSHARK_BIN, "-r", pcap_file, "-q", "-z", "io,phs,"]
            )
            stats_rc, stats_out, stats_err = await _run_tshark(
                [TSHARK_BIN, "-r", pcap_file, "-q", "-z", "io,stat,0"]
            )
            if phs_rc != 0:
                return {"error": phs_err.strip() or f"tshark exited {phs_rc}"}
            return {
                "session_id": session_id,
                "report_type": "summary",
                "file_size_bytes": os.path.getsize(pcap_file),
                "display_filter": display_filter,
                "protocol_hierarchy": phs_out.strip(),
                "io_statistics": stats_out.strip(),
            }

        elif report_type == "packets":
            max_packets = max(1, min(max_packets, 5000))
            args = base_args + [
                "-T", "fields",
                "-e", "frame.number",
                "-e", "frame.time_relative",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "_ws.col.Protocol",
                "-e", "frame.len",
                "-e", "_ws.col.Info",
                "-E", "separator=\t",
                "-E", "header=y",
                "-c", str(max_packets),
            ]
            rc, out, err = await _run_tshark(args)
            if rc != 0:
                return {"error": err.strip() or f"tshark exited {rc}"}
            lines = out.strip().splitlines()
            return {
                "session_id": session_id,
                "report_type": "packets",
                "display_filter": display_filter,
                "max_packets": max_packets,
                "packet_count": max(0, len(lines) - 1),  # exclude header
                "table": out.strip(),
            }

        elif report_type == "conversations":
            rc, out, err = await _run_tshark(
                [TSHARK_BIN, "-r", pcap_file, "-q", "-z", "conv,ip"]
            )
            if rc != 0:
                return {"error": err.strip() or f"tshark exited {rc}"}
            return {
                "session_id": session_id,
                "report_type": "conversations",
                "conversations": out.strip(),
            }

        return {"error": f"Unknown report_type '{report_type}'"}

    @mcp.tool()
    async def list_capture_sessions() -> dict:
        """List all active and completed packet capture sessions in this server session."""
        return {
            "sessions": {
                sid: {
                    "interface": sess["interface"],
                    "output_file": sess["file"],
                    "status": "running" if sess["proc"].returncode is None else "complete",
                    "pcap_resource": f"capture://sessions/{sid}/pcap",
                }
                for sid, sess in _sessions.items()
            }
        }
