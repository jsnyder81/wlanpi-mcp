import os

from mcp.server.fastmcp import FastMCP

from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.tools.capture import _sessions


def register(mcp: FastMCP, client: CoreClient) -> None:

    @mcp.resource(
        "capture://sessions/{session_id}/pcap",
        mime_type="application/vnd.tcpdump.pcap",
        description="Raw PCAP file for a capture session — downloadable by MCP clients that support binary resources.",
    )
    async def capture_pcap(session_id: str) -> bytes:
        """Raw PCAP binary for a capture session. Download and open in Wireshark."""
        sess = _sessions.get(session_id)
        if sess is None:
            raise ValueError(f"No capture session found with id '{session_id}'")

        pcap_file = sess["file"]
        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"Capture file not found: {pcap_file}")

        with open(pcap_file, "rb") as f:
            return f.read()
