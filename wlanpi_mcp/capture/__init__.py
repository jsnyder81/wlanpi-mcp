"""
Wi-Fi packet capture over the wlanpi-core streaming WebSocket.

wlanpi-core exposes capture only as a WebSocket (`/api/v1/streaming/capture`),
not as REST, so this package is the one place in the server that speaks a
non-HTTP core protocol. It still talks to nothing but wlanpi-core: no local
subprocesses, no local files.

The pcapng reader and 802.11 dissector are adapted from wlanpi-core
`tools/capture_harness/capture_harness.py` and use the standard library only.
"""

from wlanpi_mcp.capture.dot11 import (
    ApInfo,
    ScanTable,
    channel_to_freq,
    freq_to_channel,
    parse_beacon,
    parse_radiotap,
    phy_label,
)
from wlanpi_mcp.capture.pcapng import PcapngReader
from wlanpi_mcp.capture.ws_client import (
    CaptureError,
    CaptureSocket,
    capture_ws_url,
    connect_capture,
    sessions_on_interface,
)

__all__ = [
    "ApInfo",
    "CaptureError",
    "CaptureSocket",
    "PcapngReader",
    "ScanTable",
    "capture_ws_url",
    "channel_to_freq",
    "connect_capture",
    "freq_to_channel",
    "parse_beacon",
    "parse_radiotap",
    "phy_label",
    "sessions_on_interface",
]
