"""
Incremental pcapng block reader for the wlanpi-core capture WebSocket.

Adapted from wlanpi-core `tools/capture_harness/capture_harness.py` (the
reference capture client). Kept to the standard library on purpose: this
server does not ship scapy/dpkt, and the dissection scope here is deliberately
narrow (enough to summarise beacons, not to replace Wireshark).

The capture WebSocket streams raw `dumpcap -w -` output, so chunks arrive
unaligned with pcapng block boundaries and a new Section Header Block can
appear mid-stream (interface numbering restarts with it). Feed every chunk to
one reader instance and it yields whole packets as they complete.

Each yielded item is ``(linktype, timestamp, packet_bytes)``. ``timestamp`` is
Unix seconds as a float, decoded from the Enhanced Packet Block using the
per-interface ``if_tsresol`` option (default microseconds); it is ``None`` when
the interface is unknown. (This trailing timestamp is the one intentional
divergence from the wlanpi-core ``capture_harness.py`` reference, added so the
frame dissector can report inter-frame timing.)
"""

import struct
from typing import Dict, List, Optional, Tuple

__all__ = ["PcapngReader"]

Packet = Tuple[int, Optional[float], bytes]


class PcapngReader:
    """Feed byte chunks; yields (linktype, timestamp, packet_bytes) per packet."""

    SHB = 0x0A0D0D0A
    IDB = 0x00000001
    EPB = 0x00000006

    #: Blocks larger than this are treated as a desync rather than as a block
    #: we are still waiting to complete. dumpcap's snaplen is far below this,
    #: so a "length" this large only ever comes from misaligned bytes — without
    #: the cap the reader would stall forever waiting for data that never comes.
    MAX_BLOCK = 16 * 1024 * 1024

    #: Default pcapng timestamp resolution when an interface omits if_tsresol.
    DEFAULT_TSRESOL = 1e-6

    def __init__(self) -> None:
        self.buf = bytearray()
        self.endian = "<"
        self.linktypes: Dict[int, int] = {}
        self.tsresol: Dict[int, float] = {}
        self._iface_seq = 0

    def feed(self, data: bytes) -> List[Packet]:
        self.buf += data
        out: List[Packet] = []
        while len(self.buf) >= 12:
            if bytes(self.buf[0:4]) == b"\x0a\x0d\x0d\x0a":
                bom = bytes(self.buf[8:12])
                if bom == b"\x4d\x3c\x2b\x1a":
                    self.endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    self.endian = ">"
            total_len = struct.unpack(self.endian + "I", self.buf[4:8])[0]
            if total_len < 12 or total_len % 4 != 0 or total_len > self.MAX_BLOCK:
                # Desynced; drop a byte and try to re-find a block boundary.
                self.buf.pop(0)
                continue
            if len(self.buf) < total_len:
                break
            block = bytes(self.buf[:total_len])
            del self.buf[:total_len]
            self._handle_block(block, out)
        return out

    def _handle_block(self, block: bytes, out: List[Packet]) -> None:
        e = self.endian
        btype = struct.unpack_from(e + "I", block, 0)[0]
        if btype == self.SHB:
            # New section: interface numbering restarts.
            self.linktypes = {}
            self.tsresol = {}
            self._iface_seq = 0
        elif btype == self.IDB:
            linktype = struct.unpack_from(e + "H", block, 8)[0]
            self.linktypes[self._iface_seq] = linktype
            self.tsresol[self._iface_seq] = self._idb_tsresol(block)
            self._iface_seq += 1
        elif btype == self.EPB:
            if len(block) < 28:
                return
            iface_id = struct.unpack_from(e + "I", block, 8)[0]
            ts_high = struct.unpack_from(e + "I", block, 12)[0]
            ts_low = struct.unpack_from(e + "I", block, 16)[0]
            caplen = struct.unpack_from(e + "I", block, 20)[0]
            data_end = 28 + caplen
            pkt = block[28:data_end]
            ticks = (ts_high << 32) | ts_low
            resol = self.tsresol.get(iface_id)
            ts = ticks * resol if resol is not None else None
            out.append((self.linktypes.get(iface_id, 127), ts, pkt))

    def _idb_tsresol(self, block: bytes) -> float:
        """Read if_tsresol (option 9) from an IDB; default microseconds."""
        e = self.endian
        # IDB body: linktype(2) reserved(2) snaplen(4), then options at 16.
        pos = 16
        end = len(block) - 4  # exclude the trailing block-total-length
        while pos + 4 <= end:
            code, length = struct.unpack_from(e + "HH", block, pos)
            pos += 4
            if code == 0:  # opt_endofopt
                break
            if code == 9 and length >= 1:  # if_tsresol
                raw = block[pos]
                if raw & 0x80:  # high bit set => power of two
                    return 2.0 ** -(raw & 0x7F)
                return 10.0 ** -(raw & 0x7F)
            pos += length + ((4 - length % 4) % 4)  # options are 4-byte padded
        return self.DEFAULT_TSRESOL
