"""Tests for the incremental pcapng reader used by the capture tools."""

import struct

from wlanpi_mcp.capture.pcapng import PcapngReader

LINKTYPE_RADIOTAP = 127
LINKTYPE_ETHERNET = 1


def shb(endian: str = "<") -> bytes:
    body = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1)
    total = 12 + len(body)
    return (
        struct.pack(endian + "II", 0x0A0D0D0A, total)
        + body
        + struct.pack(endian + "I", total)
    )


def idb(linktype: int, endian: str = "<", options: bytes = b"") -> bytes:
    body = struct.pack(endian + "HHI", linktype, 0, 262144) + options
    total = 12 + len(body)
    return (
        struct.pack(endian + "II", 0x00000001, total)
        + body
        + struct.pack(endian + "I", total)
    )


def tsresol_option(value: int) -> bytes:
    # if_tsresol: option code 9, length 1, padded to 4 bytes; then opt_endofopt.
    return (
        struct.pack("<HH", 9, 1)
        + bytes([value])
        + b"\x00" * 3
        + struct.pack("<HH", 0, 0)
    )


def epb(payload: bytes, iface: int = 0, endian: str = "<", ts: int = 0) -> bytes:
    pad = (-len(payload)) % 4
    ts_high, ts_low = (ts >> 32) & 0xFFFFFFFF, ts & 0xFFFFFFFF
    body = (
        struct.pack(
            endian + "IIIII", iface, ts_high, ts_low, len(payload), len(payload)
        )
        + payload
        + b"\x00" * pad
    )
    total = 12 + len(body)
    return (
        struct.pack(endian + "II", 0x00000006, total)
        + body
        + struct.pack(endian + "I", total)
    )


def feed_in_chunks(reader: PcapngReader, data: bytes, size: int):
    out = []
    for offset in range(0, len(data), size):
        out.extend(reader.feed(data[offset : offset + size]))
    return out


def test_extracts_packet_from_one_chunk():
    stream = shb() + idb(LINKTYPE_RADIOTAP) + epb(b"hello-frame")
    packets = PcapngReader().feed(stream)
    assert packets == [(LINKTYPE_RADIOTAP, 0.0, b"hello-frame")]


def test_survives_unaligned_chunk_splits():
    stream = (
        shb() + idb(LINKTYPE_RADIOTAP) + epb(b"frame-one") + epb(b"frame-two-longer")
    )
    for size in (1, 3, 7, 13, 64):
        packets = feed_in_chunks(PcapngReader(), stream, size)
        assert packets == [
            (LINKTYPE_RADIOTAP, 0.0, b"frame-one"),
            (LINKTYPE_RADIOTAP, 0.0, b"frame-two-longer"),
        ], f"chunk size {size}"


def test_partial_block_yields_nothing_until_complete():
    stream = shb() + idb(LINKTYPE_RADIOTAP) + epb(b"frame")
    reader = PcapngReader()
    assert reader.feed(stream[:-4]) == []
    assert reader.feed(stream[-4:]) == [(LINKTYPE_RADIOTAP, 0.0, b"frame")]


def test_linktype_follows_interface_id():
    stream = (
        shb()
        + idb(LINKTYPE_RADIOTAP)
        + idb(LINKTYPE_ETHERNET)
        + epb(b"radio", iface=0)
        + epb(b"wired", iface=1)
    )
    assert PcapngReader().feed(stream) == [
        (LINKTYPE_RADIOTAP, 0.0, b"radio"),
        (LINKTYPE_ETHERNET, 0.0, b"wired"),
    ]


def test_unknown_interface_id_defaults_to_radiotap():
    stream = shb() + idb(LINKTYPE_ETHERNET) + epb(b"orphan", iface=9)
    # Unknown iface: linktype defaults to radiotap and timestamp is unknown.
    assert PcapngReader().feed(stream) == [(LINKTYPE_RADIOTAP, None, b"orphan")]


def test_mid_stream_shb_resets_interface_numbering():
    first = shb() + idb(LINKTYPE_ETHERNET) + epb(b"first", iface=0)
    second = shb() + idb(LINKTYPE_RADIOTAP) + epb(b"second", iface=0)
    reader = PcapngReader()
    assert reader.feed(first) == [(LINKTYPE_ETHERNET, 0.0, b"first")]
    # New section: interface 0 is now the radiotap interface, not the old one.
    assert reader.feed(second) == [(LINKTYPE_RADIOTAP, 0.0, b"second")]


def test_big_endian_section_is_detected():
    stream = shb(">") + idb(LINKTYPE_RADIOTAP, ">") + epb(b"be-frame", endian=">")
    assert PcapngReader().feed(stream) == [(LINKTYPE_RADIOTAP, 0.0, b"be-frame")]


def test_recovers_from_leading_garbage():
    junk = b"\x11\x22\x33\x44" * 3
    stream = junk + shb() + idb(LINKTYPE_RADIOTAP) + epb(b"after-desync")
    assert PcapngReader().feed(stream) == [(LINKTYPE_RADIOTAP, 0.0, b"after-desync")]


def test_absurd_block_length_does_not_stall_the_reader():
    # A misaligned "length" of 4 GiB is a desync, not a block still arriving:
    # without the size cap the reader would wait for it forever.
    junk = struct.pack("<II", 0x00000006, 0xFFFFFFFC)
    stream = junk + shb() + idb(LINKTYPE_RADIOTAP) + epb(b"still-here")
    assert PcapngReader().feed(stream) == [(LINKTYPE_RADIOTAP, 0.0, b"still-here")]


def test_short_epb_is_ignored():
    truncated = struct.pack("<II", 0x00000006, 16) + b"\x00" * 4 + struct.pack("<I", 16)
    stream = shb() + idb(LINKTYPE_RADIOTAP) + truncated + epb(b"good")
    assert PcapngReader().feed(stream) == [(LINKTYPE_RADIOTAP, 0.0, b"good")]


def test_default_microsecond_timestamp_resolution():
    # No if_tsresol option => microseconds; 1_500_000 ticks = 1.5 s.
    stream = shb() + idb(LINKTYPE_RADIOTAP) + epb(b"f", ts=1_500_000)
    ((_lt, ts, _pkt),) = PcapngReader().feed(stream)
    assert ts == 1.5


def test_if_tsresol_nanoseconds_is_honoured():
    # if_tsresol=9 => nanoseconds; 1_500_000_000 ticks = 1.5 s.
    stream = (
        shb()
        + idb(LINKTYPE_RADIOTAP, options=tsresol_option(9))
        + epb(b"f", ts=1_500_000_000)
    )
    ((_lt, ts, _pkt),) = PcapngReader().feed(stream)
    assert ts == 1.5
