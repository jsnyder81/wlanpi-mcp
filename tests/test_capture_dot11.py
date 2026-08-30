"""Tests for the radiotap/802.11 dissection behind the capture summaries."""

import struct

import pytest

from wlanpi_mcp.capture.dot11 import (
    ApInfo,
    FrameLog,
    ScanTable,
    channel_to_freq,
    freq_to_channel,
    parse_beacon,
    parse_frame,
    parse_radiotap,
    parse_radiotap_full,
    parse_rsn,
    phy_label,
    subtype_name,
)

# radiotap present bits: 3 = channel (freq u16 + flags u16), 5 = antenna
# signal (s8), 10 = dBm TX power (s8).
_PRESENT = (1 << 3) | (1 << 5) | (1 << 10)


def radiotap(freq: int = 2437, signal: int = -42, txpower: int = 20) -> bytes:
    fields = struct.pack("<HHbb", freq, 0x00A0, signal, txpower)
    length = 8 + len(fields)
    return struct.pack("<BBHI", 0, 0, length, _PRESENT) + fields


def ie(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value


def rsn_ie(akms, pairwise: int = 1, caps: int = 0) -> bytes:
    body = struct.pack("<H", 1) + b"\x00\x0f\xac\x04"
    body += struct.pack("<H", pairwise) + b"\x00\x0f\xac\x04" * pairwise
    body += struct.pack("<H", len(akms))
    for akm in akms:
        body += b"\x00\x0f\xac" + bytes([akm])
    body += struct.pack("<H", caps)  # RSN capabilities
    return ie(48, body)


WPA_IE = ie(221, b"\x00\x50\xf2\x01\x01\x00" + b"\x00\x50\xf2\x02")


def beacon(
    bssid: str = "aa:bb:cc:dd:ee:ff",
    ssid: bytes = b"testnet",
    ies: bytes = b"",
    privacy: bool = False,
    subtype: int = 8,
    rt: bytes = None,
    ftype: int = 0,
) -> bytes:
    rt = radiotap() if rt is None else rt
    addr = bytes(int(o, 16) for o in bssid.split(":"))
    frame_control = struct.pack("<H", (subtype << 4) | (ftype << 2))
    header = (
        frame_control
        + b"\x00\x00"  # duration
        + b"\xff" * 6  # addr1 (broadcast)
        + addr  # addr2
        + addr  # addr3 (BSSID)
        + b"\x00\x00"  # seq control
    )
    caps = 0x0011 if privacy else 0x0001
    fixed = b"\x00" * 8 + struct.pack("<H", 100) + struct.pack("<H", caps)
    return rt + header + fixed + ie(0, ssid) + ies


# ── frequency helpers ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "channel,freq",
    [(1, 2412), (6, 2437), (11, 2462), (14, 2484), (36, 5180), (149, 5745)],
)
def test_channel_freq_round_trip(channel, freq):
    assert channel_to_freq(channel) == freq
    assert freq_to_channel(freq) == channel


def test_channel_to_freq_rejects_6ghz_channel_numbers():
    with pytest.raises(ValueError):
        channel_to_freq(233)


def test_freq_to_channel_handles_6ghz_and_unknown():
    assert freq_to_channel(5955) == 1
    assert freq_to_channel(1234) is None


# ── radiotap ─────────────────────────────────────────────────────────────────


def test_parse_radiotap_extracts_fields():
    info, length = parse_radiotap(radiotap(freq=5180, signal=-63, txpower=17))
    assert info == {"freq": 5180, "signal": -63, "txpower": 17}
    assert length == 14


def test_parse_radiotap_rejects_short_or_bogus_headers():
    assert parse_radiotap(b"\x00\x00")[1] == 0
    # Header claims to be longer than the buffer.
    assert parse_radiotap(struct.pack("<BBHI", 0, 0, 400, _PRESENT))[1] == 0


# ── beacon dissection ────────────────────────────────────────────────────────


def test_parse_beacon_basic_fields():
    ap = parse_beacon(beacon(ies=ie(3, bytes([6])) + ie(7, b"US ")))
    assert ap.bssid == "aa:bb:cc:dd:ee:ff"
    assert ap.ssid == "testnet"
    assert ap.channel == 6
    assert ap.signal == -42
    assert ap.txpower == 20
    assert ap.country == "US"


def test_channel_comes_from_radiotap_without_ds_element():
    ap = parse_beacon(beacon(rt=radiotap(freq=5180)))
    assert ap.channel == 36


def test_tpc_report_overrides_radiotap_txpower():
    ap = parse_beacon(beacon(ies=ie(35, bytes([13, 0]))))
    assert ap.txpower == 13


def test_probe_response_is_parsed_and_other_frames_are_not():
    assert parse_beacon(beacon(subtype=5)) is not None
    assert parse_beacon(beacon(subtype=4)) is None  # probe request
    assert parse_beacon(beacon(ftype=2)) is None  # data frame
    assert parse_beacon(b"\x00" * 4) is None


@pytest.mark.parametrize(
    "akms,expected",
    [
        ([2], "WPA2-PSK"),
        ([8], "WPA3"),
        ([1], "WPA2-Ent"),
        ([5], "WPA2-Ent"),
        ([2, 8], "WPA2/3"),
        ([255], "WPA2"),
    ],
)
def test_rsn_akm_classification(akms, expected):
    ap = parse_beacon(beacon(ies=rsn_ie(akms), privacy=True))
    assert ap.security == expected


def test_wpa_vendor_ie_without_rsn_is_wpa():
    ap = parse_beacon(beacon(ies=WPA_IE, privacy=True))
    assert ap.security == "WPA"


def test_privacy_bit_without_rsn_or_wpa_is_wep():
    ap = parse_beacon(beacon(privacy=True))
    assert ap.security == "WEP"


def test_no_privacy_bit_is_open():
    ap = parse_beacon(beacon())
    assert ap.security == "Open"


def test_hidden_ssid_zero_length():
    assert parse_beacon(beacon(ssid=b"")).ssid == "<hidden>"


def test_hidden_ssid_nul_padded():
    assert parse_beacon(beacon(ssid=b"\x00\x00\x00\x00")).ssid == "<hidden>"


def test_phy_amendments_from_information_elements():
    ies = (
        ie(45, b"\x00" * 26)  # HT capabilities  -> n
        + ie(191, b"\x00" * 12)  # VHT capabilities -> ac
        + ie(255, bytes([35]) + b"\x00" * 8)  # HE capabilities  -> ax
        + ie(255, bytes([108]) + b"\x00" * 8)  # EHT capabilities -> be
    )
    ap = parse_beacon(beacon(ies=ies, rt=radiotap(freq=5180)))
    assert ap.phy == {"n", "ac", "ax", "be"}
    assert phy_label(ap) == "a/n/ac/ax/be"


def test_phy_label_uses_g_on_24ghz():
    ap = ApInfo(channel=6, phy={"n", "ax"})
    assert phy_label(ap) == "g/n/ax"


def test_truncated_information_element_stops_parsing():
    # Tag claims 40 bytes of value but only 2 are present.
    ap = parse_beacon(beacon(ies=bytes([45, 40]) + b"\x01\x02"))
    assert ap.ssid == "testnet"
    assert "n" not in ap.phy


# ── ScanTable ────────────────────────────────────────────────────────────────


def test_scan_table_merges_by_bssid():
    table = ScanTable()
    table.update(parse_beacon(beacon(ssid=b"", ies=ie(45, b"\x00" * 26))))
    table.update(
        parse_beacon(
            beacon(
                ssid=b"realname", ies=ie(255, bytes([35])) + rsn_ie([2]), privacy=True
            )
        )
    )
    assert len(table.aps) == 1
    ap = table.aps["aa:bb:cc:dd:ee:ff"]
    assert ap.count == 2
    assert ap.ssid == "realname"  # a later real SSID replaces <hidden>
    assert ap.phy == {"n", "ax"}  # amendments are unioned across frames
    assert ap.security == "WPA2-PSK"


def test_scan_table_keeps_known_ssid_when_a_hidden_beacon_follows():
    table = ScanTable()
    table.update(parse_beacon(beacon(ssid=b"realname")))
    table.update(parse_beacon(beacon(ssid=b"")))
    assert table.aps["aa:bb:cc:dd:ee:ff"].ssid == "realname"


def test_to_result_shape_and_sort_order():
    table = ScanTable()
    table.update(
        parse_beacon(
            beacon(
                bssid="00:00:00:00:00:11",
                ssid=b"far",
                rt=radiotap(freq=2437, signal=-80),
            )
        )
    )
    table.update(
        parse_beacon(
            beacon(
                bssid="00:00:00:00:00:22",
                ssid=b"near",
                rt=radiotap(freq=2437, signal=-30),
            )
        )
    )
    table.update(
        parse_beacon(
            beacon(
                bssid="00:00:00:00:00:33",
                ssid=b"fivegig",
                rt=radiotap(freq=5180, signal=-50),
                ies=ie(7, b"US "),
            )
        )
    )
    rows = table.to_result()
    # Sorted by channel, then strongest signal first inside a channel.
    assert [r["ssid"] for r in rows] == ["near", "far", "fivegig"]
    assert set(rows[0]) == {
        "bssid",
        "ssid",
        "channel",
        "signal_dbm",
        "security",
        "akm",
        "pairwise_ciphers",
        "group_cipher",
        "pmf",
        "phy",
        "tx_power",
        "country",
        "frames_seen",
    }
    assert rows[0] == {
        "bssid": "00:00:00:00:00:22",
        "ssid": "near",
        "channel": 6,
        "signal_dbm": -30,
        "security": "Open",
        "akm": [],
        "pairwise_ciphers": [],
        "group_cipher": None,
        "pmf": None,
        "phy": "g",
        "tx_power": 20,
        "country": "",
        "frames_seen": 1,
    }
    assert rows[2]["channel"] == 36 and rows[2]["phy"] == "a"


def test_to_result_is_empty_for_an_empty_table():
    assert ScanTable().to_result() == []


# ── full AKM / cipher / PMF detail ───────────────────────────────────────────


def test_parse_rsn_full_detail():
    # WPA3 transition: SAE(8) + PSK(2), CCMP pairwise+group, PMF required.
    rsn = parse_rsn(
        struct.pack("<H", 1)  # version
        + b"\x00\x0f\xac\x04"  # group cipher: CCMP-128
        + struct.pack("<H", 1)
        + b"\x00\x0f\xac\x04"  # pairwise: CCMP-128
        + struct.pack("<H", 2)
        + b"\x00\x0f\xac\x08"  # AKM: SAE
        + b"\x00\x0f\xac\x02"  # AKM: PSK
        + struct.pack("<H", 0x00C0)  # RSN caps: MFPC + MFPR
    )
    assert rsn["group_cipher"] == "CCMP-128"
    assert rsn["pairwise_ciphers"] == ["CCMP-128"]
    assert rsn["akm_suites"] == ["SAE", "PSK"]
    assert rsn["pmf"] == {"capable": True, "required": True}


def test_ap_row_carries_akm_and_pmf():
    table = ScanTable()
    table.update(parse_beacon(beacon(ies=rsn_ie([8], caps=0x0080), privacy=True)))
    row = table.to_result()[0]
    assert row["security"] == "WPA3"
    assert row["akm"] == ["SAE"]
    assert row["pairwise_ciphers"] == ["CCMP-128"]
    assert row["group_cipher"] == "CCMP-128"
    assert row["pmf"] == "capable"


def test_owe_is_labelled():
    ap = parse_beacon(beacon(ies=rsn_ie([18]), privacy=True))
    assert ap.security == "OWE"


def test_wpa_vendor_detail_populates_row():
    wpa_full = ie(
        221,
        b"\x00\x50\xf2\x01"
        + struct.pack("<H", 1)  # version
        + b"\x00\x50\xf2\x02"  # group: TKIP
        + struct.pack("<H", 1)
        + b"\x00\x50\xf2\x04"  # pairwise: CCMP-128
        + struct.pack("<H", 1)
        + b"\x00\x50\xf2\x02",  # AKM: PSK
    )
    table = ScanTable()
    table.update(parse_beacon(beacon(ies=wpa_full, privacy=True)))
    row = table.to_result()[0]
    assert row["security"] == "WPA"
    assert row["akm"] == ["PSK"]
    assert row["pairwise_ciphers"] == ["CCMP-128"]
    assert row["group_cipher"] == "TKIP"
    assert row["pmf"] is None


# ── full radiotap decode ─────────────────────────────────────────────────────


def test_parse_radiotap_full_lists_present_fields():
    info, length = parse_radiotap_full(radiotap(freq=5180, signal=-63, txpower=17))
    assert length == 14
    assert info["freq"] == 5180
    assert info["signal"] == -63
    assert info["txpower"] == 17
    assert set(info["present"]) == {"channel", "signal", "txpower"}
    # The helper's channel flags (0x00A0) mark 2.4 GHz + CCK regardless of freq.
    assert info["channel_flags"]["band"] == "2.4GHz"
    assert info["channel_flags"]["modulation"] == "cck"


def radiotap_mcs(index: int = 9, flags: int = 0x14, known: int = 0x1F) -> bytes:
    present = 1 << 19
    fields = bytes([known, flags, index])
    length = 8 + len(fields)
    return struct.pack("<BBHI", 0, 0, length, present) + fields


def test_parse_radiotap_full_decodes_mcs():
    info, _ = parse_radiotap_full(radiotap_mcs(index=9))
    assert info["mcs"] == {
        "index": 9,
        "bandwidth_mhz": 20,
        "short_gi": True,
        "format": "mixed",
        "fec": "ldpc",
    }


# ── per-frame dissection ─────────────────────────────────────────────────────


def mac(text: str) -> bytes:
    return bytes(int(o, 16) for o in text.split(":"))


def mgmt_frame(
    subtype: int,
    addr1: str = "ff:ff:ff:ff:ff:ff",
    addr2: str = "aa:bb:cc:00:00:01",
    addr3: str = "aa:bb:cc:00:00:01",
    body: bytes = b"",
    rt: bytes = None,
) -> bytes:
    rt = radiotap() if rt is None else rt
    fc = struct.pack("<H", (subtype << 4) | (0 << 2))
    header = fc + b"\x00\x00" + mac(addr1) + mac(addr2) + mac(addr3) + b"\x00\x00"
    return rt + header + body


def test_subtype_names_cover_all_types():
    assert subtype_name(0, 8) == "beacon"
    assert subtype_name(0, 11) == "auth"
    assert subtype_name(1, 13) == "ack"
    assert subtype_name(2, 8) == "qos-data"
    assert subtype_name(1, 99) == "subtype-99"


def test_parse_frame_beacon_addresses_and_result():
    rec = parse_frame(beacon(bssid="aa:bb:cc:dd:ee:ff", ssid=b"lab"))
    assert rec["kind"] == "mgmt/beacon"
    assert rec["addr1"] == "ff:ff:ff:ff:ff:ff"
    assert rec["addr2"] == "aa:bb:cc:dd:ee:ff"
    assert rec["addr3"] == "aa:bb:cc:dd:ee:ff"
    assert rec["result"] == {"ssid": "lab"}
    assert "channel" in rec["radiotap"]["present"]


def test_parse_frame_auth_result():
    body = struct.pack("<HHH", 0, 2, 0)  # open, seq 2, success
    rec = parse_frame(mgmt_frame(11, body=body))
    assert rec["kind"] == "mgmt/auth"
    assert rec["result"] == {
        "algorithm": {"code": 0, "name": "open"},
        "seq": 2,
        "status": {"code": 0, "name": "success"},
    }


def test_parse_frame_sae_auth_result():
    body = struct.pack("<HHH", 3, 1, 0)  # SAE, seq 1, success
    rec = parse_frame(mgmt_frame(11, body=body))
    assert rec["result"]["algorithm"] == {"code": 3, "name": "sae"}


def test_parse_frame_assoc_response_status_and_aid():
    body = struct.pack("<HHH", 0x0011, 0, 0xC001)  # caps, success, aid
    rec = parse_frame(mgmt_frame(1, body=body))
    assert rec["kind"] == "mgmt/assoc-resp"
    assert rec["result"]["status"] == {"code": 0, "name": "success"}
    assert rec["result"]["aid"] == 1


def test_parse_frame_deauth_reason():
    rec = parse_frame(mgmt_frame(12, body=struct.pack("<H", 3)))
    assert rec["kind"] == "mgmt/deauth"
    assert rec["result"] == {"reason": {"code": 3, "name": "deauth-leaving"}}


def test_parse_frame_probe_request_ssid():
    rec = parse_frame(mgmt_frame(4, body=ie(0, b"target-net")))
    assert rec["kind"] == "mgmt/probe-req"
    assert rec["result"] == {"ssid": "target-net"}


def test_parse_frame_control_ack_has_only_addr1():
    # ACK (ctrl subtype 13): FC + duration + addr1.
    frame = (
        radiotap()
        + struct.pack("<H", (13 << 4) | (1 << 2))
        + b"\x00\x00"
        + mac("11:22:33:44:55:66")
    )
    rec = parse_frame(frame)
    assert rec["kind"] == "ctrl/ack"
    assert rec["addr1"] == "11:22:33:44:55:66"
    assert "addr2" not in rec and "addr3" not in rec


def test_parse_frame_control_rts_has_two_addresses():
    frame = (
        radiotap()
        + struct.pack("<H", (11 << 4) | (1 << 2))
        + b"\x00\x00"
        + mac("11:22:33:44:55:66")
        + mac("aa:aa:aa:aa:aa:aa")
    )
    rec = parse_frame(frame)
    assert rec["kind"] == "ctrl/rts"
    assert rec["addr1"] == "11:22:33:44:55:66"
    assert rec["addr2"] == "aa:aa:aa:aa:aa:aa"


def test_parse_frame_wds_data_has_four_addresses():
    fc = struct.pack("<H", (8 << 4) | (2 << 2) | 0x0300)  # qos-data, to_ds+from_ds
    frame = (
        radiotap()
        + fc
        + b"\x00\x00"
        + mac("00:00:00:00:00:01")
        + mac("00:00:00:00:00:02")
        + mac("00:00:00:00:00:03")
        + b"\x00\x00"
        + mac("00:00:00:00:00:04")
    )
    rec = parse_frame(frame)
    assert rec["kind"] == "data/qos-data"
    assert rec["to_ds"] and rec["from_ds"]
    assert rec["addr4"] == "00:00:00:00:00:04"


def test_parse_frame_returns_none_on_bogus_radiotap():
    assert parse_frame(b"\x00\x00") is None


# ── FrameLog ─────────────────────────────────────────────────────────────────


def test_frame_log_counts_are_exact_but_records_are_capped():
    log = FrameLog(max_frames=2)
    for _ in range(5):
        log.add({"kind": "mgmt/beacon"})
    log.add({"kind": "ctrl/ack"})
    result = log.to_result()
    assert result["frame_total"] == 6
    assert result["frames_returned"] == 2
    assert result["frames_truncated"] is True
    assert result["frame_types"] == {"mgmt/beacon": 5, "ctrl/ack": 1}


def test_frame_log_timestamps_are_relative_to_first_frame():
    log = FrameLog()
    log.add({"kind": "mgmt/beacon"}, ts=1000.0)
    log.add({"kind": "mgmt/beacon"}, ts=1000.5)
    assert log.frames[0]["t"] == 0.0
    assert log.frames[0]["n"] == 1
    assert log.frames[1]["t"] == 0.5
    assert log.frames[1]["n"] == 2


def test_frame_log_zero_cap_keeps_counts_only():
    log = FrameLog(max_frames=0)
    log.add({"kind": "mgmt/beacon"})
    result = log.to_result()
    assert result["frames"] == []
    assert result["frame_total"] == 1
    assert result["frame_types"] == {"mgmt/beacon": 1}
