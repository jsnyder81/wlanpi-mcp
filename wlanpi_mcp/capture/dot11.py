"""
Radiotap + 802.11 dissection for capture summaries.

Adapted from wlanpi-core `tools/capture_harness/capture_harness.py` (the
reference capture client). Standard library only — no scapy/dpkt.

Two views are produced from the same frames:

* an **access-point table** (:class:`ScanTable`), keyed by BSSID and merged
  from beacons/probe-responses, with full RSN/WPA detail (AKM suites, pairwise
  and group ciphers, PMF) alongside the compact security label; and
* a **per-frame log** (:class:`FrameLog`) covering *every* frame type — the
  named type/subtype, source/destination addresses (addr1..addr4), a full
  radiotap decode, and, for the frames that carry one, a decoded result
  (authentication algorithm/status, association status/AID, deauth/disassoc
  reason, probe/assoc SSID).

The radiotap decoder walks the first present-word's fields end to end (TSFT
through HE); vendor namespaces and any field past the ones defined here stop
the walk rather than risk misaligning the rest. This is a summariser, not a
full protocol decoder, but it no longer throws information away.
"""

import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__all__ = [
    "ApInfo",
    "FrameLog",
    "ScanTable",
    "channel_to_freq",
    "freq_to_channel",
    "parse_beacon",
    "parse_frame",
    "parse_radiotap",
    "parse_radiotap_full",
    "parse_rsn",
    "parse_wpa",
    "phy_label",
    "subtype_name",
]

#: Default cap on how many per-frame records a FrameLog keeps; counts are exact
#: regardless. Beacons dominate a busy capture, so the cap keeps the returned
#: summary bounded without dropping the type/subtype tallies.
DEFAULT_MAX_FRAMES = 200


# ---------------------------------------------------------------------------
# Channel / frequency helpers
# ---------------------------------------------------------------------------


def channel_to_freq(ch: int) -> int:
    """Map a 2.4/5 GHz channel number to its centre frequency in MHz."""
    if ch == 14:
        return 2484
    if 1 <= ch <= 13:
        return 2412 + (ch - 1) * 5
    if 32 <= ch <= 196:  # 5 GHz
        return 5000 + ch * 5
    raise ValueError(
        f"cannot map channel {ch} to a frequency; 6 GHz channels must be "
        "given as explicit frequencies"
    )


def freq_to_channel(freq: int) -> Optional[int]:
    """Map a frequency in MHz to a channel number, or None if unknown."""
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472:
        return (freq - 2412) // 5 + 1
    if 5000 <= freq <= 5895:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115:  # 6 GHz
        return (freq - 5950) // 5
    return None


# ---------------------------------------------------------------------------
# Radiotap
# ---------------------------------------------------------------------------

# (align, size) for radiotap present bits 0..27. Bits 28+ (TLVs), the namespace
# bits (29/30) and the extension bit (31) are not walked — hitting one stops
# field decoding rather than guessing an offset.
_RT_FIELDS = {
    0: (8, 8),  # TSFT
    1: (1, 1),  # Flags
    2: (1, 1),  # Rate
    3: (2, 4),  # Channel (freq u16 + flags u16)
    4: (2, 2),  # FHSS
    5: (1, 1),  # dBm antenna signal
    6: (1, 1),  # dBm antenna noise
    7: (2, 2),  # Lock quality
    8: (2, 2),  # TX attenuation
    9: (2, 2),  # dB TX attenuation
    10: (1, 1),  # dBm TX power
    11: (1, 1),  # Antenna
    12: (1, 1),  # dB antenna signal
    13: (1, 1),  # dB antenna noise
    14: (2, 2),  # RX flags
    15: (2, 2),  # TX flags
    16: (1, 1),  # RTS retries
    17: (1, 1),  # Data retries
    18: (4, 8),  # XChannel (deprecated)
    19: (1, 3),  # MCS
    20: (4, 8),  # A-MPDU status
    21: (2, 12),  # VHT
    22: (8, 12),  # timestamp
    23: (2, 12),  # HE
    24: (2, 12),  # HE-MU
    25: (2, 6),  # HE-MU-other-user (best effort)
    26: (1, 1),  # 0-length PSDU
    27: (2, 4),  # L-SIG
}

_RT_NAMES = {
    0: "tsft",
    1: "flags",
    2: "rate",
    3: "channel",
    4: "fhss",
    5: "signal",
    6: "noise",
    7: "lock_quality",
    8: "tx_attenuation",
    9: "db_tx_attenuation",
    10: "txpower",
    11: "antenna",
    12: "db_signal",
    13: "db_noise",
    14: "rx_flags",
    15: "tx_flags",
    16: "rts_retries",
    17: "data_retries",
    18: "xchannel",
    19: "mcs",
    20: "ampdu",
    21: "vht",
    22: "timestamp",
    23: "he",
    24: "he_mu",
    25: "he_mu_other_user",
    26: "zero_length_psdu",
    27: "lsig",
}


def _signed8(b: bytes) -> int:
    return struct.unpack("<b", b[:1])[0]


def _decode_rt_field(bit: int, raw: bytes, info: dict) -> None:
    """Decode one radiotap field into ``info`` (best effort; never raises)."""
    try:
        if bit == 0:
            info["tsft"] = struct.unpack_from("<Q", raw, 0)[0]
        elif bit == 1:
            val = raw[0]
            info["flags"] = {
                "cfp": bool(val & 0x01),
                "short_preamble": bool(val & 0x02),
                "wep": bool(val & 0x04),
                "fragmentation": bool(val & 0x08),
                "fcs_at_end": bool(val & 0x10),
                "data_pad": bool(val & 0x20),
                "bad_fcs": bool(val & 0x40),
                "short_gi": bool(val & 0x80),
            }
        elif bit == 2:
            info["rate_mbps"] = raw[0] * 0.5
        elif bit == 3:
            freq, chflags = struct.unpack_from("<HH", raw, 0)
            info["freq"] = freq
            band = None
            if chflags & 0x0080:
                band = "2.4GHz"
            elif chflags & 0x0100:
                band = "5/6GHz"
            modulation = (
                "cck" if chflags & 0x0020 else ("ofdm" if chflags & 0x0040 else None)
            )
            info["channel_flags"] = {
                "band": band,
                "modulation": modulation,
                "raw": chflags,
            }
        elif bit == 4:
            info["fhss"] = struct.unpack_from("<H", raw, 0)[0]
        elif bit == 5:
            info["signal"] = _signed8(raw)
        elif bit == 6:
            info["noise"] = _signed8(raw)
        elif bit == 7:
            info["lock_quality"] = struct.unpack_from("<H", raw, 0)[0]
        elif bit == 8:
            info["tx_attenuation"] = struct.unpack_from("<H", raw, 0)[0]
        elif bit == 9:
            info["db_tx_attenuation"] = struct.unpack_from("<H", raw, 0)[0]
        elif bit == 10:
            info["txpower"] = _signed8(raw)
        elif bit == 11:
            info["antenna"] = raw[0]
        elif bit == 12:
            info["db_signal"] = raw[0]
        elif bit == 13:
            info["db_noise"] = raw[0]
        elif bit == 14:
            info["rx_flags"] = struct.unpack_from("<H", raw, 0)[0]
        elif bit == 15:
            info["tx_flags"] = struct.unpack_from("<H", raw, 0)[0]
        elif bit == 16:
            info["rts_retries"] = raw[0]
        elif bit == 17:
            info["data_retries"] = raw[0]
        elif bit == 18:
            _flags, freq, chan, maxpower = struct.unpack_from("<IHBb", raw, 0)
            info["xchannel"] = {"freq": freq, "channel": chan, "max_power": maxpower}
        elif bit == 19:
            info["mcs"] = _decode_mcs(raw)
        elif bit == 20:
            ref, flags = struct.unpack_from("<IH", raw, 0)
            info["ampdu"] = {"reference": ref, "flags": flags}
        elif bit == 21:
            info["vht"] = _decode_vht(raw)
        elif bit == 22:
            ts, accuracy, unit_pos, flags = struct.unpack_from("<QHBB", raw, 0)
            info["timestamp"] = {
                "ts": ts,
                "accuracy": accuracy,
                "unit": unit_pos & 0x0F,
            }
        elif bit == 23:
            info["he"] = _decode_he(raw)
        elif bit == 24:
            info["he_mu"] = raw.hex()
        elif bit == 25:
            info["he_mu_other_user"] = raw.hex()
        elif bit == 26:
            info["zero_length_psdu"] = raw[0]
        elif bit == 27:
            info["lsig"] = raw.hex()
    except (struct.error, IndexError):
        pass


def _decode_mcs(raw: bytes) -> dict:
    known, flags, index = raw[0], raw[1], raw[2]
    out: dict = {}
    if known & 0x02:
        out["index"] = index
    if known & 0x01:
        out["bandwidth_mhz"] = {0: 20, 1: 40, 2: 20, 3: 20}[flags & 0x03]
    if known & 0x04:
        out["short_gi"] = bool(flags & 0x04)
    if known & 0x08:
        out["format"] = "greenfield" if flags & 0x08 else "mixed"
    if known & 0x10:
        out["fec"] = "ldpc" if flags & 0x10 else "bcc"
    if known & 0x20:
        out["stbc"] = (flags >> 5) & 0x03
    return out


_VHT_BW = {0: 20, 1: 40, 2: 40, 3: 40, 4: 80, 8: 80, 9: 80, 10: 80, 11: 160, 12: 160}


def _decode_vht(raw: bytes) -> dict:
    known = struct.unpack_from("<H", raw, 0)[0]
    flags = raw[2]
    bw = raw[3] & 0x1F
    mcs_nss = raw[4:8]
    out: dict = {"bandwidth_mhz": _VHT_BW.get(bw)}
    if known & 0x0004:
        out["short_gi"] = bool(flags & 0x04)
    users = []
    for b in mcs_nss:
        nss = b & 0x0F
        if nss:
            users.append({"mcs": (b >> 4) & 0x0F, "nss": nss})
    out["users"] = users
    return out


def _decode_he(raw: bytes) -> dict:
    d = list(struct.unpack_from("<HHHHHH", raw, 0))
    return {
        "ppdu_format": {0: "su", 1: "ext-su", 2: "mu", 3: "trig"}.get(d[0] & 0x0003),
        "bss_color": d[2] & 0x003F,
        "ul_dl": (d[2] >> 7) & 1,
        "data_mcs": (d[2] >> 8) & 0x0F,
        "dcm": (d[2] >> 12) & 1,
        "gi": {0: "0.8us", 1: "1.6us", 2: "3.2us"}.get((d[4] >> 4) & 0x03),
        "data_bandwidth_ru": {0: "20MHz", 1: "40MHz", 2: "80MHz", 3: "160MHz"}.get(
            d[4] & 0x000F, f"ru-{d[4] & 0x000F}"
        ),
    }


def parse_radiotap_full(buf: bytes) -> Tuple[dict, int]:
    """
    Decode a radiotap header end to end.

    Returns ``(fields, header_len)``; ``header_len`` is 0 if the header is
    malformed. ``fields`` holds every present field it could decode (see
    ``_RT_NAMES``) plus a ``present`` list of the field names the header
    advertised, so callers can tell "absent" from "could not decode".
    """
    info: dict = {}
    if len(buf) < 8:
        return info, 0
    _ver, _pad, length = struct.unpack_from("<BBH", buf, 0)
    if length < 8 or length > len(buf):
        return info, 0
    present_words = []
    off = 4
    while off + 4 <= len(buf):
        word = struct.unpack_from("<I", buf, off)[0]
        present_words.append(word)
        off += 4
        if not (word & (1 << 31)):
            break
    if not present_words:
        return info, length
    present = present_words[0]
    info["present"] = [
        _RT_NAMES[b] for b in range(28) if present & (1 << b) and b in _RT_NAMES
    ]
    if len(present_words) > 1:
        info["extended_present"] = True
    pos = off
    for bit in range(0, 28):
        if not (present & (1 << bit)):
            continue
        field_spec = _RT_FIELDS.get(bit)
        if field_spec is None:  # unknown size; cannot advance safely
            break
        align, size = field_spec
        if pos % align:
            pos += align - (pos % align)
        end = pos + size
        if end > length:
            break
        _decode_rt_field(bit, buf[pos:end], info)
        pos = end
    return info, length


def parse_radiotap(buf: bytes) -> Tuple[dict, int]:
    """Back-compat projection: the freq/signal/txpower the AP path needs."""
    full, length = parse_radiotap_full(buf)
    return {
        "freq": full.get("freq"),
        "signal": full.get("signal"),
        "txpower": full.get("txpower"),
    }, length


# ---------------------------------------------------------------------------
# 802.11 frame types / subtypes
# ---------------------------------------------------------------------------

_TYPE_NAMES = {0: "mgmt", 1: "ctrl", 2: "data", 3: "ext"}

_MGMT_SUBTYPES = {
    0: "assoc-req",
    1: "assoc-resp",
    2: "reassoc-req",
    3: "reassoc-resp",
    4: "probe-req",
    5: "probe-resp",
    6: "timing-adv",
    8: "beacon",
    9: "atim",
    10: "disassoc",
    11: "auth",
    12: "deauth",
    13: "action",
    14: "action-no-ack",
}

_CTRL_SUBTYPES = {
    2: "trigger",
    3: "tack",
    4: "beamforming-report-poll",
    5: "vht-he-ndp-announce",
    6: "control-frame-ext",
    7: "control-wrapper",
    8: "block-ack-req",
    9: "block-ack",
    10: "ps-poll",
    11: "rts",
    12: "cts",
    13: "ack",
    14: "cf-end",
    15: "cf-end-cf-ack",
}

_DATA_SUBTYPES = {
    0: "data",
    1: "data-cf-ack",
    2: "data-cf-poll",
    3: "data-cf-ack-poll",
    4: "null",
    5: "cf-ack",
    6: "cf-poll",
    7: "cf-ack-poll",
    8: "qos-data",
    9: "qos-data-cf-ack",
    10: "qos-data-cf-poll",
    11: "qos-data-cf-ack-poll",
    12: "qos-null",
    14: "qos-cf-poll",
    15: "qos-cf-ack-poll",
}

_EXT_SUBTYPES = {0: "dmg-beacon", 1: "s1g-beacon"}

_SUBTYPE_TABLES = {
    0: _MGMT_SUBTYPES,
    1: _CTRL_SUBTYPES,
    2: _DATA_SUBTYPES,
    3: _EXT_SUBTYPES,
}

#: Control subtypes that carry a transmitter address (addr2) after addr1.
_CTRL_HAS_ADDR2 = frozenset({8, 9, 10, 11, 14, 15})


def subtype_name(ftype: int, subtype: int) -> str:
    """Human-readable subtype name, e.g. (0, 8) -> 'beacon'."""
    table = _SUBTYPE_TABLES.get(ftype, {})
    return table.get(subtype, f"subtype-{subtype}")


# ---------------------------------------------------------------------------
# Management result codes
# ---------------------------------------------------------------------------

_AUTH_ALGS = {
    0: "open",
    1: "shared-key",
    2: "fast-bss-transition",
    3: "sae",
    4: "fils-sk",
    5: "fils-sk-pfs",
    6: "fils-pk",
}

_STATUS_CODES = {
    0: "success",
    1: "unspecified-failure",
    5: "cannot-support-all-capabilities",
    6: "reassoc-no-association",
    7: "assoc-denied-unspecified",
    8: "unsupported-auth-algorithm",
    9: "auth-seq-out-of-order",
    10: "auth-challenge-failure",
    11: "auth-timeout",
    12: "assoc-denied-ap-full",
    13: "unsupported-basic-rates",
    17: "assoc-denied-no-short-preamble",
    22: "assoc-denied-spectrum-mgmt-required",
    25: "assoc-denied-no-short-slot",
    27: "assoc-denied-no-ht",
    30: "assoc-request-rejected-temporarily",
    31: "robust-mgmt-frame-policy-violation",
    37: "request-declined",
    38: "invalid-parameters",
    40: "invalid-information-element",
    43: "invalid-pairwise-cipher",
    44: "invalid-akmp",
    46: "invalid-rsn-capabilities",
    52: "invalid-pmkid",
    53: "invalid-mde",
    76: "auth-rejected-anti-clogging",
    77: "auth-rejected-unsupported-group",
}

_REASON_CODES = {
    1: "unspecified",
    2: "prior-auth-invalid",
    3: "deauth-leaving",
    4: "disassoc-inactivity",
    5: "disassoc-ap-busy",
    6: "class2-frame-from-nonauth",
    7: "class3-frame-from-nonassoc",
    8: "disassoc-sta-leaving",
    9: "sta-not-authenticated",
    13: "invalid-information-element",
    14: "mic-failure",
    15: "4way-handshake-timeout",
    16: "group-key-handshake-timeout",
    17: "ie-differs",
    18: "invalid-group-cipher",
    19: "invalid-pairwise-cipher",
    20: "invalid-akmp",
    23: "ieee8021x-auth-failed",
    24: "cipher-suite-rejected",
    34: "disassoc-low-ack",
}

_ACTION_CATEGORIES = {
    0: "spectrum-management",
    1: "qos",
    3: "block-ack",
    4: "public",
    5: "radio-measurement",
    6: "fast-bss-transition",
    7: "ht",
    8: "sa-query",
    10: "wnm",
    17: "vht",
    21: "he",
    127: "vendor-specific",
}


def _named(code: int, table: Dict[int, str]) -> dict:
    return {"code": code, "name": table.get(code, "reserved")}


# ---------------------------------------------------------------------------
# RSN / WPA security detail
# ---------------------------------------------------------------------------

_OUI_RSN = b"\x00\x0f\xac"
_OUI_MS = b"\x00\x50\xf2"

HIDDEN_SSID = "<hidden>"

_RSN_CIPHERS = {
    0: "use-group",
    1: "WEP-40",
    2: "TKIP",
    4: "CCMP-128",
    5: "WEP-104",
    6: "BIP-CMAC-128",
    8: "GCMP-128",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "BIP-GMAC-128",
    12: "BIP-GMAC-256",
    13: "BIP-CMAC-256",
}

_RSN_AKMS = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    7: "TDLS",
    8: "SAE",
    9: "FT-SAE",
    10: "AP-PeerKey",
    11: "802.1X-Suite-B",
    12: "802.1X-Suite-B-192",
    13: "FT-802.1X-SHA384",
    14: "FILS-SHA256",
    15: "FILS-SHA384",
    16: "FT-FILS-SHA256",
    17: "FT-FILS-SHA384",
    18: "OWE",
    19: "FT-PSK-SHA384",
    20: "PSK-SHA384",
}

_MS_CIPHERS = {0: "use-group", 1: "WEP-40", 2: "TKIP", 4: "CCMP-128", 5: "WEP-104"}
_MS_AKMS = {1: "802.1X", 2: "PSK"}


def _suite(buf: bytes, off: int) -> bytes:
    """The 4-byte cipher/AKM suite selector at ``off`` (OUI + type)."""
    end = off + 4
    return buf[off:end]


def _suite_name(suite: bytes, ciphers: Dict[int, str]) -> str:
    if len(suite) < 4:
        return "?"
    oui, t = suite[:3], suite[3]
    if oui == _OUI_RSN:
        return (
            _RSN_CIPHERS.get(t, f"rsn:{t}")
            if ciphers is _RSN_CIPHERS
            else _RSN_AKMS.get(t, f"rsn:{t}")
        )
    if oui == _OUI_MS:
        return ciphers.get(t, f"ms:{t}")
    return f"{oui.hex()}:{t}"


def _akm_types(val: bytes) -> set:
    """The set of RSN AKM suite type bytes in an RSN element (for labelling)."""
    types: set = set()
    try:
        off = 2 + 4  # version + group cipher
        pw_count = struct.unpack_from("<H", val, off)[0]
        off += 2 + 4 * pw_count
        akm_count = struct.unpack_from("<H", val, off)[0]
        off += 2
        for _ in range(akm_count):
            suite = _suite(val, off)
            off += 4
            if suite[:3] == _OUI_RSN:
                types.add(suite[3])
    except (struct.error, IndexError):
        pass
    return types


def _rsn_security(val: bytes) -> str:
    """Compact security label from an RSN element's AKM suites."""
    akm_types = _akm_types(val)
    has_sae = bool(akm_types & {8, 9})
    has_psk = bool(akm_types & {2, 4, 6})
    has_ent = bool(akm_types & {1, 3, 5})
    if has_sae and has_psk:
        return "WPA2/3"
    if has_sae:
        return "WPA3"
    if 18 in akm_types:
        return "OWE"
    if has_ent:
        return "WPA2-Ent"
    if has_psk:
        return "WPA2-PSK"
    return "WPA2"


def parse_rsn(val: bytes) -> dict:
    """Full RSN element decode: version, ciphers, AKM suites, PMF."""
    out: dict = {
        "type": "RSN",
        "group_cipher": None,
        "pairwise_ciphers": [],
        "akm_suites": [],
        "pmf": None,
    }
    try:
        out["version"] = struct.unpack_from("<H", val, 0)[0]
        out["group_cipher"] = _suite_name(val[2:6], _RSN_CIPHERS)
        off = 6
        pw_count = struct.unpack_from("<H", val, off)[0]
        off += 2
        out["pairwise_ciphers"] = [
            _suite_name(_suite(val, off + 4 * i), _RSN_CIPHERS) for i in range(pw_count)
        ]
        off += 4 * pw_count
        akm_count = struct.unpack_from("<H", val, off)[0]
        off += 2
        out["akm_suites"] = [
            _suite_name(_suite(val, off + 4 * i), _RSN_AKMS) for i in range(akm_count)
        ]
        off += 4 * akm_count
        if off + 2 <= len(val):
            caps = struct.unpack_from("<H", val, off)[0]
            out["pmf"] = {
                "capable": bool(caps & 0x0080),
                "required": bool(caps & 0x0040),
            }
    except (struct.error, IndexError):
        pass
    return out


def parse_wpa(val: bytes) -> dict:
    """Full WPA (vendor) element decode. WPA1 has no PMF."""
    out: dict = {
        "type": "WPA",
        "group_cipher": None,
        "pairwise_ciphers": [],
        "akm_suites": [],
        "pmf": None,
    }
    try:
        off = 4  # OUI(3) + type(1)
        out["version"] = struct.unpack_from("<H", val, off)[0]
        off += 2
        out["group_cipher"] = _suite_name(_suite(val, off), _MS_CIPHERS)
        off += 4
        pw_count = struct.unpack_from("<H", val, off)[0]
        off += 2
        out["pairwise_ciphers"] = [
            _suite_name(_suite(val, off + 4 * i), _MS_CIPHERS) for i in range(pw_count)
        ]
        off += 4 * pw_count
        akm_count = struct.unpack_from("<H", val, off)[0]
        off += 2
        out["akm_suites"] = [
            _suite_name(_suite(val, off + 4 * i), _MS_AKMS) for i in range(akm_count)
        ]
    except (struct.error, IndexError):
        pass
    return out


def _pmf_label(pmf: Optional[dict]) -> Optional[str]:
    if not pmf:
        return None
    if pmf.get("required"):
        return "required"
    if pmf.get("capable"):
        return "capable"
    return "disabled"


# ---------------------------------------------------------------------------
# Beacon / probe-response dissection (the AP table)
# ---------------------------------------------------------------------------


@dataclass
class ApInfo:
    bssid: str = ""
    ssid: str = ""
    channel: Optional[int] = None
    signal: Optional[int] = None
    security: str = "Open"
    phy: set = field(default_factory=set)
    txpower: Optional[int] = None
    country: str = ""
    count: int = 0
    last_seen: float = 0.0
    rsn: Optional[dict] = None
    wpa: Optional[dict] = None
    bss_load: Optional[dict] = None


def _parse_bss_load(val: bytes) -> Optional[dict]:
    """Decode the QBSS/BSS Load element (tag 11): station count, channel
    utilization (0-255 -> percent), and available admission capacity."""
    if len(val) < 5:
        return None
    try:
        stations = struct.unpack_from("<H", val, 0)[0]
        chan_util = val[2]
        admission = struct.unpack_from("<H", val, 3)[0]
    except struct.error:
        return None
    return {
        "stations": stations,
        "channel_utilization": round(chan_util / 255 * 100, 1),
        "channel_utilization_raw": chan_util,
        "available_admission_capacity": admission,
    }


def _iter_ies(pkt: bytes, start: int):
    """Yield (tag, value) for each information element from ``start``."""
    p = start
    end = len(pkt)
    while p + 2 <= end:
        tag = pkt[p]
        ln = pkt[p + 1]
        val_start = p + 2
        val_end = val_start + ln
        val = pkt[val_start:val_end]
        p = val_end
        if len(val) < ln:
            break
        yield tag, val


def _ssid_from_ies(pkt: bytes, start: int) -> Optional[str]:
    for tag, val in _iter_ies(pkt, start):
        if tag == 0:
            if not val or not val.strip(b"\x00"):
                return HIDDEN_SSID
            return val.decode("utf-8", "replace")
    return None


def parse_beacon(pkt: bytes) -> Optional[ApInfo]:
    """Parse a management beacon/probe-response into ApInfo, else None."""
    rt_info, rtlen = parse_radiotap(pkt)
    if rtlen == 0:
        return None
    if len(pkt) < rtlen + 24:
        return None
    fc = struct.unpack_from("<H", pkt, rtlen)[0]
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    if ftype != 0 or subtype not in (5, 8):  # mgmt beacon(8)/probe-resp(5)
        return None

    ap = ApInfo()
    bssid_start = rtlen + 16  # addr3 of the management header
    bssid_end = bssid_start + 6
    ap.bssid = ":".join(f"{b:02x}" for b in pkt[bssid_start:bssid_end])
    ap.signal = rt_info.get("signal")
    ap.txpower = rt_info.get("txpower")
    if rt_info.get("freq"):
        ap.channel = freq_to_channel(rt_info["freq"])

    caps_off = rtlen + 24 + 8 + 2  # + timestamp(8) + interval(2)
    privacy = False
    if caps_off + 2 <= len(pkt):
        caps = struct.unpack_from("<H", pkt, caps_off)[0]
        privacy = bool(caps & 0x0010)

    have_rsn = have_wpa = False
    for tag, val in _iter_ies(pkt, rtlen + 24 + 12):
        if tag == 0:
            if not val or not val.strip(b"\x00"):
                ap.ssid = HIDDEN_SSID
            else:
                ap.ssid = val.decode("utf-8", "replace")
        elif tag == 3 and val:
            ap.channel = val[0]
        elif tag == 7 and len(val) >= 2:
            ap.country = val[:2].decode("ascii", "replace")
        elif tag == 11:  # QBSS/BSS Load: station count, channel utilization
            ap.bss_load = _parse_bss_load(val)
        elif tag == 35 and val:  # TPC report: tx power, link margin
            ap.txpower = struct.unpack_from("<b", val, 0)[0]
        elif tag == 45:
            ap.phy.add("n")
        elif tag == 48:
            have_rsn = True
            ap.security = _rsn_security(val)
            ap.rsn = parse_rsn(val)
        elif tag == 191:
            ap.phy.add("ac")
        elif tag == 221 and val[:3] == _OUI_MS and len(val) >= 4 and val[3] == 1:
            have_wpa = True
            ap.wpa = parse_wpa(val)
        elif tag == 255 and val:  # extension IEs
            ext = val[0]
            if ext in (35, 36):
                ap.phy.add("ax")
            elif ext in (106, 108):
                ap.phy.add("be")

    if not have_rsn:
        if have_wpa:
            ap.security = "WPA"
        elif privacy:
            ap.security = "WEP"
        else:
            ap.security = "Open"
    return ap


_PHY_ORDER = ["n", "ac", "ax", "be"]


def phy_label(ap: ApInfo) -> str:
    """Render the 802.11 amendments seen for an AP, e.g. 'g/n/ax'."""
    base = "g" if (ap.channel or 0) <= 14 else "a"
    amend = [x for x in _PHY_ORDER if x in ap.phy]
    return "/".join([base] + amend)


# ---------------------------------------------------------------------------
# Per-frame dissection (all frame types)
# ---------------------------------------------------------------------------


def _mac(pkt: bytes, off: int) -> Optional[str]:
    end = off + 6
    if end > len(pkt):
        return None
    return ":".join(f"{b:02x}" for b in pkt[off:end])


def _mgmt_result(subtype: int, pkt: bytes, body: int) -> Optional[dict]:
    """Decode the fixed 'result' fields of a management frame, if any."""
    n = len(pkt)

    def u16(o: int) -> Optional[int]:
        return struct.unpack_from("<H", pkt, o)[0] if o + 2 <= n else None

    if subtype in (1, 3):  # assoc-resp / reassoc-resp
        status, aid = u16(body + 2), u16(body + 4)
        out: dict = {}
        if status is not None:
            out["status"] = _named(status, _STATUS_CODES)
        if aid is not None:
            out["aid"] = aid & 0x3FFF
        return out or None
    if subtype == 11:  # auth
        alg, seq, status = u16(body), u16(body + 2), u16(body + 4)
        out = {}
        if alg is not None:
            out["algorithm"] = _named(alg, _AUTH_ALGS)
        if seq is not None:
            out["seq"] = seq
        if status is not None:
            out["status"] = _named(status, _STATUS_CODES)
        return out or None
    if subtype in (10, 12):  # disassoc / deauth
        reason = u16(body)
        return {"reason": _named(reason, _REASON_CODES)} if reason is not None else None
    if subtype == 0:  # assoc-req
        ssid = _ssid_from_ies(pkt, body + 4)
        return {"ssid": ssid} if ssid is not None else None
    if subtype == 2:  # reassoc-req (cap + listen + current AP)
        ssid = _ssid_from_ies(pkt, body + 10)
        return {"ssid": ssid} if ssid is not None else None
    if subtype == 4:  # probe-req
        ssid = _ssid_from_ies(pkt, body)
        return {"ssid": ssid} if ssid is not None else None
    if subtype in (5, 8):  # probe-resp / beacon
        ssid = _ssid_from_ies(pkt, body + 12)
        return {"ssid": ssid} if ssid is not None else None
    if subtype in (13, 14) and body < n:  # action
        return {"category": _named(pkt[body], _ACTION_CATEGORIES)}
    return None


def parse_frame(pkt: bytes) -> Optional[dict]:
    """
    Dissect any 802.11 frame into a JSON-safe record.

    Returns the named type/subtype, the addresses present for that frame,
    a full radiotap decode, and a decoded ``result`` for the management
    frames that carry one. ``None`` only when the frame control cannot be read.
    """
    rt, rtlen = parse_radiotap_full(pkt)
    if rtlen == 0 or len(pkt) < rtlen + 2:
        return None
    fc = struct.unpack_from("<H", pkt, rtlen)[0]
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    type_name = _TYPE_NAMES.get(ftype, "unknown")
    sub_name = subtype_name(ftype, subtype)

    rec: dict = {
        "type": type_name,
        "subtype": subtype,
        "kind": f"{type_name}/{sub_name}",
    }
    to_ds = bool(fc & 0x0100)
    from_ds = bool(fc & 0x0200)
    if to_ds:
        rec["to_ds"] = True
    if from_ds:
        rec["from_ds"] = True
    if fc & 0x0800:
        rec["retry"] = True
    if fc & 0x4000:
        rec["protected"] = True

    a1 = _mac(pkt, rtlen + 4)
    if a1:
        rec["addr1"] = a1
    if ftype in (0, 2) or (ftype == 1 and subtype in _CTRL_HAS_ADDR2):
        a2 = _mac(pkt, rtlen + 10)
        if a2:
            rec["addr2"] = a2
    if ftype in (0, 2):
        a3 = _mac(pkt, rtlen + 16)
        if a3:
            rec["addr3"] = a3
    if ftype == 2 and to_ds and from_ds:
        a4 = _mac(pkt, rtlen + 24)
        if a4:
            rec["addr4"] = a4

    if ftype == 0:
        result = _mgmt_result(subtype, pkt, rtlen + 24)
        if result:
            rec["result"] = result

    rec["radiotap"] = rt
    return rec


class FrameLog:
    """
    Collect per-frame records during a capture window.

    Keeps exact per-kind counts for every frame seen. The returned record list
    is capped at ``max_frames`` so a busy capture stays a summary; ``0`` returns
    no records (counts only), and a negative value means no cap (every frame is
    returned). Frame timestamps are reported relative to the first frame.
    """

    def __init__(self, max_frames: int = DEFAULT_MAX_FRAMES) -> None:
        self.max_frames = max_frames
        self.frames: List[dict] = []
        self.counts: Dict[str, int] = {}
        self.total = 0
        self.truncated = False
        self._t0: Optional[float] = None

    def add(self, record: dict, ts: Optional[float] = None) -> None:
        self.total += 1
        kind = record.get("kind", "unknown")
        self.counts[kind] = self.counts.get(kind, 0) + 1
        # A negative cap means "keep everything"; 0 keeps nothing.
        if self.max_frames >= 0 and len(self.frames) >= self.max_frames:
            self.truncated = True
            return
        record["n"] = self.total
        if ts is not None:
            if self._t0 is None:
                self._t0 = ts
            record["t"] = round(ts - self._t0, 6)
        self.frames.append(record)

    def to_result(self) -> dict:
        return {
            "frames": self.frames,
            "frame_total": self.total,
            "frames_returned": len(self.frames),
            "frames_truncated": self.truncated,
            "frame_types": dict(
                sorted(self.counts.items(), key=lambda kv: (-kv[1], kv[0]))
            ),
        }


# ---------------------------------------------------------------------------
# Scan table (the AP summary)
# ---------------------------------------------------------------------------


class ScanTable:
    """BSSID-keyed merge of everything seen during one capture window."""

    def __init__(self) -> None:
        self.aps: Dict[str, ApInfo] = {}
        self.other = 0

    def update(self, ap: ApInfo) -> None:
        existing = self.aps.get(ap.bssid)
        if existing is None:
            ap.count = 1
            ap.last_seen = time.monotonic()
            self.aps[ap.bssid] = ap
            return
        existing.count += 1
        existing.last_seen = time.monotonic()
        if ap.ssid and ap.ssid != HIDDEN_SSID:
            existing.ssid = ap.ssid
        if ap.channel:
            existing.channel = ap.channel
        if ap.signal is not None:
            existing.signal = ap.signal
        if ap.txpower is not None:
            existing.txpower = ap.txpower
        if ap.country:
            existing.country = ap.country
        if ap.security != "Open":
            existing.security = ap.security
        if ap.rsn:
            existing.rsn = ap.rsn
        if ap.wpa:
            existing.wpa = ap.wpa
        if ap.bss_load:
            existing.bss_load = ap.bss_load
        existing.phy |= ap.phy

    def to_result(self) -> List[dict]:
        """JSON-safe AP rows, strongest signal first within each channel."""
        rows = sorted(
            self.aps.values(),
            key=lambda a: (
                a.channel or 999,
                -(a.signal if a.signal is not None else -999),
            ),
        )
        out = []
        for a in rows:
            detail = a.rsn or a.wpa or {}
            load = a.bss_load or {}
            out.append(
                {
                    "bssid": a.bssid,
                    "ssid": a.ssid,
                    "channel": a.channel,
                    "signal_dbm": a.signal,
                    "security": a.security,
                    "akm": detail.get("akm_suites", []),
                    "pairwise_ciphers": detail.get("pairwise_ciphers", []),
                    "group_cipher": detail.get("group_cipher"),
                    "pmf": _pmf_label(detail.get("pmf")),
                    "phy": phy_label(a),
                    "tx_power": a.txpower,
                    "country": a.country,
                    "stations": load.get("stations"),
                    "channel_utilization": load.get("channel_utilization"),
                    "frames_seen": a.count,
                }
            )
        return out
