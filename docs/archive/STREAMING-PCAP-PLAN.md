# Implementation brief: streaming pcap (capture WebSocket) tools for wlanpi-mcp

**Audience:** an Opus 5 coding agent implementing this from a cold start. This brief is
self-contained — it names every file, the protocol, the reference source, and the decisions
already made, so you should not need to re-derive the design. Read the two reference documents
below once before writing code, then follow the file-by-file plan.

## Context / why

wlanpi-mcp is a thin MCP bridge to the wlanpi-core REST API (`http://localhost:31415`);
per `CLAUDE.md` it runs no local subprocesses and reads no local files — every capability goes
through a core endpoint. wlanpi-core's `integration/mcp-prague` branch now ships a finished,
tested **Wi-Fi packet-capture** capability, but it is **not REST** — it is a single WebSocket.
This task adds capture tools to wlanpi-mcp that consume that WebSocket. Consuming a core
WebSocket is still within the "core-API-only, no local subprocess/file" spirit of the project;
`CLAUDE.md` must be amended to say so (see Modified files).

**Reference material (read before coding):**
- `~/source/wlanpi-core/docs/capture-ws-mcp-handover.md` — the integration spec written *for
  this task*. Authoritative on protocol, ownership model, own-vs-subscribe, TLS, and the
  single-radio hop caveat. When this brief and the handover disagree, the handover wins.
- `~/source/wlanpi-core/tools/capture_harness/capture_harness.py` — a 730-line working
  reference client (stdlib + `websockets`). Its `PcapngReader`, `parse_radiotap`,
  `parse_beacon`, `_rsn_security`, `ScanTable`, `channel_to_freq`/`freq_to_channel`, and
  `phy_label` are the **drop-in source** you vendor and adapt. `run_owner`/`run_subscriber`/
  `run_list`/`_authenticate`/`_consume`/`_find_sessions` are the flows you translate into tools.

**Branch state:** work is on `feature/streaming-pcap` (already created off `upstream/main`).
The prior wlan_scan WIP is stashed (`git stash list` shows it) — do not disturb it.

## Decisions already made (do not re-litigate)

1. **Tool set (full):** `capture_scan`, `capture_observe`, `list_capture_sessions`,
   `get_capture_channels`. No `capture_frames` in v1.
2. **Busy interface:** when `capture_scan`'s target interface is already owned by another
   session (would fail `INTERFACE_IN_USE`), **auto-subscribe** to that session and return the
   same AP summary with `role: "subscriber"` — one tool call always yields data. Role is always
   explicit in the result.
3. **Dissector:** **vendor** the harness parser (stdlib `struct` only, ~350 lines) into a new
   `wlanpi_mcp/capture/` package. Do **not** add scapy/dpkt. The only new dependency is
   `websockets`.

## Protocol reference (from the handover — implement exactly)

- WS URL: `ws://<host>:31415/api/v1/streaming/capture` (derive from `Settings.WLANPI_CORE_URL`:
  `http→ws`, `https→wss`, keep host/port, set that path). On-box loopback needs no TLS.
- **First** client→server message MUST be `{"command":"auth","token":"<core JWT>"}`. Server
  replies text event `AUTH_OK` (`data.did`) or closes with code **4401** (failure / 10 s timeout
  / token-in-URL). **Never** put the token in the query string.
- Subsequent commands (JSON text): `get_supported_frequencies {}`, `configure
  {"interfaces": {"wlanpiN": {"channels": [{"freq": 2412, "width": 20}], "dwell_time": 250}}}`
  (`width`∈{20,40,80,160}, `dwell_time` 50–60000 ms), `start {"interfaces": ["wlanpiN"],
  "pcap_filter": ""}`, `stop {}` (owner only), `subscribe {"session_id": "cap_xxxx"}`,
  `unsubscribe {}`, `list_sessions {}`.
- Interface names are monitor-mode **`wlanpiN`**, not `wlan0`. MCP passes the interface; core
  resolves its network namespace itself.
- Server→client: **binary frames** = pcapng bytes, arriving in **unaligned chunks** (buffer and
  parse incrementally; a new SHB can appear mid-stream → reset interface numbering).
  **Text events** = `{"type","event","code","data"}`. Codes to handle: `AUTH_OK`,
  `CAPTURE_STARTED` (`data.session_id`, `data.interfaces`), `CHANNEL_SET` (hop spam; count it),
  `CHANNEL_SET_FAILED` (`data.message` has the `iw` reason — surface it), `SUBSCRIBED`
  (`data.owner`, `data.namespace`, `data.config`), `SESSIONS` (`data.sessions`),
  `CAPTURE_STOPPED`/`CAPTURE_ENDED` (stop consuming), and `event:"error"` codes
  (`AUTH_FAILED`, `INTERFACE_IN_USE`, `SESSION_NOT_FOUND`, `CONFIG_INVALID`,
  `INTERFACE_NOT_AVAILABLE`).
- **Ownership:** a capture lives with its owning socket; closing the socket stops it. Never leave
  an ownerless background capture. Owner flows MUST `stop` and close the socket in a `finally`.
  Any authenticated socket may `subscribe` read-only; `SUBSCRIBED` returns the owner's config so
  a subscriber is never blind.
- **Every capture result MUST state its role** (`"owner"`/`"subscriber"`) plus `session_id` and
  the running `config`.
- **Single-radio caveat (handover §7):** where the capture phy is shared with managed `wlan0`,
  channel hops fail with `Device or resource busy (-16)` while `wlan0` scans; core retries once
  then emits `CHANNEL_SET_FAILED`. Surface these in the result and mention the caveat in tool
  docstrings — do not present a silent partial capture as complete.

## Existing conventions to match (study these files first)

- `wlanpi_mcp/tools/wifi.py` — canonical tool module: top-level `register(mcp, client)`
  containing `@mcp.tool()`-decorated async closures. Docstrings ARE the LLM-facing tool
  descriptions. Add capture as a new module in the same shape.
- Tools **return `{"error": "..."}` dicts, never raise** — the LLM client needs readable text.
  Wrap connect/auth/start failures into error dicts.
- `wlanpi_mcp/client/core_client.py` — token resolution rule: `get_token()` (contextvar set by
  the SSE bearer middleware) else `Settings.WLANPI_CORE_TOKEN` (stdio fallback), else a
  RuntimeError. The WS client MUST reuse this exact rule. `_current_token()` is private; add a
  public `current_token()` wrapper and pass it into the WS layer (do not duplicate the logic).
- `wlanpi_mcp/server.py` — every module is wired via `<module>.register(mcp, client)`. Add the
  capture module there.
- `wlanpi_mcp/config.py` — `Settings` (pydantic-settings). `WLANPI_CORE_URL` is the base you
  derive the WS URL from.
- `tests/test_tools_gaps.py` — the tool-test pattern: a local `_register(module)` builds a
  `FastMCP("test")`, calls `module.register` with a mocked client, and returns
  `mcp._tool_manager._tools` (tool closures reachable via `tools["name"].fn(...)`).
- `tests/conftest.py` — `settings`, `bearer_token` (sets the `current_token` contextvar),
  `client` fixtures. `asyncio_mode=auto` (no `@pytest.mark.asyncio` needed, though existing
  tests sometimes add it).

## New files

### `wlanpi_mcp/capture/__init__.py`
Empty package marker (or re-export the public names).

### `wlanpi_mcp/capture/pcapng.py`
Vendor `PcapngReader` from the harness verbatim in behavior: `feed(bytes) -> list[(linktype,
packet_bytes)]`, buffering unaligned chunks; handle SHB (endianness + interface-numbering reset),
IDB (linktype table), EPB (extract caplen packet), and desync recovery (drop one byte, re-find a
block). Add a module docstring noting provenance: *adapted from wlanpi-core
tools/capture_harness/capture_harness.py.*

### `wlanpi_mcp/capture/dot11.py`
Vendor from the harness: `channel_to_freq`, `freq_to_channel`, `parse_radiotap` (first
present-word → freq/signal/txpower), `_rsn_security`, `@dataclass ApInfo`, `parse_beacon`
(beacon/probe-resp → SSID/BSSID/channel/signal/security/phy-set{n,ac,ax,be}/TPC txpower/country),
`phy_label`, and `ScanTable` (BSSID-keyed merge). **Add** `ScanTable.to_result() -> list[dict]`
returning JSON-safe AP dicts — keys `bssid, ssid, channel, signal_dbm, security, phy (=phy_label),
tx_power, country, frames_seen` — sorted by `(channel, -signal)`. Tools return this; never raw
pcap. Same provenance docstring.

### `wlanpi_mcp/capture/ws_client.py`
Async protocol driver, built for testability:
- `capture_ws_url(settings) -> str` — derive ws/wss URL from `Settings.WLANPI_CORE_URL`.
- `async def connect_capture(settings) -> CaptureSocket` — `websockets.connect(url,
  max_size=None)` and wrap in `CaptureSocket`. Keep this the single seam tests monkeypatch.
- `class CaptureSocket` wrapping an injected object exposing async `send(str)` / `recv()` (so a
  test can pass a scripted stub with queued messages, no real socket). Methods:
  - `authenticate(token)` — send auth FIRST; wait for `AUTH_OK` (return `did`); on
    `AUTH_FAILED` / 4401 close / 10 s timeout raise a typed `CaptureError` with a clean message.
  - `list_sessions()`, `get_supported_frequencies()` — send command, await matching event,
    return `data`.
  - `configure(interfaces_cfg)` + `start(interfaces, pcap_filter)` → await `CAPTURE_STARTED`
    (return `session_id`) or raise `CaptureError` carrying the error `code` (so callers branch on
    `INTERFACE_IN_USE`, `CONFIG_INVALID`, `INTERFACE_NOT_AVAILABLE`).
  - `subscribe(session_id)` → await `SUBSCRIBED`, return `{owner, namespace, config}`;
    `SESSION_NOT_FOUND` → `CaptureError`.
  - `consume(reader, table, duration_s)` — bounded loop: binary → `reader.feed` →
    `parse_beacon` → `table.update`; text events collected — record `CHANNEL_SET_FAILED`
    `{freq/message}`, count `CHANNEL_SET`, and return early on `CAPTURE_ENDED`/`CAPTURE_STOPPED`.
    Return an events summary (`channel_issues`, `other_frames`).
  - `stop()` — best-effort; owner flows call it in `finally`.
- Define `class CaptureError(Exception)` with an optional `.code`.

### `wlanpi_mcp/tools/capture.py`
`register(mcp, client)` with four `@mcp.tool()` async closures. Each wraps its whole body so any
`CaptureError`/connect failure/timeout returns `{"error": "..."}`. Reuse the client's token via
`client.current_token()`. Docstrings (LLM-facing) MUST say: interfaces are monitor-mode
`wlanpiN` (discover via `get_network_interfaces`); results are summaries, not raw pcap; and the
single-radio hop caveat. Tools:

1. `capture_scan(interface="wlanpi0", channels=None, width=20, dwell_ms=250, duration_s=10, pcap_filter="")`
   — owner flow (handover Shape A). Connect+auth; `list_sessions` pre-flight. If a running
   session covers `interface` → auto-subscribe, consume `duration_s`, return
   `{"role":"subscriber","session_id","owner","config","aps",...}`. Else build config (if
   `channels is None`, call `get_supported_frequencies` and hop supported channels; else map
   channel numbers via `channel_to_freq`), `configure`+`start`, consume, then `stop`+close in
   `finally`. Return `{"role":"owner","session_id","config","aps":[...],"other_frames":N,
   "channel_issues":[...]}` (add a single-radio hint when `channel_issues` non-empty). Clamp
   `duration_s` default 10, max 60 (the call blocks for the whole window).
2. `capture_observe(interface=None, session_id=None, duration_s=10)` — subscriber flow (Shape B).
   Resolve session: explicit `session_id`; else match `interface` in `list_sessions`; else the
   sole running session (error dict if none / ambiguous). `subscribe`, consume bounded, return
   `{"role":"subscriber","session_id","owner","namespace","config","aps",...}`. Never `stop`.
3. `list_capture_sessions()` — auth + `list_sessions`; return the sessions verbatim.
4. `get_capture_channels()` — auth + `get_supported_frequencies`; return per-adapter supported
   channels, annotating each freq with its channel number via `freq_to_channel`.

## Modified files

- `pyproject.toml` — add `"websockets>=12"` to `[project].dependencies`. (dh-virtualenv reads
  deps from here; no `debian/` change needed.)
- `wlanpi_mcp/server.py` — import `capture` from `wlanpi_mcp.tools` and add
  `capture.register(mcp, client)` alongside the other tool registrations.
- `wlanpi_mcp/client/core_client.py` — add `def current_token(self) -> str: return
  self._current_token()` (public wrapper) so the WS layer reuses the token rule.
- `CLAUDE.md` — amend the "thin bridge to the REST API / no local subprocesses" paragraph to
  state the bridge also consumes core's capture **WebSocket** (still core-API-only), and document
  the `wlanpi_mcp/capture/` package with its vendored-from-`capture_harness` provenance.

## Tests (new files, mirror `tests/test_tools_gaps.py`)

- `tests/test_capture_pcapng.py` — synthetic SHB/IDB/EPB blocks built with `struct`: packet
  extraction across unaligned chunk splits, linktype mapping, mid-stream SHB reset, desync
  recovery.
- `tests/test_capture_dot11.py` — hand-crafted radiotap+beacon fixtures: field extraction; RSN →
  WPA2-PSK / WPA3 / WPA2-Ent / WPA2/3; WPA vendor IE → WPA; privacy bit → WEP; hidden SSID; HE/EHT
  extension IEs; `ScanTable` merge + `to_result()` shape/sort.
- `tests/test_capture_tools.py` — use the `_register()` pattern; drive `CaptureSocket` with a
  scripted stub ws (queued recv: `AUTH_OK` → `SESSIONS` → `CAPTURE_STARTED` → binary pcapng →
  `CHANNEL_SET_FAILED` → `CAPTURE_ENDED`) by monkeypatching `connect_capture`. Cover: auth sent
  first; auth failure → error dict; owner happy path reports `role:"owner"` and calls `stop` on
  exit **including on exception**; busy interface → auto-subscribe → `role:"subscriber"` + owner
  config; `capture_observe` resolution (explicit id / by interface / sole / none→error);
  `channel_issues` surfaced; token fallback (contextvar vs `WLANPI_CORE_TOKEN`).

## Verification

1. `pip install -e ".[testing]"` (pulls `websockets`); `pytest` — full suite green.
2. Live check against a device on the `integration/mcp-prague` core build:
   `WLANPI_CORE_TOKEN=$(sudo getjwt … access_token) WLANPI_CORE_URL=http://<device>:31415 \
   python -m wlanpi_mcp --transport stdio`, then exercise `get_capture_channels` →
   `capture_scan(interface="wlanpi0", duration_s=10)` → `list_capture_sessions`; with the harness
   owning a capture, `capture_observe`.
3. On-box-auth risk: the localhost-HMAC-rejects-JWT issue is fixed on prague by credential-based
   dispatch (core commit `c67070c`); against older core use the LAN-IP `WLANPI_CORE_URL`
   workaround (see the `wlanpi-core-localhost-hmac` memory).

## Out of scope (handover §8)
Durable/detached captures, per-stream subscriber ACLs, revocation tearing down live streams,
`capture_frames`.
