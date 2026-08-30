# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An MCP (Model Context Protocol) server that exposes WLAN Pi capabilities - device info, service management, Wi-Fi scanning, packet capture, profiler, Bluetooth, VLANs - to AI assistants. It is a thin bridge to the `wlanpi-core` API on `http://localhost:31415`: every tool and resource goes through that API, and nothing runs local subprocesses or reads local files. Keep it that way - if a capability has no wlanpi-core endpoint, the endpoint gets added upstream first.

Almost all of that API is REST. The one exception is **packet capture**, which wlanpi-core exposes only as a WebSocket (`/api/v1/streaming/capture`) - so `wlanpi_mcp/capture/` speaks that protocol instead of HTTP. That is still core-API-only: same host, same JWT, still no local subprocess and no local file. Do not read this as licence to add other non-core transports.

## Commands

```bash
# Setup (Python >= 3.13)
pip install -e ".[testing]"

# Run all tests / one file / one test
pytest
pytest tests/test_auth.py
pytest tests/test_auth.py::test_passes_token_to_downstream_context

# Run the server locally
python -m wlanpi_mcp --transport stdio   # default; direct MCP client invocation
python -m wlanpi_mcp --transport sse     # HTTP daemon mode (uvicorn), how systemd runs it

# Build the Debian package (dh-virtualenv, installs to /opt/wlanpi-mcp)
dpkg-buildpackage -us -uc
```

`asyncio_mode = auto` is set in pyproject.toml, so async tests don't need `@pytest.mark.asyncio`. Lint and format tooling is configured via tox (`tox -e lint`, `tox -e formatcheck`, `tox -e format`) using flake8/black/isort/autoflake.

## Architecture

- `wlanpi_mcp/server.py` - `create_server()` builds the FastMCP instance and wires every module in. All tool/resource/prompt modules follow the same pattern: a top-level `register(mcp, client)` function containing `@mcp.tool()` / `@mcp.resource()` decorated closures. Adding a capability = new module in `tools/` or `resources/` + a `register()` call in `server.py`. The "Phase 1/2/3" comments reflect the order features were built, nothing more.
- `wlanpi_mcp/client/core_client.py` - `CoreClient`, the single async httpx client for wlanpi-core. Module-level singleton via `init_client()`/`get_client()`, created in `__main__.py` and passed to `register()` functions.
- `wlanpi_mcp/config.py` - pydantic-settings `Settings`, loaded from environment or `/etc/wlanpi-mcp/config.env`. Also holds `ALLOWED_SERVICES`, the allowlist that gates `start_service`/`stop_service`/`restart_service`. `ALLOW_POWER_CONTROL` (default true) gates `reboot_device`/`shutdown_device`.
- `wlanpi_mcp/capture/` - the capture WebSocket client, used by `tools/capture.py`. `ws_client.py` derives the ws/wss URL from `WLANPI_CORE_URL` and drives the protocol (`CaptureSocket`: auth first, then `configure`/`start`/`subscribe`/`list_sessions`/`stop`; `CaptureError` carries core's error code so callers can branch on `INTERFACE_IN_USE`). `pcapng.py` and `dot11.py` are a stdlib-only incremental pcapng reader and radiotap/802.11 dissector **vendored from wlanpi-core `tools/capture_harness/capture_harness.py`** - keep them in sync with that reference rather than growing a parallel dissector, and do not pull in scapy/dpkt. The dissector has since been extended past the harness on purpose (the pcapng reader also yields a per-frame timestamp; `dot11.py` adds full radiotap decode, all frame type/subtype names, per-frame source/dest addresses, decoded management results, full RSN/WPA AKM/cipher/PMF detail, and the QBSS/BSS Load element) - these extensions are ours, so re-sync the *shared* parsing logic without dropping them. Capture tools return dissected summaries, never raw pcap: two views come out of the same frames - an AP table (`ScanTable.to_result()`, one row per BSSID with the compact security label plus full `akm`/`pairwise_ciphers`/`group_cipher`/`pmf`, and `stations`/`channel_utilization` from the QBSS Load element when present) and a per-frame log (`FrameLog`, exact per-kind counts always, plus up to `max_frames` records carrying addresses, radiotap and any decoded result). The per-frame record list is capped (`max_frames`, 0 disables it) precisely so a busy capture stays a summary and never becomes a text pcap.

Capture ownership matters: a capture lives with its WebSocket, so closing the socket stops it. Owner flows must `stop()` and close in a `finally` - never leave an ownerless capture on the device - and every capture result states its `role` (`owner`/`subscriber`), `session_id` and running `config`. `capture_scan` auto-subscribes when the interface is already owned by another session. `CHANNEL_SET_FAILED` events are non-fatal and are surfaced in `channel_issues`: on single-radio devices, hops fail while the managed `wlan0` scans, and a partial capture must not be reported as complete.
### Authentication: JWT passthrough (deliberate design - do not add server-side auth)

This server implements **no authentication of its own**. The MCP client presents a JWT issued by wlanpi-core (`POST /api/v1/auth/token`) as `Authorization: Bearer <token>`, and that same token is passed through on every outbound wlanpi-core API call, where it is validated. This forces all MCP access through wlanpi-core's token system, even onbox.

The flow: `middleware/bearer_token.py` (SSE mode, always installed) rejects tokenless connections with 401 and stashes the Bearer token in the `auth/token_context.py` contextvar; `CoreClient._request` reads it back and forwards it. It's pure ASGI middleware (not `BaseHTTPMiddleware`) on purpose - the SSE session loop and its tool-call tasks run in the same task tree as the `GET /sse` request, so the contextvar set there is visible during tool execution. Note the token used for API calls is the one from the SSE connection, not the per-message POSTs.

The server never mints, verifies, refreshes, or caches tokens. A 401 from wlanpi-core (expired/revoked token) propagates back to the MCP client as a tool error - there is no retry, since the server doesn't own the token and can't refresh it. This applies mid-session too: if the token expires while an SSE session is open, tool calls start failing with 401 until the client reconnects with a fresh token. Stdio mode has no HTTP headers, so `WLANPI_CORE_TOKEN` in config/env is the fallback token source there.

The capture WebSocket uses the same token by the same rule, via the public `CoreClient.current_token()` wrapper - core requires it as the **first** message (`{"command":"auth","token":...}`) and closes with 4401 if it is missing, invalid, or put in the URL query string. Never place the token in the WebSocket URL.

Tests for this live in `tests/test_auth.py` (middleware: 401 on missing/non-Bearer token, contextvar propagation and reset) and `tests/test_client.py` (token forwarding, 401 passthrough without retry, missing-token error, stdio fallback).

### Tool conventions

Tools return error dicts (`{"error": "..."}`) rather than raising, so the LLM client gets a readable message. Read-heavy resources in `resources/` use a small module-level TTL cache (`_cached_get`). Docstrings on tool functions are the MCP tool descriptions shown to the model - write them for an LLM consumer.

## Deployment

Ships as a Debian package (`debian/`) built with dh-virtualenv into `/opt/wlanpi-mcp`, depends on `wlanpi-core`, and runs as the `wlanpi` user via the systemd unit in `install/lib/systemd/system/wlanpi-mcp.service` (SSE transport, config from `/etc/wlanpi-mcp/config.env`, example in `install/etc/wlanpi-mcp/config.env.example`).
