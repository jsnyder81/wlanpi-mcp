# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An MCP (Model Context Protocol) server that exposes WlanPi capabilities — device info, service management, Wi-Fi scanning, profiler, Bluetooth, VLANs, packet capture — to AI assistants. It is mostly a thin bridge to the `wlanpi-core` REST API on `http://localhost:31415`; the exception is packet capture, which runs `dumpcap`/`tshark` subprocesses directly on the device.

## Commands

```bash
# Setup (Python >= 3.11)
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

`asyncio_mode = auto` is set in pyproject.toml, so async tests don't need `@pytest.mark.asyncio`. There is no lint/format tooling configured.

## Architecture

- `wlanpi_mcp/server.py` — `create_server()` builds the FastMCP instance and wires every module in. All tool/resource/prompt modules follow the same pattern: a top-level `register(mcp, client)` function containing `@mcp.tool()` / `@mcp.resource()` decorated closures. Adding a capability = new module in `tools/` or `resources/` + a `register()` call in `server.py`. The "Phase 1/2/3" comments reflect the order features were built, nothing more.
- `wlanpi_mcp/client/core_client.py` — `CoreClient`, the single async httpx client for wlanpi-core. Module-level singleton via `init_client()`/`get_client()`, created in `__main__.py` and passed to `register()` functions.
- `wlanpi_mcp/config.py` — pydantic-settings `Settings`, loaded from environment or `/etc/wlanpi-mcp/config.env`. Also holds `ALLOWED_SERVICES`, the allowlist that gates `start_service`/`stop_service`/`restart_service`. `ALLOW_POWER_CONTROL` (default true) gates `reboot_device`/`shutdown_device`.
- `wlanpi_mcp/tools/capture.py` — packet capture is local subprocess work, not a wlanpi-core call. Sessions live in the module-level `_sessions` dict (session_id → dumpcap process + pcap path), which is in-memory and per-process. `resources/capture.py` imports that same `_sessions` to serve the raw PCAP as a binary MCP resource at `capture://sessions/{session_id}/pcap`.

### Authentication: JWT passthrough (deliberate design — do not add server-side auth)

This server implements **no authentication of its own**. The MCP client presents a JWT issued by wlanpi-core (`POST /api/v1/auth/token`) as `Authorization: Bearer <token>`, and that same token is passed through on every outbound wlanpi-core API call, where it is validated. This forces all MCP access through wlanpi-core's token system, even onbox.

The flow: `middleware/bearer_token.py` (SSE mode, always installed) rejects tokenless connections with 401 and stashes the Bearer token in the `auth/token_context.py` contextvar; `CoreClient._request` reads it back and forwards it. It's pure ASGI middleware (not `BaseHTTPMiddleware`) on purpose — the SSE session loop and its tool-call tasks run in the same task tree as the `GET /sse` request, so the contextvar set there is visible during tool execution. Note the token used for API calls is the one from the SSE connection, not the per-message POSTs.

The server never mints, verifies, refreshes, or caches tokens. A 401 from wlanpi-core (expired/revoked token) propagates back to the MCP client as a tool error — there is no retry, since the server doesn't own the token and can't refresh it. This applies mid-session too: if the token expires while an SSE session is open, tool calls start failing with 401 until the client reconnects with a fresh token. Stdio mode has no HTTP headers, so `WLANPI_CORE_TOKEN` in config/env is the fallback token source there.

Tests for this live in `tests/test_auth.py` (middleware: 401 on missing/non-Bearer token, contextvar propagation and reset) and `tests/test_client.py` (token forwarding, 401 passthrough without retry, missing-token error, stdio fallback).

### Tool conventions

Tools return error dicts (`{"error": "..."}`) rather than raising, so the LLM client gets a readable message. Read-heavy resources in `resources/` use a small module-level TTL cache (`_cached_get`). Docstrings on tool functions are the MCP tool descriptions shown to the model — write them for an LLM consumer.

## Deployment

Ships as a Debian package (`debian/`) built with dh-virtualenv into `/opt/wlanpi-mcp`, depends on `wlanpi-core`, and runs as the `wlanpi` user via the systemd unit in `install/lib/systemd/system/wlanpi-mcp.service` (SSE transport, config from `/etc/wlanpi-mcp/config.env`, example in `install/etc/wlanpi-mcp/config.env.example`).
