# wlanpi-mcp

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that exposes [WLAN Pi](https://wlanpi.com) capabilities — device info, service management, Wi-Fi scanning, profiler control, Bluetooth, and VLANs — to AI assistants like Claude.

It is a thin bridge to the `wlanpi-core` REST API on the device (`http://localhost:31415`); every tool call goes through that API.

## How it runs

Two transports:

- **SSE (daemon mode)** — how the Debian package runs it under systemd: an HTTP server on port `8766` that remote MCP clients connect to at `http://<wlanpi>:8766/sse`. Every connection **must** present a wlanpi-core JWT (see [Authentication](#authentication)).
- **stdio** — the MCP client launches the server as a subprocess. Only useful when the client runs on the WLAN Pi itself.

## Installation on the WLAN Pi

Install the Debian package (depends on `wlanpi-core`):

```bash
sudo apt install ./wlanpi-mcp_*.deb
```

This installs to `/opt/wlanpi-mcp`, enables the `wlanpi-mcp` systemd service (SSE mode on port 8766), and reads configuration from `/etc/wlanpi-mcp/config.env` (see `install/etc/wlanpi-mcp/config.env.example`).

To build the package from source: `dpkg-buildpackage -us -uc`.

## Authentication

This server implements **no authentication of its own** — by design. Your MCP client presents a JWT issued by wlanpi-core as `Authorization: Bearer <token>`, and that same token is forwarded on every wlanpi-core API call, where it is validated (signature, expiry, revocation). The MCP server never mints, verifies, or refreshes tokens; if the token expires mid-session, tool calls fail with 401 until the client reconnects with a fresh one.

### Generating a token with `getjwt`

The easiest way to get a token is the `getjwt` helper that ships with wlanpi-core. SSH to the WLAN Pi and run:

```bash
sudo getjwt claude-desktop --no-color
```

The positional argument is a device ID — an arbitrary name identifying the client the token is for (e.g. `claude-desktop`, `claude-code`). `sudo` is needed because `getjwt` signs the request with wlanpi-core's local HMAC shared secret, which unprivileged users can't read. `--no-color` gives clean output for copy/paste or scripting.

It prints the token response:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

Use the `access_token` value as your Bearer token in the client configs below. Tokens expire (7 days by default in wlanpi-core) — when tool calls start failing with 401, generate a fresh token and update your client config.

Alternatively, call `POST /api/v1/auth/token` yourself — see the wlanpi-core API docs (Swagger UI at `http://<wlanpi>:31415/docs`) for the HMAC signing details.

The full flow, including the nginx `X-Real-IP` handling that makes on-box calls take core's JWT validation path, is documented in [docs/auth-flow.md](docs/auth-flow.md).

## Connecting Claude Code

On any machine that can reach the WLAN Pi:

```bash
claude mcp add --transport sse wlanpi http://<wlanpi-ip>:8766/sse \
  --header "Authorization: Bearer <your-wlanpi-core-jwt>"
```

Then verify with `/mcp` inside Claude Code — the `wlanpi` server should show as connected, with its tools and resources listed.

To share the config with your whole project (checked into `.mcp.json`) add `--scope project`; the default scope is local to you.

### Claude Code running on the WLAN Pi itself (stdio)

If Claude Code runs on the device, you can skip the HTTP hop and launch the server over stdio. There are no HTTP headers in stdio mode, so the token comes from the `WLANPI_CORE_TOKEN` environment variable instead:

```bash
claude mcp add wlanpi \
  --env WLANPI_CORE_TOKEN=<your-wlanpi-core-jwt> \
  -- /opt/wlanpi-mcp/bin/python -m wlanpi_mcp --transport stdio
```

(Use your own interpreter path instead of `/opt/wlanpi-mcp/bin/python` if you installed from source with pip.)

## Connecting Claude Desktop

Claude Desktop launches stdio servers, so a remote SSE server is bridged with the [`mcp-remote`](https://www.npmjs.com/package/mcp-remote) proxy (requires Node.js on your desktop machine).

Edit your Claude Desktop config file:

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wlanpi": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote",
        "http://<wlanpi-ip>:8766/sse",
        "--transport", "sse-only",
        "--allow-http",
        "--header", "Authorization: Bearer ${WLANPI_TOKEN}"
      ],
      "env": {
        "WLANPI_TOKEN": "<your-wlanpi-core-jwt>"
      }
    }
  }
}
```

Notes:

- `--allow-http` is required because the server is plain HTTP on your LAN. Only do this on a network you trust — the token travels in cleartext.
- `--transport sse-only` skips mcp-remote's streamable-HTTP probe; this server speaks SSE.
- The token is passed via the `env` block and interpolated into the header (`${WLANPI_TOKEN}`) — this sidesteps a known mcp-remote issue with spaces in `args` values on some platforms.

Restart Claude Desktop after editing the file. The WlanPi tools appear under the tools (🔨) menu.

## Configuration

Settings load from the environment or `/etc/wlanpi-mcp/config.env`:

| Variable | Default | Purpose |
|---|---|---|
| `WLANPI_CORE_URL` | `http://localhost:31415` | wlanpi-core API base URL |
| `WLANPI_CORE_TOKEN` | *(empty)* | Fallback JWT for **stdio mode only**; leave empty in SSE mode |
| `WLANPI_MCP_HOST` | `0.0.0.0` | SSE bind host |
| `WLANPI_MCP_PORT` | `8766` | SSE bind port |
| `ALLOW_POWER_CONTROL` | `true` | Set `false` to disable the `reboot_device`/`shutdown_device` tools |
| `LOG_LEVEL` | `INFO` | Logging level |

Service management tools (`start_service`, `stop_service`, `restart_service`) are restricted to the allowlist in `wlanpi_mcp/config.py` (`ALLOWED_SERVICES`).

## What's exposed

- **Tools** — system/power control, network interface queries, WLAN/Wi-Fi scanning, VLAN config, profiler control, Bluetooth, network config profiles, regulatory domain, device mode, and diagnostics utilities.
- **Resources** — read-oriented views of device info, network state, services, Bluetooth, profiler results, network configs, and device mode.
- **Prompts** — guided diagnostics workflows.

Connect a client and list tools/resources for the full, current inventory.

## Development

Requires Python ≥ 3.11.

```bash
pip install -e ".[testing]"
pytest                                    # run tests
python -m wlanpi_mcp --transport stdio    # run locally (stdio)
python -m wlanpi_mcp --transport sse      # run locally (SSE on :8766)
```

## License

BSD-3-Clause
