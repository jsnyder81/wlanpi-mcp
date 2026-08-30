# Migration plan: `mcp[cli]` bundled FastMCP → standalone FastMCP v3

## Context / why

wlanpi-mcp is built on the FastMCP that ships **inside the official MCP SDK**
(`mcp[cli]`, imported as `from mcp.server.fastmcp import FastMCP`). That bundled
FastMCP is the v1-lineage API and is now effectively in maintenance — active
FastMCP development happens in the standalone **PrefectHQ/fastmcp** package,
which reached **v3.0.0 (stable)**. Moving to standalone fastmcp v3 buys the
modern transport (Streamable HTTP — the current MCP spec transport; SSE is
deprecated), a native middleware/transform architecture, and ongoing features
(structured tool output, resource security, cache hints).

This is a **package swap, not a version bump**: the dependency changes from
`mcp[cli]` to `fastmcp>=3` (fastmcp still depends on `mcp` underneath, so
`mcp.types` and friends remain importable), and imports move from
`mcp.server.fastmcp` to `fastmcp`.

Two facts make this non-trivial and shape the phasing below:
- **The bearer-token middleware is coupled to the SSE transport's internals.**
  `middleware/bearer_token.py` deliberately leans on `mcp/server/sse.py`
  binding `scope["user"]` per session and rejecting later POSTs with a
  different principal (documented in `CLAUDE.md` as the reason it's hand-rolled
  ASGI, not `BaseHTTPMiddleware`). Streamable HTTP has a **different session
  model**, so that per-token session-binding security property does **not**
  carry over for free.
- **The test suite reaches a private internal.** 6 test files use
  `mcp._tool_manager._tools[name].fn` to call tool closures directly. fastmcp
  v3's tool manager is not guaranteed to expose that shape.

Recommendation: **two phases.** Phase 1 lands fastmcp v3 with **zero
client-facing change** (keep SSE, which v3 still supports though discourages).
Phase 2 modernizes the transport to Streamable HTTP as a separate, separately
tested change, because it is both a client-breaking change and the place the
middleware security property must be re-established.

## Current surface (measured)

- `from mcp.server.fastmcp import FastMCP` in **27 files** (all `tools/`,
  `resources/`, `prompts/`, `server.py`, `__main__.py`, `middleware/`, and 5
  test files). `FastMCP` appears 61× — almost all are `mcp: FastMCP` type hints
  on `register(mcp, client)` and `@mcp.tool()` / `@mcp.resource()` decorators,
  which are unchanged in v3.
- `server.py`: `FastMCP(name, instructions=…, host=host, port=port)` — the
  `host`/`port` kwargs are **removed** in v3 (transport config moves to serve
  time).
- `__main__.py`: `mcp.run(transport="stdio")` (unchanged) and the SSE path
  `mcp.sse_app()` → `add_middleware(BearerTokenMiddleware)` → `uvicorn.run(...)`.
- `middleware/bearer_token.py`: imports `mcp.server.auth.middleware.bearer_auth`
  and `mcp.server.auth.provider` (SDK internals, still present under fastmcp v3)
  and depends on SSE session/principal semantics.
- Non-fastmcp SDK imports to keep working: `mcp.server.auth.*` (middleware +
  tests), `mcp.server.sse.SseServerTransport` (tests). These resolve as long as
  `mcp` remains an install dependency of fastmcp — **verify** they aren't moved.

## Phase 1 — swap to fastmcp v3, keep SSE (no client-facing change)

Goal: the server runs on `fastmcp>=3`, the full test suite passes, and MCP
clients still connect exactly as today (SSE on the same path). Nothing about
the deployment or client `mcp.json` changes.

1. **`pyproject.toml`** — replace `"mcp[cli]>=1.0,<2"` with `"fastmcp>=3,<4"`.
   Keep `uvicorn`/`starlette` (still used for the SSE ASGI app + middleware).
   Confirm `mcp` arrives transitively (for the `mcp.server.auth`/`mcp.types`
   imports) — pin `mcp` explicitly if fastmcp's range is looser than we want.
2. **Import rewrite (27 files)** — `from mcp.server.fastmcp import FastMCP` →
   `from fastmcp import FastMCP`. Purely mechanical; the `@mcp.tool()` /
   `@mcp.resource()` / `@mcp.prompt()` decorators and `register(mcp, client)`
   signatures are unchanged. A single `sed` across the tree plus a review pass.
3. **`server.py` constructor** — drop `host=`/`port=` from `FastMCP(...)`. Keep
   `name` and `instructions`. `create_server()` keeps its `host`/`port`
   parameters but stops forwarding them to the constructor (they're already
   passed to uvicorn in `__main__.py`, so nothing else changes). Verify
   `instructions=` is still an accepted kwarg in v3; if renamed, adjust.
4. **`__main__.py` serving** —
   - stdio: `mcp.run(transport="stdio")` is unchanged.
   - SSE: replace `mcp.sse_app()` with v3's SSE ASGI app accessor. v3 keeps SSE
     via `run(transport="sse")`; confirm the ASGI-app form used for custom
     uvicorn + middleware (likely `mcp.sse_app()` retained, else `http_app(
     transport="sse")`). Keep the `add_middleware(BearerTokenMiddleware)` wrap
     and the existing `uvicorn.run(...)` call.
5. **Bearer middleware** — expected to work unchanged *because Phase 1 stays on
   SSE*, so the `mcp/server/sse.py` principal-binding it relies on is still in
   play. **Verify** the two `mcp.server.auth.*` imports still resolve under
   fastmcp v3's dependency, and that v3's SSE app still uses `SseServerTransport`
   with the same `scope["user"]` binding. If v3's SSE app bypasses that binding,
   treat it as a Phase 2 item (re-establish per-token binding) rather than
   shipping Phase 1 with the property silently weakened.
6. **Test accessor (6 files)** — replace `mcp._tool_manager._tools[name].fn`
   with a v3-supported accessor. Preferred: a small local helper in each test
   (or a shared `conftest` helper) that resolves a tool's underlying callable
   via the public API (`await mcp.get_tool(name)` / `list_tools()` then the
   fn/handler attribute — confirm the exact attribute name in v3). This is the
   one test-mechanics change; the assertions themselves stay.
7. **Run the suite** — `pytest` must stay green (currently 126). No behavior
   change is expected; this phase is a substrate swap.

Deliverable of Phase 1: a branch that builds the same Debian package, runs
under the same systemd unit, serves the same SSE endpoint, and passes all tests
— just on fastmcp v3.

## Phase 2 — modernize transport to Streamable HTTP (separate, client-breaking)

Do this only after Phase 1 is reviewed and merged. This is where the real
design work is.

1. **Serving** — `__main__.py` moves the daemon path to `mcp.http_app()` /
   `mcp.run(transport="http", host=…, port=…)`. Decide stateless vs stateful
   HTTP (affects whether per-connection contextvars behave like the SSE session
   loop did).
2. **Re-establish the auth security property** — this is the crux. Under SSE the
   middleware got per-token session binding *for free* from
   `mcp/server/sse.py`. Streamable HTTP's request/session lifecycle is
   different, so we must deliberately re-implement: (a) reject tokenless
   requests with 401 (still straightforward at the ASGI layer), and (b) ensure
   the token captured for a session is the one used for that session's tool
   calls, with no cross-session bleed. Validate the contextvar propagation holds
   under the HTTP task model (the exact concern `CLAUDE.md` flags). Consider
   whether fastmcp v3's **native middleware** (`Middleware` / server middleware)
   is a cleaner home than the hand-rolled ASGI shim — but only if it preserves
   the contextvar-visible-during-tool-execution guarantee; otherwise keep the
   ASGI shim.
3. **Deployment + clients (breaking)** — update
   `install/lib/systemd/system/wlanpi-mcp.service`, the nginx `/mcp` mount plan
   (see the `backlog-nginx-mcp-mount` memory), the config example, and **every
   client `mcp.json`** (endpoint path changes from `/sse` to the Streamable HTTP
   path). Coordinate this as a real rollout, not a silent switch.
4. **Auth tests** — `tests/test_auth.py` currently asserts SSE-transport
   behavior (`SseServerTransport`, principal binding). Rewrite against the HTTP
   session model to prove the same security property by its new mechanism.

## Key risks / verification items (confirm against installed fastmcp v3, not docs)

- **SSE ASGI-app accessor name** in v3 (`sse_app()` vs `http_app(transport=
  "sse")`) — drives Phase 1 step 4.
- **`mcp.server.auth.*` and `mcp.server.sse` still importable** under fastmcp
  v3's pinned `mcp` — the middleware and auth tests depend on them.
- **Tool-manager internals** — the exact public accessor for a tool's callable
  in v3 (Phase 1 step 6).
- **`instructions=` kwarg** still accepted by `FastMCP()` in v3.
- **SSE principal-binding** still provided by v3's SSE app (else it's a Phase 2
  security item, not a Phase 1 freebie).

## Verification

1. `pip install -e ".[testing]"` resolves `fastmcp>=3` and its `mcp` dependency;
   `pytest` → full suite green (Phase 1 target: still 126, no assertion
   changes; Phase 2: rewritten auth tests).
2. stdio smoke: `python -m wlanpi_mcp --transport stdio` starts and lists tools.
3. SSE smoke (Phase 1): start the daemon, connect an MCP client on the existing
   `/sse` path with a Bearer token, confirm a tool call round-trips and a
   tokenless connection still gets 401 — i.e. no client-visible change.
4. Phase 2 only: repeat 3 against the Streamable HTTP endpoint, and explicitly
   test that two clients with different tokens cannot drive each other's
   sessions (the SSE property, re-proven).
5. Rebuild the Debian package (`dpkg-buildpackage -us -uc`) and confirm the
   dh-virtualenv install still imports and starts under the systemd unit.

## Explicitly out of scope
Adopting fastmcp v3's own OAuth/`token_verifier` auth — this server does no
server-side auth by design (JWT passthrough to wlanpi-core; see `CLAUDE.md`).
The migration keeps that model; it does not hand auth to fastmcp.
