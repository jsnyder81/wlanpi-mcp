import argparse
import asyncio
import logging
import sys

from wlanpi_mcp.config import get_settings
from wlanpi_mcp.client.core_client import init_client


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WlanPi MCP server",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport: stdio (for direct client invocation) or sse (HTTP daemon mode)",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Bind host for SSE transport (overrides config)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port for SSE transport (overrides config)",
    )
    args = parser.parse_args()

    settings = get_settings()
    _configure_logging(settings.LOG_LEVEL)

    client = init_client(settings)

    host = args.host or settings.WLANPI_MCP_HOST
    port = args.port or settings.WLANPI_MCP_PORT

    from wlanpi_mcp.server import create_server
    mcp = create_server(client, host=host, port=port)

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        _run_sse(mcp, settings, host, port)


def _run_sse(mcp, settings, host: str, port: int) -> None:
    import uvicorn
    from wlanpi_mcp.middleware.bearer_token import BearerTokenMiddleware

    # FastMCP exposes the Starlette ASGI app for SSE via sse_app().
    # Every connection must present a wlanpi-core JWT, which is passed
    # through to wlanpi-core on API calls (validated there, not here).
    sse_app = mcp.sse_app()
    sse_app.add_middleware(BearerTokenMiddleware)

    uvicorn.run(
        sse_app,
        host=host,
        port=port,
        log_level=settings.LOG_LEVEL.lower(),
    )


if __name__ == "__main__":
    main()
