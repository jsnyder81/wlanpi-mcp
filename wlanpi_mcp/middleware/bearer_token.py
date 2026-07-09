import hashlib

from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from starlette.authentication import AuthCredentials
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from wlanpi_mcp.auth.token_context import current_token


def _principal_for(token: str) -> AuthenticatedUser:
    """
    Represent the connecting token as an ASGI principal keyed by a fingerprint
    of the token itself.

    The MCP SSE transport binds each session to the principal on scope["user"]
    at connect time and rejects any later POST /messages/ whose principal
    differs (mcp/server/sse.py). By keying the principal on a SHA-256 of the
    raw token, that binding rejects any message carrying a different token than
    the one that opened the session — so one client's session cannot be driven
    with another client's (or an unauthenticated) credential.

    We hash rather than parse the JWT: this middleware never validates tokens
    (that is wlanpi-core's job), and the fingerprint only needs to be stable
    and unique per token. The raw token stays out of the principal object; it
    already lives in the contextvar for the actual API call.
    """
    fingerprint = hashlib.sha256(token.encode()).hexdigest()
    return AuthenticatedUser(
        AccessToken(token=fingerprint, client_id=fingerprint, scopes=[])
    )


class BearerTokenMiddleware:
    """
    Requires every HTTP request to carry a wlanpi-core JWT as
    'Authorization: Bearer <token>' and stashes it in a contextvar so
    CoreClient can pass it through to wlanpi-core.

    The token is not validated here — wlanpi-core rejects bad tokens with a
    401, which propagates back to the MCP client as a tool error.

    Pure ASGI middleware (not BaseHTTPMiddleware) so the downstream app runs
    in the same task: the contextvar set here is visible to the SSE session
    loop and every tool-call task it spawns.

    It also publishes a per-token principal on scope["user"] so the SSE
    transport binds each session to its opening token and refuses messages
    presenting a different one (see _principal_for).
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        auth = Headers(scope=scope).get("authorization", "")
        token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""

        if not token:
            response = JSONResponse(
                {
                    "detail": (
                        "Missing Bearer token. Obtain a JWT from wlanpi-core "
                        "(POST /api/v1/auth/token) and send it as "
                        "'Authorization: Bearer <token>'."
                    )
                },
                status_code=401,
            )
            await response(scope, receive, send)
            return

        scope["user"] = _principal_for(token)
        scope["auth"] = AuthCredentials()

        ctx_token = current_token.set(token)
        try:
            await self.app(scope, receive, send)
        finally:
            current_token.reset(ctx_token)
