import asyncio
import logging
import time
from typing import Optional

import httpx
import jwt

from wlanpi_mcp.auth.hmac_client import AUTH_ENDPOINT, generate_signature
from wlanpi_mcp.config import Settings

log = logging.getLogger(__name__)

_TOKEN_REFRESH_MARGIN = 86400  # refresh 24h before expiry


class TokenManager:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._token: Optional[str] = None
        self._expires_at: float = 0.0
        self._lock = asyncio.Lock()

    async def get_token(self) -> str:
        async with self._lock:
            if self._needs_refresh():
                self._token = await self._bootstrap_token()
            return self._token  # type: ignore[return-value]

    def invalidate(self) -> None:
        self._token = None
        self._expires_at = 0.0

    def _needs_refresh(self) -> bool:
        if not self._token:
            return True
        return time.time() > (self._expires_at - _TOKEN_REFRESH_MARGIN)

    async def _bootstrap_token(self) -> str:
        request_body, signature = generate_signature(
            self._settings.WLANPI_CORE_SECRET_PATH,
            self._settings.WLANPI_CORE_DEVICE_ID,
        )

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self._settings.WLANPI_CORE_URL}{AUTH_ENDPOINT}",
                content=request_body,
                headers={
                    "X-Request-Signature": signature,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=10.0,
            )
            response.raise_for_status()

        data = response.json()
        token = data["access_token"]

        # Decode without verification just to read the exp claim
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
            self._expires_at = float(claims.get("exp", time.time() + 86400 * 7))
        except Exception:
            self._expires_at = time.time() + 86400 * 6

        log.info("wlanpi-core JWT bootstrapped successfully")
        return token
