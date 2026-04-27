import pytest
import respx
import httpx

from wlanpi_mcp.config import Settings


@pytest.fixture
def settings():
    return Settings(
        WLANPI_CORE_URL="http://localhost:31415",
        WLANPI_CORE_SECRET_PATH="/tmp/fake_secret.bin",
        WLANPI_CORE_DEVICE_ID="test-device",
        WLANPI_MCP_API_KEY="test-key",
    )


@pytest.fixture
def mock_token(tmp_path):
    """Provides a TokenManager pre-loaded with a fake token so tests skip HMAC bootstrap."""
    import time
    from unittest.mock import AsyncMock, patch
    from wlanpi_mcp.auth.token_manager import TokenManager

    manager = TokenManager.__new__(TokenManager)
    manager._token = "fake.jwt.token"
    manager._expires_at = time.time() + 86400 * 7
    import asyncio
    manager._lock = asyncio.Lock()

    async def _get_token():
        return manager._token

    with patch.object(manager, "get_token", side_effect=_get_token):
        yield manager
