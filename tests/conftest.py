import pytest

from wlanpi_mcp.auth.token_context import current_token
from wlanpi_mcp.client.core_client import CoreClient
from wlanpi_mcp.config import Settings

FAKE_TOKEN = "fake.jwt.token"


@pytest.fixture
def settings():
    return Settings(
        WLANPI_CORE_URL="http://localhost:31415",
        _env_file=None,
    )


@pytest.fixture
def bearer_token():
    """Simulates BearerTokenMiddleware having captured a client JWT."""
    ctx = current_token.set(FAKE_TOKEN)
    yield FAKE_TOKEN
    current_token.reset(ctx)


@pytest.fixture
def client(settings, bearer_token):
    return CoreClient(settings)
