from pydantic_settings import BaseSettings, SettingsConfigDict


ALLOWED_SERVICES = [
    "wlanpi-profiler",
    "wlanpi-fpms",
    "wlanpi-chat-bot",
    "bt-agent",
    "bt-network",
    "iperf",
    "iperf3",
    "tftpd-hpa",
    "hostapd",
    "wpa_supplicant",
    "wpa_supplicant@wlan0",
    "kismet",
    "grafana-server",
    "cockpit",
    "wlanpi-grafana-scanner-wlan0",
    "wlanpi-grafana-scanner-wlan1",
    "wlanpi-grafana-scanner-wlan2",
    "wlanpi-grafana-health",
    "wlanpi-grafana-internet",
    "wlanpi-grafana-wispy-24",
    "wlanpi-grafana-wispy-5",
    "wlanpi-grafana-wipry-lp-24",
    "wlanpi-grafana-wipry-lp-5",
    "wlanpi-grafana-wipry-lp-6",
    "wlanpi-grafana-wipry-lp-stop",
]


class Settings(BaseSettings):
    WLANPI_CORE_URL: str = "http://localhost:31415"
    WLANPI_CORE_SECRET_PATH: str = (
        "/home/wlanpi/.local/share/wlanpi-core/secrets/shared_secret.bin"
    )
    WLANPI_CORE_DEVICE_ID: str = "wlanpi-mcp"
    WLANPI_MCP_API_KEY: str = ""
    WLANPI_MCP_HOST: str = "0.0.0.0"
    WLANPI_MCP_PORT: int = 8765
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file="/etc/wlanpi-mcp/config.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


def get_settings() -> Settings:
    return Settings()
