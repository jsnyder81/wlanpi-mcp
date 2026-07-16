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
    # Fallback wlanpi-core JWT for stdio transport, where there is no HTTP
    # Authorization header to pass through. Leave empty in SSE/daemon mode.
    WLANPI_CORE_TOKEN: str = ""
    # Gate for the reboot_device/shutdown_device tools. Set false to prevent
    # MCP clients from power-cycling the device.
    ALLOW_POWER_CONTROL: bool = True
    WLANPI_MCP_HOST: str = "0.0.0.0"
    # 8766: avoid colliding with the wlanpi-fpms2 state service on 8765
    WLANPI_MCP_PORT: int = 8766
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file="/etc/wlanpi-mcp/config.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


def get_settings() -> Settings:
    return Settings()
