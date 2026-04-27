from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP) -> None:

    @mcp.prompt()
    def diagnose_connectivity() -> str:
        """Run a full connectivity diagnostic on the WlanPi."""
        return (
            "You are a network diagnostic assistant with access to WlanPi tools. "
            "Perform a full connectivity diagnostic by doing the following in order:\n"
            "1. Call get_device_info to identify the device model, hostname, and operating mode.\n"
            "2. Call get_device_stats to check CPU, RAM, disk, and temperature for any health issues.\n"
            "3. Call get_network_interfaces to list all interfaces and their states.\n"
            "4. Call get_reachability to test gateway ping, DNS, and internet access.\n"
            "5. Call get_network_info to get LLDP/CDP neighbours and public IP.\n"
            "Then summarise: which interfaces are up, whether internet is reachable, "
            "what network devices are visible via LLDP/CDP, and any anomalies in health metrics."
        )

    @mcp.prompt()
    def troubleshoot_service(service_name: str) -> str:
        """Diagnose why a WlanPi service is not working as expected."""
        return (
            f"You are a WlanPi service troubleshooter. The user is having trouble with '{service_name}'.\n"
            "1. Call list_allowed_services and verify that the service name is in the list.\n"
            f"2. Call get_service_status with name='{service_name}' to check its current state.\n"
            "3. If the service is stopped, ask the user whether they want you to start it.\n"
            "   If yes, call start_service with the service name and then verify with get_service_status.\n"
            "4. If the service is already running but misbehaving, call get_device_stats to check "
            "   for resource pressure (high CPU, low RAM) that could cause instability.\n"
            "Summarise your findings and recommended next steps."
        )

    @mcp.prompt()
    def health_check() -> str:
        """Quick health check of the WlanPi device."""
        return (
            "You are a WlanPi health checker. Run a quick health assessment:\n"
            "1. Call get_device_info to confirm the device identity and mode.\n"
            "2. Call get_device_stats and evaluate each metric:\n"
            "   - CPU: warn if > 80%, fail if > 95%\n"
            "   - RAM: warn if > 85%, fail if > 95%\n"
            "   - Disk: warn if > 80%, fail if > 90%\n"
            "   - Temperature: warn if > 70C, fail if > 80C\n"
            "3. Call get_reachability and flag any failed checks.\n"
            "Return a structured report with PASS / WARN / FAIL for each metric "
            "and an overall device health status."
        )

    @mcp.prompt()
    def service_manager() -> str:
        """Interactive service start/stop assistant."""
        return (
            "You are a WlanPi service management assistant.\n"
            "1. Call list_allowed_services to show the user which services can be managed.\n"
            "2. Ask the user which service they want to manage and what action: "
            "   status, start, or stop.\n"
            "3. Call get_service_status to show the current state before any action.\n"
            "4. If the user wants to start or stop a service, confirm with them before proceeding.\n"
            "5. After the action, call get_service_status again to verify the new state and report back."
        )
