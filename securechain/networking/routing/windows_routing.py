"""Native Windows Routing Controller using ROUTE.EXE and netsh."""

import ctypes
import ipaddress
import re
import subprocess
from datetime import datetime, timezone
from typing import List, Optional

from securechain.core.exceptions import RoutingError
from securechain.networking.routing.controller import RouteEntry, RouteSnapshot, RoutingController
from securechain.security.logging_sanitizer import get_logger, sanitize_string

logger = get_logger("securechain.networking.windows_routing")


def is_windows_admin() -> bool:
    """Check if current process has elevated administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class WindowsRoutingController(RoutingController):
    """Routing controller interfacing with Windows route.exe and PowerShell."""

    def __init__(self) -> None:
        self._is_admin = is_windows_admin()
        self._temporary_routes: List[RouteEntry] = []

    def check_privileges(self) -> None:
        if not self._is_admin:
            raise RoutingError(
                "Windows administrator privileges are required to modify the system routing table."
            )

    def snapshot(self) -> RouteSnapshot:
        routes = self.get_routes()
        default_route = next((r for r in routes if r.destination == "0.0.0.0/0"), None)
        return RouteSnapshot(
            timestamp=datetime.now(timezone.utc),
            routes=routes,
            default_gateway=default_route.gateway if default_route else None,
            default_interface=default_route.interface if default_route else None,
        )

    def get_routes(self) -> List[RouteEntry]:
        try:
            cmd = ["route", "print", "4"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode != 0:
                return []
            return self._parse_route_print(res.stdout)
        except Exception as exc:
            logger.warning(f"Failed to inspect Windows routes: {sanitize_string(str(exc))}")
            return []

    def _parse_route_print(self, output: str) -> List[RouteEntry]:
        routes: List[RouteEntry] = []
        active_routes_section = False
        for line in output.splitlines():
            line = line.strip()
            if "Active Routes:" in line:
                active_routes_section = True
                continue
            if "Persistent Routes:" in line:
                active_routes_section = False
                break
            if active_routes_section:
                parts = line.split()
                if len(parts) >= 5:
                    dest, mask, gw, iface, metric = parts[0], parts[1], parts[2], parts[3], parts[4]
                    try:
                        net = ipaddress.IPv4Network(f"{dest}/{mask}", strict=False)
                        routes.append(
                            RouteEntry(
                                destination=str(net),
                                gateway=gw,
                                interface=iface,
                                metric=int(metric),
                            )
                        )
                    except Exception:
                        continue
        return routes

    def add_route(self, destination: str, gateway: str, interface: str, metric: int = 10) -> bool:
        self.check_privileges()
        net = ipaddress.IPv4Network(destination, strict=False)
        cmd = [
            "route",
            "add",
            str(net.network_address),
            "mask",
            str(net.netmask),
            gateway,
            "metric",
            str(metric),
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if res.returncode != 0:
            raise RoutingError(f"route add failed: {res.stderr or res.stdout}")

        entry = RouteEntry(
            destination=destination,
            gateway=gateway,
            interface=interface,
            metric=metric,
            is_temporary=True,
        )
        self._temporary_routes.append(entry)
        return True

    def delete_route(self, destination: str, gateway: Optional[str] = None) -> bool:
        self.check_privileges()
        net = ipaddress.IPv4Network(destination, strict=False)
        cmd = ["route", "delete", str(net.network_address), "mask", str(net.netmask)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return res.returncode == 0

    def verify_route(self, destination: str, expected_gateway: str) -> bool:
        routes = self.get_routes()
        return any(r.destination == destination and r.gateway == expected_gateway for r in routes)

    def detect_unexpected_changes(self, snapshot: RouteSnapshot) -> List[RouteEntry]:
        current = self.get_routes()
        snapshot_destinations = {r.destination: r for r in snapshot.routes}
        unexpected = []
        for r in current:
            if r.destination not in snapshot_destinations:
                unexpected.append(r)
        return unexpected

    def restore(self, snapshot: RouteSnapshot) -> bool:
        self.cleanup_temporary_routes()
        return True

    def cleanup_temporary_routes(self) -> int:
        if not self._is_admin:
            return 0
        cleaned = 0
        for r in list(self._temporary_routes):
            if self.delete_route(r.destination):
                cleaned += 1
        self._temporary_routes.clear()
        return cleaned
