"""Base Routing Controller abstraction and models for SecureChain."""

import ipaddress
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


@dataclass(frozen=True)
class RouteEntry:
    """Represents a single routing table entry."""

    destination: str  # CIDR notation e.g. "198.51.100.10/32" or "0.0.0.0/0"
    gateway: str      # Next-hop gateway IP e.g. "192.168.1.1" or "10.8.0.1"
    interface: str    # Interface name or index e.g. "eth0", "sim-vpn-01"
    metric: int = 10
    is_temporary: bool = False
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def network(self):
        return ipaddress.ip_network(self.destination, strict=False)


@dataclass
class RouteSnapshot:
    """Snapshot of system routes prior to any modifications."""

    timestamp: datetime
    routes: List[RouteEntry]
    default_gateway: Optional[str] = None
    default_interface: Optional[str] = None


class RoutingController(ABC):
    """Abstract interface defining routing operations."""

    @abstractmethod
    def snapshot(self) -> RouteSnapshot:
        """Capture current routing table snapshot for later rollback."""

    @abstractmethod
    def get_routes(self) -> List[RouteEntry]:
        """Inspect and return current active routes."""

    @abstractmethod
    def add_route(self, destination: str, gateway: str, interface: str, metric: int = 10) -> bool:
        """Create a new route in the routing table."""

    @abstractmethod
    def delete_route(self, destination: str, gateway: Optional[str] = None) -> bool:
        """Remove a route from the routing table."""

    @abstractmethod
    def verify_route(self, destination: str, expected_gateway: str) -> bool:
        """Verify that traffic to destination matches the expected next-hop gateway."""

    @abstractmethod
    def detect_unexpected_changes(self, snapshot: RouteSnapshot) -> List[RouteEntry]:
        """Detect any routes added or modified that were not authorized by SecureChain."""

    @abstractmethod
    def restore(self, snapshot: RouteSnapshot) -> bool:
        """Restore routing table to the exact state captured in snapshot."""

    @abstractmethod
    def cleanup_temporary_routes(self) -> int:
        """Remove all temporary routes created during the current session."""
